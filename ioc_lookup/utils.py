# -*- coding: utf-8 -*-
__author__ = "lundberg"

from contextlib import contextmanager
from copy import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Self, Set

from flask import abort, request
from flask_limiter.util import get_remote_address
from pymisp import PyMISPError

from ioc_lookup.ioc_lookup_app import current_ioc_lookup_app
from ioc_lookup.misp_api import TLP, Attr, AttrType, MISPApi
from ioc_lookup.parse import InputError, ParseException, parse_items


class TagParseException(Exception):
    pass


class EventInfoException(Exception):
    pass


@dataclass
class User:
    identifier: str
    is_trusted_user: bool
    in_trusted_org: bool
    org_domain: str


@dataclass
class Votes:
    positives: int = 0
    positive_orgs: Set[str] = field(default_factory=set)
    negatives: int = 0
    negative_orgs: Set[str] = field(default_factory=set)


@dataclass
class SightingsData:
    can_add_sighting: bool
    can_add_false_positive: bool
    votes: Dict[str, Votes] = field(default_factory=dict)

    @classmethod
    def from_sightings(cls, data: List[Dict[str, Any]], votes: Dict[str, Votes]):
        can_add_sighting = True
        can_add_false_positive = True
        now = datetime.utcnow()
        for item in data:
            # Check if a sighting has been reported in the latest 24 hours by this org
            if can_add_sighting and item.get("type", None) == "0":
                date_sighting = datetime.utcfromtimestamp(int(item["date_sighting"]))
                min_vote_hours = current_ioc_lookup_app.config["SIGHTING_MIN_POSITIVE_VOTE_HOURS"]
                if date_sighting > (now - timedelta(hours=min_vote_hours)):
                    can_add_sighting = False
            # Check if there has been a false-positive report by this org
            elif can_add_false_positive and item.get("type", None) == "1":
                can_add_false_positive = False
        return cls(can_add_sighting=can_add_sighting, can_add_false_positive=can_add_false_positive, votes=votes)


@dataclass
class ReportData:
    reference: str
    items: list[Attr]
    tlp: TLP
    tags: list[str]
    info: str
    publish: bool = False
    by_proxy: bool = False

    @classmethod
    def load_data(cls, data: dict[str, Any]) -> Optional[Self]:
        reference = " ".join(data.get("reference", "").split())  # Normalise whitespace
        tlp = TLP(str(data.get("tlp")))
        info = data.get("info")
        by_proxy = data.get("by_proxy", False)

        if not info:
            raise EventInfoException("Event info is mandatory")

        report_items = parse_items(data.get("ioc", ""))
        if not report_items:
            return None

        for item in copy(report_items):
            if AttrType.URL in item.report_types:
                # Also report FQDN for URLs
                url_domain = item.get_domain()
                if url_domain is not None:
                    report_items.append(Attr(value=url_domain, type=AttrType.DOMAIN, report_types=[AttrType.DOMAIN]))

        tags = [str(tlp.value)]
        for tag in data.get("tags", []):
            if tag in current_ioc_lookup_app.config["ALLOWED_EVENT_TAGS"]:
                tags.append(tag)
            else:
                raise TagParseException(f"Tag {tag} is not allowed")

        return cls(reference=reference, items=report_items, tlp=tlp, info=info, tags=tags, by_proxy=by_proxy)


def request_to_data() -> dict[str, Any]:
    """
    Parse the request data into a dictionary
    """
    if request.form:
        data: dict[str, Any] = dict(request.form)
        # collect tag checkboxes in to a tags list
        tags: list[str] = []
        # set by_proxy to True if checkbox is checked
        by_proxy = False
        for key, value in request.form.items():
            if key.startswith("tag_") and value == "on":
                tags.append(key.removeprefix("tag_"))
            if key == "by_proxy" and value == "on":
                by_proxy = True
        data["tags"] = tags
        data["by_proxy"] = by_proxy
        return data
    elif request.json:
        return request.json
    else:
        raise ParseException("No input found", errors=[InputError(line=0, message="No input found")])


def get_ipaddr_or_eppn() -> str:
    """
    Uses eppn if supplied else remote address for rate limiting
    """
    # Get identifier by HTTP_REMOTE_USER
    current_ioc_lookup_app.logger.debug("REQUEST ENVIRONMENT:")
    current_ioc_lookup_app.logger.debug(request.environ)
    identifier = request.environ.get("HTTP_REMOTE_USER", None)
    current_ioc_lookup_app.logger.debug(f"Identifier from request environment: {identifier}")

    # Get identifier by api key
    api_key = request.environ.get("HTTP_API_TOKEN", None)
    if api_key is not None:
        identifier = current_ioc_lookup_app.api_keys.get(api_key)
        current_ioc_lookup_app.logger.debug(f"Identifier from api key: {identifier}")

    if not identifier:
        current_ioc_lookup_app.logger.warning("HTTP_REMOTE_USER and HTTP_API_TOKEN is missing from request environment")
        if current_ioc_lookup_app.config.get("DEBUG", False) is False:
            abort(401)
        # Fallback to remote address if in debug mode
        current_ioc_lookup_app.logger.warning("Falling back to remote address in debug mode")
        identifier = get_remote_address()
        current_ioc_lookup_app.logger.debug(f"Identifier from get_ipaddr: {identifier}")
    return identifier


def get_user() -> User:
    identifier = get_ipaddr_or_eppn()
    return User(
        identifier=identifier,
        is_trusted_user=is_trusted_user(identifier),
        in_trusted_org=in_trusted_orgs(identifier),
        org_domain=get_org_domain(identifier),
    )


def is_trusted_user(userid: str) -> bool:
    """
    Checks the eppn against a whitelist
    """
    if userid in current_ioc_lookup_app.trusted_users:
        current_ioc_lookup_app.logger.debug(f"User with id {userid} is a trusted user")
        return True
    current_ioc_lookup_app.logger.debug(f"User with id {userid} IS NOT a trusted user")
    return False


def get_org_domain(userid: str) -> str:
    return userid.split("@")[-1].lower()


def in_trusted_orgs(userid: str) -> bool:
    org_domain = get_org_domain(userid)
    return org_domain in current_ioc_lookup_app.trusted_orgs


def get_sightings_data(user: User, search_result: List[Dict[str, Any]]) -> SightingsData:
    attribute_votes = {}
    org_sightings = []
    with misp_api_for() as api:
        for item in search_result:
            votes = Votes()
            for sighting in api.sighting_lookup(attribute_id=item["id"]):
                org_name = sighting["source"].replace(current_ioc_lookup_app.config["SIGHTING_SOURCE_PREFIX"], "")
                if sighting["type"] == "0":
                    votes.positives += 1
                    votes.positive_orgs.add(org_name)
                elif sighting["type"] == "1":
                    votes.negatives += 1
                    votes.negative_orgs.add(org_name)
            attribute_votes[item["id"]] = votes
            with misp_api_for(user) as org_api:
                org_sightings.extend(
                    org_api.sighting_lookup(
                        attribute_id=item["id"],
                        source=f'{current_ioc_lookup_app.config["SIGHTING_SOURCE_PREFIX"]}{user.org_domain}',
                    )
                )
    return SightingsData.from_sightings(data=org_sightings, votes=attribute_votes)


@contextmanager
def misp_api_for(user: Optional[User] = None) -> Iterator[MISPApi]:
    if current_ioc_lookup_app.misp_apis is None:
        raise PyMISPError("No MISP session exists")
    if user is None:
        # Use default api key as org specific api keys return org specific data
        user = User(identifier="default", is_trusted_user=False, in_trusted_org=False, org_domain="default")
        current_ioc_lookup_app.logger.debug("Default user used for api call")
    current_ioc_lookup_app.logger.debug(f"User {user.identifier} mapped to domain {user.org_domain}")

    # Lazy load apis per org
    if (
        user.org_domain not in current_ioc_lookup_app.misp_apis
        and user.org_domain in current_ioc_lookup_app.trusted_orgs
    ):
        try:
            current_ioc_lookup_app.misp_apis[user.org_domain] = MISPApi(
                name=current_ioc_lookup_app.trusted_orgs[user.org_domain].domain,
                api_url=current_ioc_lookup_app.config["MISP_URL"],
                api_key=current_ioc_lookup_app.trusted_orgs[user.org_domain].misp_api_key,
                verify_cert=current_ioc_lookup_app.config["MISP_VERIFYCERT"],
            )
            current_ioc_lookup_app.logger.info(f"Loaded api for {user.org_domain}")
        except PyMISPError:
            abort(400, "Authentication failed. Make sure your organizations api key is up to date.")
        except Exception as ex:
            current_ioc_lookup_app.logger.exception(f"Could not load domain mapping for {user.org_domain}: {ex}")

    api = current_ioc_lookup_app.misp_apis.get(user.org_domain)
    if api is None:
        current_ioc_lookup_app.logger.debug(f"Could not find domain {user.org_domain} for user {user} in TRUSTED_ORGS")
        current_ioc_lookup_app.logger.debug("Using default api")
        api = current_ioc_lookup_app.misp_apis["default"]
    else:
        current_ioc_lookup_app.logger.debug(f"Using {user.org_domain} api: {api}")
    yield api


def utc_now() -> datetime:
    """Return current time with tz=UTC"""
    return datetime.now(tz=timezone.utc)

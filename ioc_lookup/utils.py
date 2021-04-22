# -*- coding: utf-8 -*-
__author__ = 'lundberg'

import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterator, List, Optional, Set

from flask import abort, current_app, request
from flask_limiter.util import get_ipaddr
from pymisp import PyMISPError
from validators import domain, ipv4, ipv6, md5, sha1, url, sha256, validator

from ioc_lookup.misp_api import Attr, AttrType, MISPApi


class ParseException(Exception):
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
            if can_add_sighting and item.get('type', None) == '0':
                date_sighting = datetime.utcfromtimestamp(int(item['date_sighting']))
                min_vote_hours = current_app.config['SIGHTING_MIN_POSITIVE_VOTE_HOURS']
                if date_sighting > (now - timedelta(hours=min_vote_hours)):
                    can_add_sighting = False
            # Check if there has been a false-positive report by this org
            elif can_add_false_positive and item.get('type', None) == '1':
                can_add_false_positive = False
        return cls(can_add_sighting=can_add_sighting, can_add_false_positive=can_add_false_positive, votes=votes)


@validator
def defanged_url(value, public=False) -> bool:
    if value.startswith('hxxp://') or value.startswith('hxxps://'):
        value = value.replace('hxx', 'htt', 1)  # Replace only the first occurrence of hxx with htt
        return url(value=value, public=public)
    return False


def parse_items(items: Optional[str]) -> List[Attr]:
    parsed_items: List[Attr] = []
    if not items:
        return parsed_items
    for item in items.split('\n'):
        if item:
            item = ''.join(item.split())  # Normalize whitespace
            item = urllib.parse.unquote_plus(item)
            if domain(item):
                search_types = [AttrType.DOMAIN]
                report_types = [AttrType.DOMAIN]
            elif url(item):
                search_types = [AttrType.URL]
                report_types = [AttrType.URL]
            elif defanged_url(item):
                search_types = [AttrType.URL]
                report_types = [AttrType.URL]
            elif ipv4(item) or ipv6(item):
                search_types = [
                    AttrType.DOMAIN_IP,
                    AttrType.IP_SRC,
                    AttrType.IP_SRC_PORT,
                    AttrType.IP_DST,
                    AttrType.IP_DST_PORT,
                ]
                report_types = [AttrType.IP_SRC]
            elif md5(item):
                search_types = [AttrType.MD5, AttrType.FILENAME_MD5]
                report_types = [AttrType.MD5]
            elif sha1(item):
                search_types = [AttrType.SHA1, AttrType.FILENAME_SHA1]
                report_types = [AttrType.SHA1]
            elif sha256(item):
                search_types = [AttrType.SHA256, AttrType.FILENAME_SHA256]
                report_types = [AttrType.SHA256]
            else:
                raise ParseException(f'Could not parse {item}')
            parsed_items.append(Attr(value=item, search_types=search_types, report_types=report_types))
    return parsed_items


def parse_item(item: Optional[str]) -> Optional[Attr]:
    try:
        items = parse_items(item)
    except ParseException:
        return None
    if not items:
        return None
    return items[0]


def get_ipaddr_or_eppn() -> str:
    """
    Uses eppn if supplied else remote address for rate limiting
    """
    current_app.logger.debug('REQUEST ENVIRONMENT:')
    current_app.logger.debug(request.environ)
    identifier = request.environ.get('HTTP_EPPN', None)
    current_app.logger.debug(f'Identifier from request environment: {identifier}')
    if not identifier:
        current_app.logger.warning('HTTP_EPPN is missing from request environment')
        identifier = get_ipaddr()
        current_app.logger.debug(f'Identifier from get_ipaddr: {identifier}')
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
    if userid in current_app.trusted_users:
        current_app.logger.debug(f'User with id {userid} is a trusted user')
        return True
    current_app.logger.debug(f'User with id {userid} IS NOT a trusted user')
    return False


def get_org_domain(userid: str) -> str:
    return 'borgorg'
    # return userid.split('@')[-1].lower()


def in_trusted_orgs(userid: str) -> bool:
    org_domain = get_org_domain(userid)
    return org_domain in current_app.trusted_orgs['org_domains']


def get_sightings_data(user: User, search_result: List[Dict[str, Any]]):
    attribute_votes = {}
    org_sightings = []
    with misp_api_for() as api:
        for item in search_result:
            votes = Votes()
            for sighting in api.sighting_lookup(attribute_id=item['id']):
                org_name = sighting['source'].replace(current_app.config["SIGHTING_SOURCE_PREFIX"], '')
                if sighting['type'] == '0':
                    votes.positives += 1
                    votes.positive_orgs.add(org_name)
                elif sighting['type'] == '1':
                    votes.negatives += 1
                    votes.negative_orgs.add(org_name)
            attribute_votes[item['id']] = votes
            with misp_api_for(user) as org_api:
                org_sightings.extend(
                    org_api.sighting_lookup(
                        attribute_id=item['id'],
                        source=f'{current_app.config["SIGHTING_SOURCE_PREFIX"]}{user.org_domain}',
                    )
                )
    return SightingsData.from_sightings(data=org_sightings, votes=attribute_votes)


@contextmanager
def misp_api_for(user: Optional[User] = None) -> Iterator[MISPApi]:
    if user is None:
        # Use default api key as org specific api keys return org specific data
        user = User(identifier='default', is_trusted_user=False, in_trusted_org=False, org_domain='default')
        current_app.logger.debug('Default user used for api call')
    current_app.logger.debug(f'User {user.identifier} mapped to domain {user.org_domain}')

    # Lazy load apis per org
    if user.org_domain not in current_app.misp_apis and user.org_domain in current_app.trusted_orgs['org_domains']:
        try:
            current_app.misp_apis[user.org_domain] = MISPApi(
                current_app.config['MISP_URL'],
                current_app.trusted_orgs['org_domains'][user.org_domain],
                current_app.config['MISP_VERIFYCERT'],
            )
            current_app.logger.info(f'Loaded api for {user.org_domain}')
        except PyMISPError:
            abort(400, 'Authentication failed. Make sure your organizations api key is up to date.')
        except Exception as ex:
            current_app.logger.exception(f'Could not load domain mapping for {user.org_domain}: {ex}')

    api = current_app.misp_apis.get(user.org_domain)
    if api is None:
        current_app.logger.debug('Using default api')
        yield current_app.misp_apis['default']
    else:
        current_app.logger.debug(f'Using {user.org_domain} api')
        yield api

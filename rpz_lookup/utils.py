# -*- coding: utf-8 -*-
__author__ = 'lundberg'

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List

from flask import current_app, request
from flask_limiter.util import get_ipaddr


@dataclass
class User:
    identifier: str
    is_trusted_user: bool
    in_trusted_org: bool
    org_domain: str


@dataclass
class Votes:
    positives: int = 0
    negatives: int = 0


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
    return userid.split('@')[-1].lower()


def in_trusted_orgs(userid: str) -> bool:
    org_domain = get_org_domain(userid)
    return org_domain in current_app.trusted_orgs['org_domains']

# -*- coding: utf-8 -*-
__author__ = 'lundberg'

from flask import current_app, request
from flask_limiter.util import get_ipaddr


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


def is_trusted_user(userid: str) -> bool:
    """
    Checks the eppn against a whitelist
    """
    if userid in current_app.trusted_users:
        current_app.logger.debug(f'User with id {userid} is a trusted user')
        return True
    current_app.logger.debug(f'User with id {userid} IS NOT a trusted user')
    return False

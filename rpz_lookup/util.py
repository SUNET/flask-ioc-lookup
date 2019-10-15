# -*- coding: utf-8 -*-
__author__ = 'lundberg'

from flask import request, current_app
from flask_limiter.util import get_ipaddr


def get_ipaddr_or_eppn():
    """
    Uses eppn if supplied else remote address for rate limiting
    """
    current_app.logger.debug('REQUEST ENVIRONMENT:')
    current_app.logger.debug(request.environ)
    identifier = request.environ.pop('HTTP_EPPN', None)
    current_app.logger.debug(f'Identifier from request environment: {identifier}')
    if not identifier:
        current_app.logger.warning('HTTP_EPPN is missing from request environment')
        identifier = get_ipaddr()
        current_app.logger.debug(f'Identifier from get_idaddr: {identifier}')
    return identifier

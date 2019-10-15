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
    if not identifier:
        identifier = get_ipaddr()
    return identifier

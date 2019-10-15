# -*- coding: utf-8 -*-
__author__ = 'lundberg'

from flask import request
from flask_limiter.util import get_ipaddr


def get_ipaddr_or_eppn():
    """
    Uses eppn if supplied else remote address for rate limiting
    """
    identifier = request.environ.pop('HTTP_EPPN', None)
    if not identifier:
        identifier = get_ipaddr()
    return identifier
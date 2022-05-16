# -*- coding: utf-8 -*-
from typing import Dict, List, Optional, cast

from flask import Flask, current_app

from ioc_lookup.misp_api import MISPApi

__author__ = 'lundberg'


class IOCLookupApp(Flask):
    trusted_users: List[str] = []
    trusted_orgs: Dict[str, Dict[str, str]] = {}
    misp_apis: Optional[Dict[str, MISPApi]]


current_ioc_lookup_app: IOCLookupApp = cast(IOCLookupApp, current_app)

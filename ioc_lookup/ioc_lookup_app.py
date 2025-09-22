from dataclasses import dataclass
from typing import cast

from flask import Flask, current_app

from ioc_lookup.misp_api import MISPApi

__author__ = "lundberg"


@dataclass
class TrustedOrg:
    domain: str
    misp_api_key: str


class IOCLookupApp(Flask):
    trusted_users: list[str] = []
    trusted_orgs: dict[str, TrustedOrg] = {}
    api_keys: dict[str, dict[str, str]] = {}
    misp_apis: dict[str, MISPApi] | None


current_ioc_lookup_app: IOCLookupApp = cast(IOCLookupApp, current_app)

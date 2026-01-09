"""
Pytest configuration and fixtures for IOC Lookup tests.

This module provides mock MISP API fixtures following Flask best practices.
"""

from collections.abc import Generator, Iterator
from datetime import datetime
from os import environ
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from flask.testing import FlaskClient
from pymisp.mispevent import MISPEvent, MISPSighting

from ioc_lookup.ioc_lookup_app import IOCLookupApp, TrustedOrg
from ioc_lookup.misp_api import MISPApi

__author__ = "lundberg"


# Sample test data for MISP responses
SAMPLE_ATTRIBUTES = [
    {
        "id": "1",
        "event_id": "100",
        "type": "domain",
        "category": "Network activity",
        "value": "malicious.example.com",
        "to_ids": True,
        "comment": "Test malicious domain",
        "timestamp": "1704067200",
    },
    {
        "id": "2",
        "event_id": "101",
        "type": "ip-src",
        "category": "Network activity",
        "value": "192.168.1.100",
        "to_ids": True,
        "comment": "Test IP address",
        "timestamp": "1704067200",
    },
    {
        "id": "3",
        "event_id": "102",
        "type": "md5",
        "category": "Payload delivery",
        "value": "0114f0fb3b87f8dc2dcbeda71c8dda9f",
        "to_ids": True,
        "comment": "Test MD5 hash",
        "timestamp": "1704067200",
    },
    {
        "id": "4",
        "event_id": "103",
        "type": "url",
        "category": "Network activity",
        "value": "https://phishing.example.com/login",
        "to_ids": True,
        "comment": "Test phishing URL",
        "timestamp": "1704067200",
    },
]

SAMPLE_SIGHTINGS = [
    {
        "id": "1",
        "attribute_id": "1",
        "event_id": "100",
        "org_id": "1",
        "date_sighting": "1704067200",
        "type": "0",  # Positive sighting
        "source": "flask-ioc-lookup_test.org",
    },
    {
        "id": "2",
        "attribute_id": "1",
        "event_id": "100",
        "org_id": "2",
        "date_sighting": "1704067100",
        "type": "1",  # False positive
        "source": "flask-ioc-lookup_other.org",
    },
]

SAMPLE_EVENT = {
    "Event": {
        "id": "100",
        "info": "Test Event",
        "date": "2024-01-01",
        "threat_level_id": "2",
        "analysis": "0",
        "distribution": "2",
        "Attribute": SAMPLE_ATTRIBUTES[:1],
    }
}


class MockPyMISP:
    """Mock implementation of ExpandedPyMISP for testing."""

    def __init__(self, url: str, key: str, ssl: bool = True) -> None:
        self.url = url
        self.key = key
        self.ssl = ssl
        self._attributes = {attr["value"]: attr for attr in SAMPLE_ATTRIBUTES}
        self._sightings: list[dict[str, Any]] = list(SAMPLE_SIGHTINGS)
        self._events: list[dict[str, Any]] = [SAMPLE_EVENT]

    def search(
        self,
        controller: str = "attributes",
        **kwargs: Any,
    ) -> dict[str, Any] | list[Any]:
        """Mock search method."""
        if controller == "attributes":
            # Filter by type_attribute if provided
            type_attr = kwargs.get("type_attribute", [])
            value: str = kwargs.get("value", "")
            searchall = kwargs.get("searchall", False)

            if isinstance(type_attr, str):
                type_attr = [type_attr]

            results = []
            for attr in SAMPLE_ATTRIBUTES:
                # Match by value (exact or partial for searchall)
                value_match = False
                if value:
                    attr_value = str(attr["value"])
                    if searchall:
                        value_match = value.replace("%", "") in attr_value
                    else:
                        value_match = attr_value == value
                else:
                    value_match = True

                # Match by type if specified
                type_match = not type_attr or attr["type"] in type_attr

                if value_match and type_match:
                    results.append(attr)

            return {"Attribute": results}

        return {"Attribute": []}

    def search_sightings(
        self,
        context: str = "attribute",
        context_id: str | None = None,
        source: str | None = None,
        type_sighting: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        pythonify: bool = False,
    ) -> list[dict[str, Any]]:
        """Mock search_sightings method."""
        results = []
        for sighting in self._sightings:
            # Filter by context_id (attribute_id)
            if context_id and sighting["attribute_id"] != context_id:
                continue
            # Filter by source
            if source and sighting["source"] != source:
                continue
            # Filter by type
            if type_sighting and sighting["type"] != type_sighting:
                continue

            if pythonify:
                misp_sighting = MISPSighting()
                misp_sighting.from_dict(**sighting)
                results.append({"sighting": misp_sighting})
            else:
                results.append({"Sighting": sighting})  # type: ignore[dict-item]

        return results

    def add_event(self, event: MISPEvent) -> MISPEvent:
        """Mock add_event method."""
        # Return the event with an ID assigned
        event_dict = event.to_dict()
        event_dict["id"] = str(len(self._events) + 100)
        self._events.append({"Event": event_dict})

        result = MISPEvent()
        result.from_dict(**event_dict)
        return result

    def add_sighting(self, sighting: MISPSighting, pythonify: bool = False) -> MISPSighting | dict[str, Any]:
        """Mock add_sighting method."""
        sighting_dict = sighting.to_dict()
        sighting_dict["id"] = str(len(self._sightings) + 1)
        self._sightings.append(sighting_dict)

        if pythonify:
            result = MISPSighting()
            result.from_dict(**sighting_dict)
            return result
        return {"Sighting": sighting_dict}

    def delete_sighting(self, sighting: MISPSighting) -> dict[str, Any]:
        """Mock delete_sighting method."""
        sighting_id = sighting.get("id")
        self._sightings = [s for s in self._sightings if s.get("id") != sighting_id]
        return {"message": "Sighting deleted"}


class MockMISPApi(MISPApi):
    """Mock MISPApi that uses MockPyMISP instead of real ExpandedPyMISP."""

    def __init__(self, name: str = "mock", api_url: str = "https://mock-misp/", api_key: str = "mock-key") -> None:
        self.name = name
        self.pymisp = MockPyMISP(api_url, api_key, ssl=True)  # type: ignore[assignment]

    def reset(self) -> None:
        """Reset the mock to initial state."""
        self.pymisp._sightings = list(SAMPLE_SIGHTINGS)  # type: ignore[attr-defined]
        self.pymisp._events = [SAMPLE_EVENT]  # type: ignore[attr-defined]


@pytest.fixture
def mock_pymisp() -> MockPyMISP:
    """Provide a MockPyMISP instance for testing."""
    return MockPyMISP("https://mock-misp/", "mock-key")


@pytest.fixture
def mock_misp_api() -> MockMISPApi:
    """Provide a MockMISPApi instance for testing."""
    return MockMISPApi()


@pytest.fixture
def test_config_path() -> Path:
    """Return path to test configuration."""
    return Path(__file__).parent / "data" / "test_config.yaml"


@pytest.fixture
def app(test_config_path: Path) -> Generator[IOCLookupApp]:
    """Create and configure a test application instance with routes and mock MISP API."""
    # Set the config path before importing app module
    environ["IOC_LOOKUP_CONFIG"] = str(test_config_path)

    # Patch ExpandedPyMISP before importing app to prevent real MISP connection
    with patch("ioc_lookup.misp_api.ExpandedPyMISP", MockPyMISP):
        # Import the actual app with routes - this creates the app with all routes registered
        from ioc_lookup import app as app_module

        test_app = app_module.app

        # Override config for testing
        test_app.config.update(
            {
                "TESTING": True,
                "DEBUG": True,
                "SIGHTINGS_ENABLED": True,
                "SIGHTING_SOURCE_PREFIX": "flask-ioc-lookup_",
                "SIGHTING_MIN_POSITIVE_VOTE_HOURS": 24,
                "CACHE_TYPE": "SimpleCache",
                "CACHE_DEFAULT_TIMEOUT": 0,  # Disable caching in tests
            }
        )

        # Set up trusted users and orgs for testing
        test_app.trusted_users = ["trusted@test.org"]
        test_app.trusted_orgs = {
            "test.org": TrustedOrg(domain="test.org", misp_api_key="test-api-key"),
        }
        test_app.api_keys = {"test-api-key-123": {"eppn": "api-user@test.org"}}

        # Replace MISP APIs with mocks
        test_app.misp_apis = {
            "default": MockMISPApi(name="default"),
            "proxy": MockMISPApi(name="proxy"),
            "test.org": MockMISPApi(name="test.org"),
        }

        yield test_app


@pytest.fixture
def client(app: IOCLookupApp) -> FlaskClient:
    """Create a test client for the application."""
    return app.test_client()


class AuthenticatedClient:
    """Test client with authentication headers."""

    def __init__(self, flask_app: IOCLookupApp) -> None:
        self._app = flask_app
        self._client = flask_app.test_client()
        self._user = "testuser@test.org"

    def _add_auth_headers(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        headers = kwargs.get("headers", {})
        headers["REMOTE_USER"] = self._user
        kwargs["headers"] = headers
        # Also set in environ for Flask to pick up
        kwargs.setdefault("environ_base", {})["HTTP_REMOTE_USER"] = self._user
        return kwargs

    def get(self, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        return self._client.get(*args, **self._add_auth_headers(kwargs))

    def post(self, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        return self._client.post(*args, **self._add_auth_headers(kwargs))

    def set_user(self, user: str) -> None:
        self._user = user


@pytest.fixture
def authenticated_client(app: IOCLookupApp) -> AuthenticatedClient:
    """Create a test client with authentication headers."""
    return AuthenticatedClient(app)


@pytest.fixture
def trusted_user_client(authenticated_client: AuthenticatedClient) -> AuthenticatedClient:
    """Create a test client authenticated as a trusted user."""
    authenticated_client.set_user("trusted@test.org")
    return authenticated_client


@pytest.fixture
def sample_domain_attribute() -> dict[str, Any]:
    """Provide a sample domain attribute."""
    return SAMPLE_ATTRIBUTES[0].copy()


@pytest.fixture
def sample_ip_attribute() -> dict[str, Any]:
    """Provide a sample IP attribute."""
    return SAMPLE_ATTRIBUTES[1].copy()


@pytest.fixture
def sample_md5_attribute() -> dict[str, Any]:
    """Provide a sample MD5 attribute."""
    return SAMPLE_ATTRIBUTES[2].copy()


@pytest.fixture
def sample_url_attribute() -> dict[str, Any]:
    """Provide a sample URL attribute."""
    return SAMPLE_ATTRIBUTES[3].copy()


@pytest.fixture
def sample_sighting() -> dict[str, Any]:
    """Provide a sample sighting."""
    return SAMPLE_SIGHTINGS[0].copy()


# Helper fixture for patching the real MISPApi
@pytest.fixture
def patch_misp_api(mock_misp_api: MockMISPApi) -> Iterator[MockMISPApi]:
    """Patch MISPApi to use MockMISPApi in tests that import app.py."""
    with patch("ioc_lookup.misp_api.ExpandedPyMISP", MockPyMISP):
        yield mock_misp_api

import hashlib
import hmac
import re
import time
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.parse import urlencode

import pytest
from flask import jsonify
from flask.testing import FlaskClient

from ioc_lookup.ioc_lookup_app import IOCLookupApp
from ioc_lookup.misp_api import MISPApi
from ioc_lookup.misp_attributes import Attr, AttrType
from ioc_lookup.parse import InputError, ParseException, defanged_url, get_canonical_url, parse_items, undefang_url
from ioc_lookup.utils import (
    apply_security_settings,
    load_api_keys,
    resolve_security_settings,
    validate_api_keys,
)

from .conftest import TEST_API_KEY, TEST_CSRF_TOKEN, TEST_ORIGIN, AuthenticatedClient, csrf_form_post, prime_csrf

__author__ = "lundberg"


def test_defang_url_handling() -> None:
    defanged_urls = [
        ("hxxp[://]example[.]org", "http://example.org"),
        ("hxxps[://]example[.]org/file/file[.]zip", "https://example.org/file/file.zip"),
        ("hxxps[://]example[.]org/file/SOMETHING/SOME-FILE", "https://example.org/file/SOMETHING/SOME-FILE"),
        (
            "hxxps[://][fd00:2800:21f:cb07:6820:80da:af6b:8b2c]/file[.]zip",
            "https://[fd00:2800:21f:cb07:6820:80da:af6b:8b2c]/file.zip",
        ),
    ]

    for item, expected in defanged_urls:
        assert defanged_url(item) is True, f"{item} is not defanged"
        url = undefang_url(item)
        url = get_canonical_url(url)
        assert url is not None
        assert url == expected, f"{url} != {expected}"


def test_parse_items(app: IOCLookupApp) -> None:
    indata = """
            example.org
            test.example.org
            example[.]org
            hxxp://example[.]org
            hxxps://example[.]org/file/file[.]zip
            http[://]example[.]org
            https[://]example[.]org/file/file[.]zip
            https://[fd00:2800:21f:cb07:6820:80da:af6b:8b2c]/file.zip
            192.168.100.100
            192[.]168[.]100[.]100
            fd00:2800:21f:cb07:6820:80da:af6b:8b2c
            fd00[:]2800[:]21f[:]cb07[:]6820[:]80da[:]af6b[:]8b2c
            0114f0fb3b87f8dc2dcbeda71c8dda9f
            md5:0114f0fb3b87f8dc2dcbeda71c8dda9f
            0b78a829c97b8abaad27a84b0a25f59be83d16bd
            sha1:0b78a829c97b8abaad27a84b0a25f59be83d16bd
            9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140
            sha256:9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140 # some text
            7b77d9c836f414bbb53c6f28fd12550435049a9c22ce21910f23ae51a684be27e9e2d3ab9774da59f8e35bf7267aa3b6b2a48394ea7acce7627b37cec9ea363b
            sha512:7b77d9c836f414bbb53c6f28fd12550435049a9c22ce21910f23ae51a684be27e9e2d3ab9774da59f8e35bf7267aa3b6b2a48394ea7acce7627b37cec9ea363b
            example@example.org
            example@example[.]org
            """
    with app.app_context():
        result = parse_items(indata)
        assert result == [
            Attr(
                value="example.org",
                type=AttrType.DOMAIN,
                search_types=[AttrType.DOMAIN, AttrType.HOSTNAME, AttrType.DOMAIN_IP],
                report_types=[AttrType.DOMAIN],
            ),
            Attr(
                value="test.example.org",
                type=AttrType.DOMAIN,
                search_types=[AttrType.DOMAIN, AttrType.HOSTNAME, AttrType.DOMAIN_IP],
                report_types=[AttrType.DOMAIN],
            ),
            Attr(
                value="example.org",
                type=AttrType.DOMAIN,
                search_types=[AttrType.DOMAIN, AttrType.HOSTNAME, AttrType.DOMAIN_IP],
                report_types=[AttrType.DOMAIN],
            ),
            Attr(
                value="http://example.org", type=AttrType.URL, search_types=[AttrType.URL], report_types=[AttrType.URL]
            ),
            Attr(
                value="https://example.org/file/file.zip",
                type=AttrType.URL,
                search_types=[AttrType.URL],
                report_types=[AttrType.URL],
            ),
            Attr(
                value="http://example.org", type=AttrType.URL, search_types=[AttrType.URL], report_types=[AttrType.URL]
            ),
            Attr(
                value="https://example.org/file/file.zip",
                type=AttrType.URL,
                search_types=[AttrType.URL],
                report_types=[AttrType.URL],
            ),
            Attr(
                value="https://[fd00:2800:21f:cb07:6820:80da:af6b:8b2c]/file.zip",
                type=AttrType.URL,
                search_types=[AttrType.URL],
                report_types=[AttrType.URL],
            ),
            Attr(
                value="192.168.100.100",
                type=AttrType.IP_SRC,
                search_types=[
                    AttrType.DOMAIN_IP,
                    AttrType.IP_SRC,
                    AttrType.IP_SRC_PORT,
                    AttrType.IP_DST,
                    AttrType.IP_DST_PORT,
                ],
                report_types=[AttrType.IP_SRC],
            ),
            Attr(
                value="192.168.100.100",
                type=AttrType.IP_SRC,
                search_types=[
                    AttrType.DOMAIN_IP,
                    AttrType.IP_SRC,
                    AttrType.IP_SRC_PORT,
                    AttrType.IP_DST,
                    AttrType.IP_DST_PORT,
                ],
                report_types=[AttrType.IP_SRC],
            ),
            Attr(
                value="fd00:2800:21f:cb07:6820:80da:af6b:8b2c",
                type=AttrType.IP_SRC,
                search_types=[
                    AttrType.DOMAIN_IP,
                    AttrType.IP_SRC,
                    AttrType.IP_SRC_PORT,
                    AttrType.IP_DST,
                    AttrType.IP_DST_PORT,
                ],
                report_types=[AttrType.IP_SRC],
            ),
            Attr(
                value="fd00:2800:21f:cb07:6820:80da:af6b:8b2c",
                type=AttrType.IP_SRC,
                search_types=[
                    AttrType.DOMAIN_IP,
                    AttrType.IP_SRC,
                    AttrType.IP_SRC_PORT,
                    AttrType.IP_DST,
                    AttrType.IP_DST_PORT,
                ],
                report_types=[AttrType.IP_SRC],
            ),
            Attr(
                value="0114f0fb3b87f8dc2dcbeda71c8dda9f",
                type=AttrType.MD5,
                search_types=[AttrType.MD5, AttrType.FILENAME_MD5, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.MD5],
            ),
            Attr(
                value="0114f0fb3b87f8dc2dcbeda71c8dda9f",
                type=AttrType.MD5,
                search_types=[AttrType.MD5, AttrType.FILENAME_MD5, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.MD5],
            ),
            Attr(
                value="0b78a829c97b8abaad27a84b0a25f59be83d16bd",
                type=AttrType.SHA1,
                search_types=[AttrType.SHA1, AttrType.FILENAME_SHA1, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.SHA1],
            ),
            Attr(
                value="0b78a829c97b8abaad27a84b0a25f59be83d16bd",
                type=AttrType.SHA1,
                search_types=[AttrType.SHA1, AttrType.FILENAME_SHA1, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.SHA1],
            ),
            Attr(
                value="9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140",
                type=AttrType.SHA256,
                search_types=[AttrType.SHA256, AttrType.FILENAME_SHA256, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.SHA256],
            ),
            Attr(
                value="9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140",
                type=AttrType.SHA256,
                search_types=[AttrType.SHA256, AttrType.FILENAME_SHA256, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.SHA256],
            ),
            Attr(
                value="7b77d9c836f414bbb53c6f28fd12550435049a9c22ce21910f23ae51a684be27e9e2d3ab9774da59f8e35bf7267aa3b6b2a48394ea7acce7627b37cec9ea363b",  # noqa: E501
                type=AttrType.SHA512,
                search_types=[AttrType.SHA512, AttrType.FILENAME_SHA512, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.SHA512],
            ),
            Attr(
                value="7b77d9c836f414bbb53c6f28fd12550435049a9c22ce21910f23ae51a684be27e9e2d3ab9774da59f8e35bf7267aa3b6b2a48394ea7acce7627b37cec9ea363b",  # noqa: E501
                type=AttrType.SHA512,
                search_types=[AttrType.SHA512, AttrType.FILENAME_SHA512, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.SHA512],
            ),
            Attr(
                value="example@example.org",
                type=AttrType.EMAIL,
                search_types=[
                    AttrType.EMAIL,
                    AttrType.EMAIL_SRC,
                    AttrType.EMAIL_DST,
                    AttrType.TARGET_EMAIL,
                    AttrType.EPPN,
                ],
                report_types=[AttrType.EMAIL],
            ),
            Attr(
                value="example@example.org",
                type=AttrType.EMAIL,
                search_types=[
                    AttrType.EMAIL,
                    AttrType.EMAIL_SRC,
                    AttrType.EMAIL_DST,
                    AttrType.TARGET_EMAIL,
                    AttrType.EPPN,
                ],
                report_types=[AttrType.EMAIL],
            ),
        ]


def test_parse_items_errors(app: IOCLookupApp) -> None:
    indata = """
            example.org
            test.example.org
            example[.]org
            some other text sha1:0b78a829c97b8abaad27a84b0a25f59be83d16bd
            other text here:9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140
            """
    with app.app_context():
        with pytest.raises(ParseException) as e:
            parse_items(indata)
        assert e.value.errors == [
            InputError(
                line=5,
                message="Invalid input:             some other text sha1:0b78a829c97b8abaad27a84b0a25f59be83d16bd",
            ),
            InputError(
                line=6,
                message="Invalid input:             other text here:9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140",  # noqa: E501
            ),
        ]
        assert jsonify({"errors": e.value.errors}).json == {
            "errors": [
                {
                    "line": 5,
                    "message": "Invalid input:             some other text sha1:0b78a829c97b8abaad27a84b0a25f59be83d16bd",  # noqa: E501
                },
                {
                    "line": 6,
                    "message": "Invalid input:             other text here:9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140",  # noqa: E501
                },
            ]
        }


# =============================================================================
# Webapp Integration Tests using Mock MISP API
# =============================================================================


class TestIndexRoute:
    """Tests for the index/search route."""

    def test_index_get_no_auth_debug_mode(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test index GET without authentication in debug mode."""
        with app.app_context():
            response = client.get("/")
            # In debug mode, should return 200 even without auth
            assert response.status_code == 200

    def test_index_search_via_url_path(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test search via URL path parameter."""
        with app.app_context():
            # Search for a domain that exists in mock data
            response = client.get("/malicious.example.com")
            assert response.status_code == 200
            # Response should contain the search term
            assert b"malicious.example.com" in response.data

    def test_index_search_via_post(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test search via POST form."""
        with app.app_context():
            response = csrf_form_post(client, "/", data={"search_query": "192.168.1.100"})
            assert response.status_code == 200

    def test_index_search_invalid_input(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test search with invalid input."""
        with app.app_context():
            response = csrf_form_post(client, "/", data={"search_query": "not a valid ioc!@#$"})
            assert response.status_code == 200
            # Should show error message
            assert b"Invalid input" in response.data

    def test_index_search_with_related_results(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test search with related results enabled."""
        with app.app_context():
            response = csrf_form_post(
                client,
                "/",
                data={"search_query": "malicious.example.com", "related_results": "yes"},
            )
            assert response.status_code == 200


class TestIndexJsonRoute:
    """Tests for the JSON API index route."""

    def test_index_json_get_no_query(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test JSON API GET without search query."""
        with app.app_context():
            response = client.get("/", headers={"Accept": "application/json"})
            assert response.status_code == 200
            data = response.get_json()
            assert "error" in data
            assert data["error"] == "No search query"

    def test_index_json_search_via_path(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test JSON API search via URL path."""
        with app.app_context():
            response = client.get("/malicious.example.com", headers={"Accept": "application/json"})
            assert response.status_code == 200
            data = response.get_json()
            assert "result" in data

    def test_index_json_search_via_post(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test JSON API search via POST."""
        with app.app_context():
            response = client.post(
                "/",
                json={"search": "192.168.1.100"},
                headers={"Accept": "application/json", "API-TOKEN": "test-api-key-123"},
            )
            assert response.status_code == 200
            data = response.get_json()
            assert "result" in data

    def test_index_json_search_domain(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test JSON API search for domain returns matching attributes."""
        with app.app_context():
            response = client.get("/malicious.example.com", headers={"Accept": "application/json"})
            assert response.status_code == 200
            data = response.get_json()
            assert "result" in data
            # Should return the matching domain attribute from mock
            assert len(data["result"]) >= 1
            assert any(attr["value"] == "malicious.example.com" for attr in data["result"])

    def test_index_json_search_ip(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test JSON API search for IP address."""
        with app.app_context():
            response = client.get("/192.168.1.100", headers={"Accept": "application/json"})
            assert response.status_code == 200
            data = response.get_json()
            assert "result" in data
            assert len(data["result"]) >= 1

    def test_index_json_search_md5(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test JSON API search for MD5 hash."""
        with app.app_context():
            response = client.get(
                "/0114f0fb3b87f8dc2dcbeda71c8dda9f",
                headers={"Accept": "application/json"},
            )
            assert response.status_code == 200
            data = response.get_json()
            assert "result" in data

    def test_index_json_invalid_input(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test JSON API with invalid input."""
        with app.app_context():
            response = client.post(
                "/",
                json={"search": "invalid!@#$%"},
                headers={"Accept": "application/json", "API-TOKEN": "test-api-key-123"},
            )
            assert response.status_code == 200
            data = response.get_json()
            assert "error" in data
            assert data["error"] == "Invalid input"


class TestReportRoute:
    """Tests for the report route."""

    def test_report_get(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report GET returns the form."""
        with app.app_context():
            response = client.get("/report")
            assert response.status_code == 200

    def test_report_post_missing_info(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report POST with missing event info."""
        with app.app_context():
            response = csrf_form_post(
                client,
                "/report",
                data={
                    "ioc": "evil.example.com",
                    "tlp": "tlp:green",
                    # Missing 'info' field
                },
            )
            assert response.status_code == 200
            assert b"Event info needs to be a short description" in response.data

    def test_report_post_invalid_tag(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report POST with invalid tag."""
        with app.app_context():
            response = csrf_form_post(
                client,
                "/report",
                data={
                    "ioc": "evil.example.com",
                    "tlp": "tlp:green",
                    "info": "Test event",
                    "tag_InvalidTag": "on",
                },
            )
            assert response.status_code == 200
            assert b"Invalid tag input" in response.data

    def test_report_post_valid_domain(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report POST with valid domain IOC."""
        with app.app_context():
            response = csrf_form_post(
                client,
                "/report",
                data={
                    "ioc": "evil.example.com",
                    "tlp": "tlp:green",
                    "info": "Test malicious domain report",
                    "tag_Phishing": "on",
                },
            )
            assert response.status_code == 200
            # Should show success or the reported item
            assert b"evil.example.com" in response.data

    def test_report_post_valid_url(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report POST with valid URL IOC."""
        with app.app_context():
            response = csrf_form_post(
                client,
                "/report",
                data={
                    "ioc": "https://phishing.example.com/login",
                    "tlp": "tlp:amber",
                    "info": "Phishing URL report",
                },
            )
            assert response.status_code == 200

    def test_report_post_empty_ioc(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report POST with empty IOC."""
        with app.app_context():
            response = csrf_form_post(
                client,
                "/report",
                data={
                    "ioc": "",
                    "tlp": "tlp:green",
                    "info": "Test event",
                },
            )
            assert response.status_code == 200
            assert b"No valid input found" in response.data


class TestReportJsonRoute:
    """Tests for the JSON API report route."""

    def test_report_json_get_not_allowed(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report JSON GET returns error."""
        with app.app_context():
            response = client.get("/report", headers={"Accept": "application/json"})
            assert response.status_code == 200
            data = response.get_json()
            assert data["error"] == "Invalid request method"

    def test_report_json_post_valid(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report JSON POST with valid data."""
        with app.app_context():
            response = client.post(
                "/report",
                json={
                    "ioc": "evil.example.com",
                    "tlp": "tlp:green",
                    "info": "Test event via API",
                    "tags": ["Phishing"],
                },
                headers={"Accept": "application/json", "API-TOKEN": "test-api-key-123"},
            )
            assert response.status_code == 200
            data = response.get_json()
            assert "report" in data
            assert len(data["report"]) >= 1
            assert data["report"][0]["value"] == "evil.example.com"

    def test_report_json_post_missing_info(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report JSON POST with missing info."""
        with app.app_context():
            response = client.post(
                "/report",
                json={
                    "ioc": "evil.example.com",
                    "tlp": "tlp:green",
                },
                headers={"Accept": "application/json", "API-TOKEN": "test-api-key-123"},
            )
            assert response.status_code == 200
            data = response.get_json()
            assert "error" in data

    def test_report_json_post_invalid_tag(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report JSON POST with invalid tag."""
        with app.app_context():
            response = client.post(
                "/report",
                json={
                    "ioc": "evil.example.com",
                    "tlp": "tlp:green",
                    "info": "Test event",
                    "tags": ["InvalidTag"],
                },
                headers={"Accept": "application/json", "API-TOKEN": "test-api-key-123"},
            )
            assert response.status_code == 200
            data = response.get_json()
            assert "error" in data
            assert data["error"] == "Invalid tag input"

    def test_report_json_post_multiple_iocs(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report JSON POST with multiple IOCs."""
        with app.app_context():
            response = client.post(
                "/report",
                json={
                    "ioc": "evil.example.com\n192.168.1.1",
                    "tlp": "tlp:green",
                    "info": "Multiple IOC report",
                },
                headers={"Accept": "application/json", "API-TOKEN": "test-api-key-123"},
            )
            assert response.status_code == 200
            data = response.get_json()
            assert "report" in data
            assert len(data["report"]) >= 2


class TestSightingRoutes:
    """Tests for sighting-related routes."""

    def test_report_sighting_requires_trusted_org(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report-sighting requires user from trusted org."""
        with app.app_context():
            # Without trusted org user, should get 401
            response = csrf_form_post(
                client,
                "/report-sighting",
                data={"search_query": "malicious.example.com", "type": "0"},
            )
            assert response.status_code == 401

    def test_report_sighting_disabled(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report-sighting when sightings are disabled."""
        app.config["SIGHTINGS_ENABLED"] = False
        with app.app_context():
            response = csrf_form_post(
                client,
                "/report-sighting",
                data={"search_query": "malicious.example.com", "type": "0"},
                environ_base={"HTTP_REMOTE_USER": "user@test.org"},
            )
            assert response.status_code == 401
        # Reset config
        app.config["SIGHTINGS_ENABLED"] = True

    def test_report_sighting_missing_params(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report-sighting with missing parameters."""
        with app.app_context():
            response = csrf_form_post(
                client,
                "/report-sighting",
                data={},
                environ_base={"HTTP_REMOTE_USER": "user@test.org"},
            )
            assert response.status_code == 400

    def test_remove_sighting_requires_trusted_org(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test remove-sighting requires user from trusted org."""
        with app.app_context():
            response = csrf_form_post(
                client,
                "/remove-sighting",
                data={"search_query": "malicious.example.com", "type": "0"},
            )
            assert response.status_code == 401

    def test_remove_sighting_disabled(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test remove-sighting when sightings are disabled."""
        app.config["SIGHTINGS_ENABLED"] = False
        with app.app_context():
            response = csrf_form_post(
                client,
                "/remove-sighting",
                data={"search_query": "malicious.example.com", "type": "0"},
                environ_base={"HTTP_REMOTE_USER": "user@test.org"},
            )
            assert response.status_code == 401
        # Reset config
        app.config["SIGHTINGS_ENABLED"] = True


class TestAuthenticatedRequests:
    """Tests for authenticated requests using the authenticated_client fixture."""

    def test_authenticated_search(self, app: IOCLookupApp, authenticated_client: AuthenticatedClient) -> None:
        """Test search with authenticated user."""
        with app.app_context():
            response = authenticated_client.get("/malicious.example.com")
            assert response.status_code == 200

    def test_authenticated_report(self, app: IOCLookupApp, authenticated_client: AuthenticatedClient) -> None:
        """Test report with authenticated user."""
        with app.app_context():
            response = authenticated_client.post(
                "/report",
                data={
                    "ioc": "reported.example.com",
                    "tlp": "tlp:green",
                    "info": "Authenticated report test",
                },
            )
            assert response.status_code == 200

    def test_trusted_user_report(self, app: IOCLookupApp, trusted_user_client: AuthenticatedClient) -> None:
        """Test report with trusted user (events get published)."""
        with app.app_context():
            response = trusted_user_client.post(
                "/report",
                data={
                    "ioc": "trusted-report.example.com",
                    "tlp": "tlp:green",
                    "info": "Trusted user report",
                },
            )
            assert response.status_code == 200

    def test_trusted_org_user_can_add_sighting(
        self, app: IOCLookupApp, authenticated_client: AuthenticatedClient
    ) -> None:
        """Test that trusted org user can add sighting."""
        with app.app_context():
            response = authenticated_client.post(
                "/report-sighting",
                data={"search_query": "malicious.example.com", "type": "0"},
            )
            # Should redirect (302) on success
            assert response.status_code == 302


class TestApiKeyPrivileges:
    """An API key acts as the eppn it maps to, including trusted user/org privileges."""

    @pytest.fixture
    def key_owner(self, app: IOCLookupApp) -> Generator[Any]:
        original_keys, original_users = app.api_keys, app.trusted_users

        def set_owner(eppn: str) -> None:
            app.api_keys = {TEST_API_KEY: eppn}

        yield set_owner
        app.api_keys, app.trusted_users = original_keys, original_users

    def _report(self, client: FlaskClient) -> Any:  # noqa: ANN401
        with patch.object(MISPApi, "add_event") as add_event:
            response = client.post(
                "/report",
                json={"ioc": "apikey.example.com", "tlp": "tlp:green", "info": "api key test"},
                headers={"API-TOKEN": TEST_API_KEY, "Accept": "application/json"},
            )
        return response, add_event

    def test_api_key_mapped_to_trusted_eppn_can_publish(
        self,
        app: IOCLookupApp,
        client: FlaskClient,
        key_owner: Any,  # noqa: ANN401
    ) -> None:
        key_owner("trusted@test.org")
        response, add_event = self._report(client)
        assert response.status_code == 200
        add_event.assert_called_once()
        assert add_event.call_args.kwargs["published"] is True

    def test_api_key_mapped_to_untrusted_eppn_does_not_publish(
        self,
        app: IOCLookupApp,
        client: FlaskClient,
        key_owner: Any,  # noqa: ANN401
    ) -> None:
        key_owner("nobody@elsewhere.org")
        response, add_event = self._report(client)
        assert response.status_code == 200
        add_event.assert_called_once()
        assert not add_event.call_args.kwargs["published"]

    @pytest.mark.parametrize("vote_type", ["0", "1"])
    def test_trusted_org_user_can_vote(
        self, app: IOCLookupApp, authenticated_client: AuthenticatedClient, vote_type: str
    ) -> None:
        before = _state(app)
        response = authenticated_client.post(
            "/report-sighting", data={"search_query": "malicious.example.com", "type": vote_type}
        )
        assert response.status_code == 302
        assert sum(s for _, s in _state(app)) == sum(s for _, s in before) + 1

    def test_untrusted_org_user_cannot_vote(self, app: IOCLookupApp, authenticated_client: AuthenticatedClient) -> None:
        authenticated_client.set_user("someone@untrusted.org")
        before = _state(app)
        response = authenticated_client.post(
            "/report-sighting", data={"search_query": "malicious.example.com", "type": "0"}
        )
        assert response.status_code == 401
        assert _state(app) == before


class TestResolveSecuritySettings:
    def test_cookie_defaults(self) -> None:
        resolved = resolve_security_settings({"SECRET_KEY": "k"}, {})
        assert resolved["SESSION_COOKIE_NAME"] == "ioc_lookup_session"
        assert resolved["SESSION_COOKIE_SECURE"] is True
        assert resolved["SESSION_COOKIE_SAMESITE"] == "Lax"
        assert resolved["SESSION_COOKIE_HTTPONLY"] is True

    def test_yaml_secure_false(self) -> None:
        assert (
            resolve_security_settings({"SECRET_KEY": "k", "SESSION_COOKIE_SECURE": False}, {})["SESSION_COOKIE_SECURE"]
            is False
        )

    def test_yaml_null_uses_default(self) -> None:
        resolved = resolve_security_settings({"SECRET_KEY": "k", "SESSION_COOKIE_SECURE": None}, {})
        assert resolved["SESSION_COOKIE_SECURE"] is True

    def test_env_secret_overrides_yaml(self) -> None:
        resolved = resolve_security_settings({"SECRET_KEY": "yaml"}, {"IOC_LOOKUP_SECRET_KEY": "env"})
        assert resolved["SECRET_KEY"] == "env"

    def test_missing_secret_key(self) -> None:
        with pytest.raises(ValueError, match="SECRET_KEY"):
            resolve_security_settings({}, {})
        with pytest.raises(ValueError, match="SECRET_KEY"):
            resolve_security_settings({"SECRET_KEY": ""}, {"IOC_LOOKUP_SECRET_KEY": ""})

    @pytest.mark.parametrize("bad", [123, True, ["a"], {"a": "b"}, b"bytes", "   "])
    def test_non_string_secret_key_rejected(self, bad: Any) -> None:  # noqa: ANN401
        with pytest.raises(ValueError, match="non-blank string") as exc_info:
            resolve_security_settings({"SECRET_KEY": bad}, {})
        assert str(bad) not in str(exc_info.value) or str(bad).strip() == ""


class TestConfigFailures:
    def test_missing_secret_raises_and_logs(self) -> None:
        logger = MagicMock()
        config: dict[str, Any] = {}
        with pytest.raises(RuntimeError, match="SECRET_KEY must be set"):
            apply_security_settings(config, {}, {}, logger)
        logger.error.assert_called_once()
        assert config == {}

    def test_empty_yaml_gives_operator_message(self) -> None:
        import yaml

        loaded = yaml.safe_load("# only a comment\n")
        yaml_config = loaded if isinstance(loaded, dict) else {}
        with pytest.raises(RuntimeError, match="SECRET_KEY must be set"):
            apply_security_settings({}, yaml_config, {}, MagicMock())

    def test_applies_settings(self) -> None:
        config: dict[str, Any] = {}
        apply_security_settings(config, {"SECRET_KEY": "k"}, {}, MagicMock())
        assert config["SECRET_KEY"] == "k"
        assert config["SESSION_COOKIE_SECURE"] is True

    def test_bad_api_keys_raise_without_key_values(self) -> None:
        logger = MagicMock()
        with pytest.raises(RuntimeError) as exc:
            load_api_keys({"secret-key": {"x": 1}}, logger)
        assert "secret-key" not in str(exc.value)
        assert "secret-key" not in str(logger.error.call_args)
        assert load_api_keys(None, logger) == {}


class TestValidateApiKeys:
    def test_valid_and_empty(self) -> None:
        assert validate_api_keys({"k": "a@b.org"}) == {"k": "a@b.org"}
        assert validate_api_keys(None) == {}
        assert validate_api_keys({}) == {}

    @pytest.mark.parametrize(
        "raw", [{"secret-key": {"nested": "x"}}, {"secret-key": ""}, {"secret-key": None}, {"": "a@b.org"}, ["x"]]
    )
    def test_invalid_does_not_leak_keys(self, raw: object) -> None:
        with pytest.raises(ValueError) as exc:
            validate_api_keys(raw)
        assert "secret-key" not in str(exc.value)


class TestErrorHandling:
    """Tests for error handling."""

    def test_misp_unavailable_html(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test MISP unavailable error returns proper HTML response."""
        # Temporarily remove MISP APIs to simulate unavailability
        original_apis = app.misp_apis
        app.misp_apis = None
        with app.app_context():
            response = client.get("/test.example.com")
            # Should handle the error gracefully
            assert response.status_code == 500 or b"unavailable" in response.data.lower()
        # Restore
        app.misp_apis = original_apis

    def test_misp_unavailable_json(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test MISP unavailable error returns proper JSON response."""
        original_apis = app.misp_apis
        app.misp_apis = None
        with app.app_context():
            response = client.get("/test.example.com", headers={"Accept": "application/json"})
            assert response.status_code == 500
            data = response.get_json()
            assert "message" in data
        # Restore
        app.misp_apis = original_apis


class TestDefangedInputs:
    """Tests for handling defanged IOC inputs."""

    def test_search_defanged_domain(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test search with defanged domain."""
        with app.app_context():
            response = csrf_form_post(client, "/", data={"search_query": "example[.]com"})
            assert response.status_code == 200

    def test_search_defanged_url(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test search with defanged URL."""
        with app.app_context():
            response = csrf_form_post(client, "/", data={"search_query": "hxxps[://]example[.]com/path"})
            assert response.status_code == 200

    def test_search_defanged_ip(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test search with defanged IP."""
        with app.app_context():
            response = csrf_form_post(client, "/", data={"search_query": "192[.]168[.]1[.]100"})
            assert response.status_code == 200

    def test_report_defanged_domain(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report with defanged domain."""
        with app.app_context():
            response = csrf_form_post(
                client,
                "/report",
                data={
                    "ioc": "evil[.]example[.]com",
                    "tlp": "tlp:green",
                    "info": "Defanged domain report",
                },
            )
            assert response.status_code == 200


CSRF_ENDPOINTS = {
    "/report": {"ioc": "csrf.example.com", "tlp": "tlp:green", "info": "CSRF test"},
    "/report-sighting": {"search_query": "malicious.example.com", "type": "0"},
    "/remove-sighting": {"search_query": "malicious.example.com", "type": "0"},
    "/": {"search_query": "192.168.1.100"},
}
USER_ENV = {"HTTP_REMOTE_USER": "testuser@test.org"}


def _state(app: IOCLookupApp) -> list[tuple[int, int]]:
    return [(len(api.pymisp._events), len(api.pymisp._sightings)) for api in app.misp_apis.values()]  # type: ignore[union-attr]


class TestCsrfProtection:
    """Tests for CSRF protection of unsafe requests."""

    @pytest.fixture
    def spies(self, app: IOCLookupApp):  # noqa: ANN201
        with (
            patch.object(MISPApi, "attr_search") as attr_search,
            patch.object(MISPApi, "add_event") as add_event,
            patch.object(MISPApi, "add_sighting") as add_sighting,
        ):
            self.attr_search, self.add_event, self.add_sighting = attr_search, add_event, add_sighting
            yield

    def _assert_untouched(self, app: IOCLookupApp, before: list[tuple[int, int]]) -> None:
        assert hasattr(self, "attr_search"), "requires spies fixture"
        assert _state(app) == before
        self.attr_search.assert_not_called()
        self.add_event.assert_not_called()
        self.add_sighting.assert_not_called()

    @pytest.mark.parametrize("url", list(CSRF_ENDPOINTS))
    @pytest.mark.usefixtures("spies")
    def test_no_token(self, app: IOCLookupApp, client: FlaskClient, url: str) -> None:
        before = _state(app)
        prime_csrf(client)
        response = client.post(url, data=CSRF_ENDPOINTS[url], headers={"Origin": TEST_ORIGIN}, environ_base=USER_ENV)
        assert response.status_code == 400
        self._assert_untouched(app, before)

    @pytest.mark.parametrize("url", list(CSRF_ENDPOINTS))
    @pytest.mark.usefixtures("spies")
    def test_garbage_token(self, app: IOCLookupApp, client: FlaskClient, url: str) -> None:
        before = _state(app)
        prime_csrf(client)
        data = {**CSRF_ENDPOINTS[url], "csrf_token": "garbage"}
        response = client.post(url, data=data, headers={"Origin": TEST_ORIGIN}, environ_base=USER_ENV)
        assert response.status_code == 400
        self._assert_untouched(app, before)

    @pytest.mark.parametrize("url", list(CSRF_ENDPOINTS))
    @pytest.mark.usefixtures("spies")
    def test_token_without_session(self, app: IOCLookupApp, client: FlaskClient, url: str) -> None:
        before = _state(app)
        data = {**CSRF_ENDPOINTS[url], "csrf_token": "some-token"}
        response = client.post(url, data=data, headers={"Origin": TEST_ORIGIN}, environ_base=USER_ENV)
        assert response.status_code == 400
        self._assert_untouched(app, before)

    @pytest.mark.parametrize("url", list(CSRF_ENDPOINTS))
    @pytest.mark.usefixtures("spies")
    def test_cross_session_token(self, app: IOCLookupApp, url: str) -> None:
        before = _state(app)
        attacker = app.test_client()
        victim = app.test_client()
        token = prime_csrf(attacker, "attacker-token")
        prime_csrf(victim, "victim-token")
        data = {**CSRF_ENDPOINTS[url], "csrf_token": token}
        response = victim.post(url, data=data, headers={"Origin": TEST_ORIGIN}, environ_base=USER_ENV)
        assert response.status_code == 400
        self._assert_untouched(app, before)

    @pytest.mark.parametrize("url", list(CSRF_ENDPOINTS))
    @pytest.mark.parametrize(
        "headers", [{"Origin": "http://evil.example"}, {"Origin": "null"}, {"Referer": "http://evil.example/x"}]
    )
    @pytest.mark.usefixtures("spies")
    def test_foreign_origin(self, app: IOCLookupApp, client: FlaskClient, url: str, headers: dict[str, str]) -> None:
        before = _state(app)
        token = prime_csrf(client)
        data = {**CSRF_ENDPOINTS[url], "csrf_token": token}
        response = client.post(url, data=data, headers=headers, environ_base=USER_ENV)
        assert response.status_code == 403
        self._assert_untouched(app, before)

    @pytest.mark.parametrize("url", list(CSRF_ENDPOINTS))
    @pytest.mark.usefixtures("spies")
    def test_no_origin_no_referer(self, app: IOCLookupApp, client: FlaskClient, url: str) -> None:
        before = _state(app)
        token = prime_csrf(client)
        data = {**CSRF_ENDPOINTS[url], "csrf_token": token}
        response = client.post(url, data=data, environ_base=USER_ENV)
        assert response.status_code == 403
        self._assert_untouched(app, before)

    def test_referer_fallback_allowed(self, app: IOCLookupApp, client: FlaskClient) -> None:
        token = prime_csrf(client, identity=USER_ENV["HTTP_REMOTE_USER"])
        data = {**CSRF_ENDPOINTS["/"], "csrf_token": token}
        response = client.post("/", data=data, headers={"Referer": f"{TEST_ORIGIN}/somewhere"}, environ_base=USER_ENV)
        assert response.status_code == 200

    def test_header_token_accepted(self, app: IOCLookupApp, client: FlaskClient) -> None:
        token = prime_csrf(client, identity=USER_ENV["HTTP_REMOTE_USER"])
        response = client.post(
            "/", data=CSRF_ENDPOINTS["/"], headers={"Origin": TEST_ORIGIN, "X-CSRF-Token": token}, environ_base=USER_ENV
        )
        assert response.status_code == 200

    def test_valid_report(self, app: IOCLookupApp, client: FlaskClient) -> None:
        before = _state(app)
        response = csrf_form_post(client, "/report", CSRF_ENDPOINTS["/report"], environ_base=USER_ENV)
        assert response.status_code == 200
        assert sum(e for e, _ in _state(app)) == sum(e for e, _ in before) + 1

    def test_valid_report_sighting(self, app: IOCLookupApp, authenticated_client: AuthenticatedClient) -> None:
        before = _state(app)
        response = authenticated_client.post("/report-sighting", data=CSRF_ENDPOINTS["/report-sighting"])
        assert response.status_code == 302
        assert sum(s for _, s in _state(app)) == sum(s for _, s in before) + 1

    def test_end_to_end_form_token(self, app: IOCLookupApp, client: FlaskClient) -> None:
        page = client.get("/report")
        match = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        assert match is not None
        response = client.post(
            "/report",
            data={**CSRF_ENDPOINTS["/report"], "csrf_token": match.group(1).decode()},
            headers={"Origin": TEST_ORIGIN},
        )
        assert response.status_code == 200

    def test_json_with_valid_api_token(self, app: IOCLookupApp, client: FlaskClient) -> None:
        response = client.post(
            "/report",
            json=CSRF_ENDPOINTS["/report"],
            headers={"Accept": "application/json", "API-TOKEN": TEST_API_KEY},
        )
        assert response.status_code == 200

    @pytest.mark.usefixtures("spies")
    def test_json_accept_form_without_api_token_rejected(self, app: IOCLookupApp, client: FlaskClient) -> None:
        before = _state(app)
        response = client.post(
            "/report",
            data=CSRF_ENDPOINTS["/report"],
            headers={"Accept": "application/json", "Origin": "http://evil.example"},
        )
        assert response.status_code in (400, 403)
        assert response.get_json()["status"] == response.status_code
        self._assert_untouched(app, before)

    @pytest.mark.usefixtures("spies")
    def test_invalid_api_token_rejected(self, app: IOCLookupApp, client: FlaskClient) -> None:
        before = _state(app)
        response = client.post(
            "/report",
            json=CSRF_ENDPOINTS["/report"],
            headers={"Accept": "application/json", "API-TOKEN": "not-a-valid-key"},
        )
        assert response.status_code in (400, 403)
        self._assert_untouched(app, before)

    @pytest.mark.usefixtures("spies")
    def test_json_post_with_api_token_and_foreign_origin_allowed(self, app: IOCLookupApp, client: FlaskClient) -> None:
        with patch.object(app.logger, "info") as info:
            response = client.post(
                "/report",
                json=CSRF_ENDPOINTS["/report"],
                headers={"API-TOKEN": TEST_API_KEY, "Origin": "http://evil.example", "Accept": "application/json"},
            )
        assert response.status_code == 200
        self.add_event.assert_called()
        logged = " ".join(str(c.args[0]) for c in info.call_args_list)
        assert "api-user@test.org" in logged
        assert TEST_API_KEY not in logged

    @pytest.mark.usefixtures("spies")
    def test_form_post_with_api_token_and_foreign_origin_rejected(self, app: IOCLookupApp, client: FlaskClient) -> None:
        before = _state(app)
        with patch.object(app.logger, "warning") as warning:
            response = client.post(
                "/report",
                data=CSRF_ENDPOINTS["/report"],
                headers={"API-TOKEN": TEST_API_KEY, "Origin": "http://evil.example"},
            )
        assert response.status_code in (400, 403)
        self._assert_untouched(app, before)
        logged = " ".join(str(c.args[0]) for c in warning.call_args_list)
        assert "non-JSON content type" in logged
        assert TEST_API_KEY not in logged

    @pytest.mark.usefixtures("spies")
    def test_unknown_api_token_with_foreign_origin_rejected(self, app: IOCLookupApp, client: FlaskClient) -> None:
        before = _state(app)
        response = client.post(
            "/report",
            data=CSRF_ENDPOINTS["/report"],
            headers={"API-TOKEN": "unknown-key", "Origin": "http://evil.example"},
        )
        assert response.status_code in (400, 403)
        self._assert_untouched(app, before)

    @pytest.mark.parametrize("token", ["", "   "])
    @pytest.mark.usefixtures("spies")
    def test_empty_api_token_rejected(self, app: IOCLookupApp, client: FlaskClient, token: str) -> None:
        before = _state(app)
        response = client.post(
            "/report",
            data=CSRF_ENDPOINTS["/report"],
            headers={"API-TOKEN": token, "Origin": "http://evil.example"},
        )
        assert response.status_code in (400, 403)
        self._assert_untouched(app, before)

    @pytest.mark.usefixtures("spies")
    def test_json_post_same_origin_without_api_token(self, app: IOCLookupApp, client: FlaskClient) -> None:
        before = _state(app)
        response = client.post(
            "/report",
            json=CSRF_ENDPOINTS["/report"],
            headers={"Accept": "application/json", "Origin": TEST_ORIGIN},
            environ_base=USER_ENV,
        )
        assert response.status_code == 400
        self._assert_untouched(app, before)

    @pytest.mark.usefixtures("spies")
    def test_remote_user_json_post_with_session_token(self, app: IOCLookupApp, client: FlaskClient) -> None:
        token = prime_csrf(client, identity=USER_ENV["HTTP_REMOTE_USER"])
        response = client.post(
            "/report",
            json=CSRF_ENDPOINTS["/report"],
            headers={"Accept": "application/json", "Origin": TEST_ORIGIN, "X-CSRF-Token": token},
            environ_base=USER_ENV,
        )
        assert response.status_code == 200
        self.add_event.assert_called()

    @pytest.fixture
    def tight_limit(self, app: IOCLookupApp) -> Generator[None]:
        from ioc_lookup.app import limiter

        original = app.config["REQUEST_RATE_LIMIT"]
        app.config["REQUEST_RATE_LIMIT"] = "3/minute"
        limiter.reset()
        yield
        app.config["REQUEST_RATE_LIMIT"] = original
        limiter.reset()

    @pytest.mark.usefixtures("spies", "tight_limit")
    def test_rate_limit_precedes_csrf(self, app: IOCLookupApp, client: FlaskClient) -> None:
        codes = [client.post("/report", data=CSRF_ENDPOINTS["/report"]).status_code for _ in range(5)]
        assert codes[:3] == [403, 403, 403]
        assert codes[3:] == [429, 429]

    @pytest.mark.usefixtures("tight_limit")
    def test_decorated_route_still_limited(self, app: IOCLookupApp, client: FlaskClient) -> None:
        codes = [client.get("/report").status_code for _ in range(5)]
        assert codes == [200, 200, 200, 429, 429]

    @pytest.mark.usefixtures("tight_limit")
    def test_rate_limit_json_response(self, app: IOCLookupApp, client: FlaskClient) -> None:
        for _ in range(3):
            client.get("/report")
        response = client.get("/report", headers={"Accept": "application/json"})
        assert response.status_code == 429
        assert response.get_json()["status"] == 429

    @pytest.mark.usefixtures("tight_limit")
    def test_static_not_rate_limited(self, app: IOCLookupApp, client: FlaskClient) -> None:
        codes = {client.get("/static/css/bootstrap-grid.css").status_code for _ in range(6)}
        assert codes == {200}

    def _form_token(self, client: FlaskClient, user: str | None) -> str:
        env = {"HTTP_REMOTE_USER": user} if user else {}
        page = client.get("/report", environ_base=env)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        assert match is not None
        return match.group(1).decode()

    @pytest.mark.usefixtures("spies")
    def test_token_minted_for_one_identity_rejected_for_another(self, app: IOCLookupApp, client: FlaskClient) -> None:
        token = self._form_token(client, "a@test.org")
        before = _state(app)
        response = client.post(
            "/report",
            data={**CSRF_ENDPOINTS["/report"], "csrf_token": token},
            headers={"Origin": TEST_ORIGIN},
            environ_base={"HTTP_REMOTE_USER": "b@test.org"},
        )
        assert response.status_code == 400
        self._assert_untouched(app, before)

    def test_token_accepted_for_same_identity(self, app: IOCLookupApp, client: FlaskClient) -> None:
        token = self._form_token(client, "a@test.org")
        response = client.post(
            "/report",
            data={**CSRF_ENDPOINTS["/report"], "csrf_token": token},
            headers={"Origin": TEST_ORIGIN},
            environ_base={"HTTP_REMOTE_USER": "a@test.org"},
        )
        assert response.status_code == 200

    def test_new_identity_gets_new_token(self, app: IOCLookupApp, client: FlaskClient) -> None:
        token_a = self._form_token(client, "a@test.org")
        token_b = self._form_token(client, "b@test.org")
        assert token_a != token_b
        assert self._form_token(client, "b@test.org") == token_b

    def test_no_remote_user_consistent(self, app: IOCLookupApp, client: FlaskClient) -> None:
        token = self._form_token(client, None)
        assert self._form_token(client, None) == token
        response = client.post("/", data={**CSRF_ENDPOINTS["/"], "csrf_token": token}, headers={"Origin": TEST_ORIGIN})
        assert response.status_code != 400

    def test_identity_binding_does_not_affect_api_key_json(self, app: IOCLookupApp, client: FlaskClient) -> None:
        response = client.post(
            "/report",
            json=CSRF_ENDPOINTS["/report"],
            headers={"API-TOKEN": TEST_API_KEY, "Accept": "application/json"},
            environ_base={"HTTP_REMOTE_USER": "someone-else@test.org"},
        )
        assert response.status_code == 200

    SLACK_SECRET = "slack-test-secret"

    def _slack_post(
        self,
        client: FlaskClient,
        data: dict[str, str] | None = None,
        secret: str | None = SLACK_SECRET,
        timestamp: str | None = None,
        signature: str | None = None,
        headers: bool = True,
    ) -> Any:  # noqa: ANN401
        body = urlencode(data if data is not None else {"channel_id": "C123", "text": "invalid!@#$"})
        ts = timestamp if timestamp is not None else str(int(time.time()))
        sig = signature
        if sig is None:
            sig = "v0=" + hmac.new((secret or "x").encode(), f"v0:{ts}:{body}".encode(), hashlib.sha256).hexdigest()
        hdrs = {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig} if headers else {}
        return client.post(
            "/slack/ioc-lookup", data=body, content_type="application/x-www-form-urlencoded", headers=hdrs
        )

    @pytest.fixture
    def slack_secret(self, app: IOCLookupApp) -> Generator[None]:
        app.config["SLACK_SIGNING_SECRET"] = self.SLACK_SECRET
        yield
        app.config.pop("SLACK_SIGNING_SECRET", None)

    def test_slack_valid_signature(self, app: IOCLookupApp, client: FlaskClient, slack_secret: None) -> None:
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_post(client)
        assert response.status_code == 200
        post_message.assert_called_once()

    def test_slack_bad_signature(self, app: IOCLookupApp, client: FlaskClient, slack_secret: None) -> None:
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_post(client, signature="v0=" + "0" * 64)
        assert response.status_code in (400, 403)
        post_message.assert_not_called()

    def test_slack_wrong_secret(self, app: IOCLookupApp, client: FlaskClient, slack_secret: None) -> None:
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_post(client, secret="other-secret")
        assert response.status_code in (400, 403)
        post_message.assert_not_called()

    def test_slack_stale_timestamp(self, app: IOCLookupApp, client: FlaskClient, slack_secret: None) -> None:
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_post(client, timestamp=str(int(time.time()) - 301))
        assert response.status_code in (400, 403)
        post_message.assert_not_called()

    def test_slack_non_integer_timestamp(self, app: IOCLookupApp, client: FlaskClient, slack_secret: None) -> None:
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_post(client, timestamp="not-a-number")
        assert response.status_code in (400, 403)
        post_message.assert_not_called()

    def test_slack_huge_timestamp(self, app: IOCLookupApp, client: FlaskClient, slack_secret: None) -> None:
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_post(client, timestamp="9" * 400)
        assert response.status_code in (400, 403)
        post_message.assert_not_called()

    def test_slack_missing_headers(self, app: IOCLookupApp, client: FlaskClient, slack_secret: None) -> None:
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_post(client, headers=False)
        assert response.status_code in (400, 403)
        post_message.assert_not_called()

    def test_slack_no_secret_configured(self, app: IOCLookupApp, client: FlaskClient) -> None:
        app.config.pop("SLACK_SIGNING_SECRET", None)
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_post(client)
        assert response.status_code in (400, 403)
        post_message.assert_not_called()

    def test_slack_body_too_large(self, app: IOCLookupApp, client: FlaskClient, slack_secret: None) -> None:
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_post(client, data={"channel_id": "C123", "text": "a" * 70000})
        assert response.status_code in (400, 403)
        post_message.assert_not_called()

    def test_slack_failure_logged_without_secrets(
        self, app: IOCLookupApp, client: FlaskClient, slack_secret: None
    ) -> None:
        bad_sig = "v0=" + "1" * 64
        with patch.object(app.logger, "warning") as warning:
            self._slack_post(client, signature=bad_sig)
        logged = " ".join(str(c.args[0]) for c in warning.call_args_list)
        assert "bad_signature" in logged
        assert bad_sig not in logged
        assert self.SLACK_SECRET not in logged

    def test_csrf_error_json_negotiation(self, app: IOCLookupApp, client: FlaskClient) -> None:
        resp = client.post("/report", data={}, headers={"Accept": "*/*"})
        assert resp.status_code in (400, 403)
        assert resp.is_json
        resp = client.post("/report", data={}, headers={"Accept": "text/html"})
        assert resp.status_code in (400, 403)
        assert not resp.is_json

    def test_max_content_length_default(self, app: IOCLookupApp) -> None:
        assert app.config["MAX_CONTENT_LENGTH"]

    def _slack_same_origin_post(self, client: FlaskClient, **kwargs: Any) -> Any:  # noqa: ANN401
        token = prime_csrf(client)
        return client.post(
            "/slack/ioc-lookup",
            data={"channel_id": "C123", "text": "example.com", "csrf_token": token},
            headers={"Origin": TEST_ORIGIN, **kwargs.pop("headers", {})},
            **kwargs,
        )

    def test_slack_session_token_without_signature_rejected(
        self, app: IOCLookupApp, client: FlaskClient, slack_secret: None
    ) -> None:
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_same_origin_post(client)
        assert response.status_code == 403
        post_message.assert_not_called()

    def test_slack_session_token_bad_signature_rejected(
        self, app: IOCLookupApp, client: FlaskClient, slack_secret: None
    ) -> None:
        headers = {"X-Slack-Request-Timestamp": str(int(time.time())), "X-Slack-Signature": "v0=" + "0" * 64}
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_same_origin_post(client, headers=headers)
        assert response.status_code == 403
        post_message.assert_not_called()

    def test_slack_session_token_no_secret_rejected(self, app: IOCLookupApp, client: FlaskClient) -> None:
        app.config.pop("SLACK_SIGNING_SECRET", None)
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_same_origin_post(client)
        assert response.status_code == 403
        post_message.assert_not_called()

    def test_slack_api_token_does_not_bypass_signature(
        self, app: IOCLookupApp, client: FlaskClient, slack_secret: None
    ) -> None:
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = client.post(
                "/slack/ioc-lookup",
                json={"channel_id": "C123", "text": "example.com"},
                headers={"API-TOKEN": TEST_API_KEY, "Accept": "application/json"},
            )
        assert response.status_code == 403
        post_message.assert_not_called()

    def test_slack_missing_channel_id(self, app: IOCLookupApp, client: FlaskClient, slack_secret: None) -> None:
        with patch("ioc_lookup.app.slackclient.chat_postMessage") as post_message:
            response = self._slack_post(client, data={"text": "example.com"})
        assert response.status_code == 400
        post_message.assert_not_called()

    def test_session_cookie_flags(self, app: IOCLookupApp, client: FlaskClient) -> None:
        response = client.get("/report")
        cookie = response.headers.get("Set-Cookie", "")
        assert "ioc_lookup_session=" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=Lax" in cookie

    def _origin_post(self, app: IOCLookupApp, client: FlaskClient, origin: str, trusted: list[str] | None) -> Any:  # noqa: ANN401
        original = app.config.get("TRUSTED_ORIGINS")
        app.config["TRUSTED_ORIGINS"] = trusted or []
        try:
            token = prime_csrf(client)
            with patch.object(app.logger, "warning") as warning:
                response = client.post(
                    "/report", data={"csrf_token": token}, headers={"Origin": origin, "Accept": "application/json"}
                )
            self._origin_logs = " ".join(str(c.args[0]) for c in warning.call_args_list)
            return response
        finally:
            app.config["TRUSTED_ORIGINS"] = original

    def test_cross_scheme_origin(self, app: IOCLookupApp, client: FlaskClient) -> None:
        response = self._origin_post(app, client, "https://localhost", None)
        assert response.status_code == 403
        assert "Origin rejected" in self._origin_logs
        assert "scheme mismatch" in self._origin_logs
        assert "X-Forwarded-Proto" in self._origin_logs
        assert "administrator" in response.get_json()["message"]
        assert TEST_CSRF_TOKEN not in self._origin_logs

    @pytest.mark.parametrize(
        ("headers", "expected"),
        [
            ({"Referer": "http://evil.example/x"}, "Referer rejected"),
            ({"Referer": "not a url"}, "Referer rejected"),
            ({}, "no Origin or Referer"),
        ],
    )
    def test_referer_and_missing_origin_rejections_logged(
        self, app: IOCLookupApp, client: FlaskClient, headers: dict[str, str], expected: str
    ) -> None:
        token = prime_csrf(client)
        with patch.object(app.logger, "warning") as warning:
            response = client.post("/report", data={"csrf_token": token}, headers=headers, environ_base=USER_ENV)
        logs = " ".join(str(c.args[0]) for c in warning.call_args_list)
        assert response.status_code == 403
        assert expected in logs
        assert "expected one of" in logs
        assert "TRUSTED_ORIGINS" in logs
        assert token not in logs

    def test_trusted_origins_accepts_https(self, app: IOCLookupApp, client: FlaskClient) -> None:
        response = self._origin_post(app, client, "https://localhost", ["https://localhost"])
        assert response.status_code != 403

    def test_trusted_origins_rejects_http(self, app: IOCLookupApp, client: FlaskClient) -> None:
        response = self._origin_post(app, client, "http://localhost", ["https://localhost"])
        assert response.status_code == 403
        assert "scheme mismatch" in self._origin_logs

    @pytest.mark.parametrize("path", ["/", "/report"])
    def test_session_pages_not_cacheable(self, app: IOCLookupApp, client: FlaskClient, path: str) -> None:
        response = client.get(path)
        assert "no-store" in response.headers["Cache-Control"]
        assert "Cookie" in response.headers["Vary"]

    def test_existing_session_cookie_still_no_store(self, app: IOCLookupApp, client: FlaskClient) -> None:
        client.get("/report")  # receives the session cookie
        response = client.get("/report")
        assert "Set-Cookie" not in response.headers
        assert "no-store" in response.headers["Cache-Control"]
        assert "Cookie" in response.headers["Vary"]

    def test_static_not_forced_no_store(self, app: IOCLookupApp, client: FlaskClient) -> None:
        response = client.get("/static/css/bootstrap-grid.css")
        assert response.status_code == 200
        assert "no-store" not in response.headers.get("Cache-Control", "")

    def test_json_error_without_session_unaffected(self, app: IOCLookupApp, client: FlaskClient) -> None:
        response = client.get("/robots-missing.txt", headers={"Accept": "application/json"})
        assert "no-store" not in response.headers.get("Cache-Control", "")

    def test_session_cookie_secure_flag(self, app: IOCLookupApp, client: FlaskClient) -> None:
        original = app.config["SESSION_COOKIE_SECURE"]
        app.config["SESSION_COOKIE_SECURE"] = True
        try:
            response = client.get("/report")
        finally:
            app.config["SESSION_COOKIE_SECURE"] = original
        assert "Secure" in response.headers.get("Set-Cookie", "")

    def test_trusted_origins_string_and_invalid(self, app: IOCLookupApp, client: FlaskClient) -> None:
        from flask import Flask

        from ioc_lookup.csrf import init_csrf

        original = app.config.get("TRUSTED_ORIGINS")
        try:
            app.config["TRUSTED_ORIGINS"] = "http://Trusted.Example:80"
            token = prime_csrf(client, identity=USER_ENV["HTTP_REMOTE_USER"])
            response = client.post(
                "/",
                data={**CSRF_ENDPOINTS["/"], "csrf_token": token},
                headers={"Origin": "http://trusted.example"},
                environ_base=USER_ENV,
            )
            assert response.status_code == 200
        finally:
            app.config["TRUSTED_ORIGINS"] = original
        bad = Flask("bad")
        bad.config["TRUSTED_ORIGINS"] = ["not-an-origin"]
        with pytest.raises(ValueError, match="TRUSTED_ORIGINS"):
            init_csrf(bad)

    def test_rejection_log_escapes_and_truncates(self, app: IOCLookupApp, client: FlaskClient) -> None:
        with patch.object(app.logger, "warning") as warning:
            client.post("/", data={}, headers={"Origin": "http://evil.example/\x1b[31mX" + "a" * 500})
        message = warning.call_args[0][0]
        assert "\x1b" not in message
        assert "a" * 201 not in message

    def test_error_page_shows_description(self, app: IOCLookupApp, client: FlaskClient) -> None:
        prime_csrf(client)
        response = client.post("/", data={}, headers={"Origin": TEST_ORIGIN})
        assert response.status_code == 400
        assert b"missing, invalid or expired" in response.data

    def test_authenticated_client_json_uses_header_token(
        self, app: IOCLookupApp, authenticated_client: AuthenticatedClient
    ) -> None:
        response = authenticated_client.post("/", json={"search": "192.168.1.100"})
        assert response.status_code == 200

import pytest
from flask import jsonify
from flask.testing import FlaskClient

from ioc_lookup.ioc_lookup_app import IOCLookupApp
from ioc_lookup.misp_attributes import Attr, AttrType
from ioc_lookup.parse import InputError, ParseException, defanged_url, get_canonical_url, parse_items, undefang_url

from .conftest import AuthenticatedClient

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
            response = client.post("/", data={"search_query": "192.168.1.100"})
            assert response.status_code == 200

    def test_index_search_invalid_input(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test search with invalid input."""
        with app.app_context():
            response = client.post("/", data={"search_query": "not a valid ioc!@#$"})
            assert response.status_code == 200
            # Should show error message
            assert b"Invalid input" in response.data

    def test_index_search_with_related_results(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test search with related results enabled."""
        with app.app_context():
            response = client.post(
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
                headers={"Accept": "application/json"},
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
                headers={"Accept": "application/json"},
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
            response = client.post(
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
            response = client.post(
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
            response = client.post(
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
            response = client.post(
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
            response = client.post(
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
                headers={"Accept": "application/json"},
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
                headers={"Accept": "application/json"},
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
                headers={"Accept": "application/json"},
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
                headers={"Accept": "application/json"},
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
            response = client.post(
                "/report-sighting",
                data={"search_query": "malicious.example.com", "type": "0"},
            )
            assert response.status_code == 401

    def test_report_sighting_disabled(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report-sighting when sightings are disabled."""
        app.config["SIGHTINGS_ENABLED"] = False
        with app.app_context():
            response = client.post(
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
            response = client.post(
                "/report-sighting",
                data={},
                environ_base={"HTTP_REMOTE_USER": "user@test.org"},
            )
            assert response.status_code == 400

    def test_remove_sighting_requires_trusted_org(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test remove-sighting requires user from trusted org."""
        with app.app_context():
            response = client.post(
                "/remove-sighting",
                data={"search_query": "malicious.example.com", "type": "0"},
            )
            assert response.status_code == 401

    def test_remove_sighting_disabled(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test remove-sighting when sightings are disabled."""
        app.config["SIGHTINGS_ENABLED"] = False
        with app.app_context():
            response = client.post(
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
            response = client.post("/", data={"search_query": "example[.]com"})
            assert response.status_code == 200

    def test_search_defanged_url(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test search with defanged URL."""
        with app.app_context():
            response = client.post("/", data={"search_query": "hxxps[://]example[.]com/path"})
            assert response.status_code == 200

    def test_search_defanged_ip(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test search with defanged IP."""
        with app.app_context():
            response = client.post("/", data={"search_query": "192[.]168[.]1[.]100"})
            assert response.status_code == 200

    def test_report_defanged_domain(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test report with defanged domain."""
        with app.app_context():
            response = client.post(
                "/report",
                data={
                    "ioc": "evil[.]example[.]com",
                    "tlp": "tlp:green",
                    "info": "Defanged domain report",
                },
            )
            assert response.status_code == 200

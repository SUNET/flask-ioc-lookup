"""
Integration tests for the IOC Lookup webapp using mock MISP API.

These tests verify the Flask routes and integration with MISP.
"""

from typing import Any

from flask.testing import FlaskClient

from ioc_lookup.ioc_lookup_app import IOCLookupApp
from ioc_lookup.misp_api import TLP

from .conftest import MockMISPApi, MockPyMISP

__author__ = "lundberg"


class TestMockMISPApi:
    """Tests for the MockMISPApi implementation."""

    def test_mock_search_all_attributes(self, mock_misp_api: MockMISPApi) -> None:
        """Test searching returns all attributes when no filter."""
        result = mock_misp_api.search()
        assert isinstance(result, dict)
        assert "Attribute" in result
        assert len(result["Attribute"]) == 4

    def test_mock_search_by_type(self, mock_misp_api: MockMISPApi) -> None:
        """Test searching by attribute type."""
        result = mock_misp_api.search(type_attribute=["domain"])
        assert isinstance(result, dict)
        assert len(result["Attribute"]) == 1
        assert result["Attribute"][0]["type"] == "domain"

    def test_mock_search_by_value(self, mock_misp_api: MockMISPApi) -> None:
        """Test searching by exact value."""
        result = mock_misp_api.search(value="192.168.1.100")
        assert isinstance(result, dict)
        assert len(result["Attribute"]) == 1
        assert result["Attribute"][0]["value"] == "192.168.1.100"

    def test_mock_searchall(self, mock_misp_api: MockMISPApi) -> None:
        """Test searchall with partial matching."""
        result = mock_misp_api.searchall(value="example.com")
        # Should match "malicious.example.com" and "https://phishing.example.com/login"
        assert len(result) == 2
        assert all("example.com" in r["value"] for r in result)

    def test_mock_attr_search(self, mock_misp_api: MockMISPApi) -> None:
        """Test attr_search method."""
        from ioc_lookup.misp_attributes import Attr, AttrType

        attr = Attr(
            value="malicious.example.com",
            type=AttrType.DOMAIN,
            search_types=[AttrType.DOMAIN, AttrType.HOSTNAME],
        )
        result = mock_misp_api.attr_search(attr)
        assert len(result) == 1
        assert result[0]["value"] == "malicious.example.com"

    def test_mock_sighting_lookup(self, mock_misp_api: MockMISPApi) -> None:
        """Test sighting_lookup method."""
        result = mock_misp_api.sighting_lookup(attribute_id="1")
        assert len(result) == 2

    def test_mock_sighting_lookup_with_source(self, mock_misp_api: MockMISPApi) -> None:
        """Test sighting_lookup with source filter."""
        result = mock_misp_api.sighting_lookup(attribute_id="1", source="flask-ioc-lookup_test.org")
        assert len(result) == 1
        assert result[0]["source"] == "flask-ioc-lookup_test.org"

    def test_mock_add_sighting(self, mock_misp_api: MockMISPApi) -> None:
        """Test adding a sighting."""
        from ioc_lookup.misp_attributes import Attr, AttrType

        attr = Attr(value="test.com", type=AttrType.DOMAIN)
        result = mock_misp_api.add_sighting(attr=attr, sighting_type="0", source="flask-ioc-lookup_new.org")
        assert result is not None

    def test_mock_domain_name_search(self, mock_misp_api: MockMISPApi) -> None:
        """Test domain_name_search method."""
        result = mock_misp_api.domain_name_search("example.com", searchall=True)
        assert len(result) == 1

    def test_mock_url_search(self, mock_misp_api: MockMISPApi) -> None:
        """Test url_search method."""
        result = mock_misp_api.url_search("https://phishing.example.com/login")
        assert len(result) == 1


class TestAppFixtures:
    """Tests to verify the app fixtures work correctly."""

    def test_app_fixture_creates_app(self, app: IOCLookupApp) -> None:
        """Test that app fixture creates a valid Flask app."""
        assert app is not None
        assert app.config["TESTING"] is True
        assert app.misp_apis is not None

    def test_app_has_mock_misp_apis(self, app: IOCLookupApp) -> None:
        """Test that app has mock MISP APIs configured."""
        assert app.misp_apis is not None
        assert "default" in app.misp_apis
        assert "proxy" in app.misp_apis
        assert "test.org" in app.misp_apis

    def test_app_has_trusted_users(self, app: IOCLookupApp) -> None:
        """Test that app has trusted users configured."""
        assert "trusted@test.org" in app.trusted_users

    def test_app_has_trusted_orgs(self, app: IOCLookupApp) -> None:
        """Test that app has trusted orgs configured."""
        assert "test.org" in app.trusted_orgs

    def test_client_fixture_works(self, app: IOCLookupApp, client: FlaskClient) -> None:
        """Test that client fixture provides a test client."""
        assert client is not None


class TestSampleDataFixtures:
    """Tests for sample data fixtures."""

    def test_sample_domain_attribute(self, sample_domain_attribute: dict[str, Any]) -> None:
        """Test sample domain attribute fixture."""
        assert sample_domain_attribute["type"] == "domain"
        assert sample_domain_attribute["value"] == "malicious.example.com"

    def test_sample_ip_attribute(self, sample_ip_attribute: dict[str, Any]) -> None:
        """Test sample IP attribute fixture."""
        assert sample_ip_attribute["type"] == "ip-src"
        assert sample_ip_attribute["value"] == "192.168.1.100"

    def test_sample_md5_attribute(self, sample_md5_attribute: dict[str, Any]) -> None:
        """Test sample MD5 attribute fixture."""
        assert sample_md5_attribute["type"] == "md5"
        assert len(sample_md5_attribute["value"]) == 32

    def test_sample_url_attribute(self, sample_url_attribute: dict[str, Any]) -> None:
        """Test sample URL attribute fixture."""
        assert sample_url_attribute["type"] == "url"
        assert sample_url_attribute["value"].startswith("https://")

    def test_sample_sighting(self, sample_sighting: dict[str, Any]) -> None:
        """Test sample sighting fixture."""
        assert sample_sighting["type"] == "0"  # Positive sighting
        assert "source" in sample_sighting


class TestMISPApiMethods:
    """Test various MISPApi methods with mock."""

    def test_tlp_to_distribution(self, mock_misp_api: MockMISPApi) -> None:
        """Test TLP to distribution mapping."""
        assert mock_misp_api.tlp_to_distribution(TLP.AMBER_STRICT) == 0
        assert mock_misp_api.tlp_to_distribution(TLP.AMBER) == 1
        assert mock_misp_api.tlp_to_distribution(TLP.GREEN) == 2
        assert mock_misp_api.tlp_to_distribution(TLP.CLEAR) == 3

    def test_add_event(self, mock_misp_api: MockMISPApi) -> None:
        """Test adding an event."""
        from ioc_lookup.misp_attributes import Attr, AttrType

        attr = Attr(
            value="evil.example.com",
            type=AttrType.DOMAIN,
            report_types=[AttrType.DOMAIN],
        )

        result = mock_misp_api.add_event(
            attr_items=[attr],
            info="Test Event",
            tags=[TLP.GREEN.value],
            comment="Test comment",
            to_ids=True,
            distribution=2,
            reference="test-ref",
        )

        assert result is not None


class TestMockRemoveSighting:
    """Tests for remove_sighting functionality."""

    def test_remove_sighting(self, mock_misp_api: MockMISPApi) -> None:
        """Test removing a sighting."""
        from ioc_lookup.misp_attributes import Attr, AttrType

        # First verify the sighting exists
        initial_sightings = mock_misp_api.sighting_lookup(attribute_id="1", source="flask-ioc-lookup_test.org")
        assert len(initial_sightings) == 1

        # Remove the sighting
        attr = Attr(
            value="malicious.example.com",
            type=AttrType.DOMAIN,
            search_types=[AttrType.DOMAIN],
        )
        mock_misp_api.remove_sighting(
            attr=attr,
            sighting_type="0",
            source="flask-ioc-lookup_test.org",
        )

        # Verify it's gone
        remaining_sightings = mock_misp_api.sighting_lookup(attribute_id="1", source="flask-ioc-lookup_test.org")
        assert len(remaining_sightings) == 0


class TestMockErrorSimulation:
    """Tests for error simulation capability."""

    def test_search_error_simulation(self, mock_misp_api: MockMISPApi) -> None:
        """Test that simulated errors are returned from search."""
        import pytest

        from ioc_lookup.misp_api import RequestException

        # Configure error
        mock_misp_api.pymisp.simulate_error(403, "Permission denied")  # type: ignore[union-attr]

        # Search should raise RequestException due to error handling in MISPApi
        with pytest.raises(RequestException, match="Permission denied"):
            mock_misp_api.search()

    def test_error_clears_after_single_use(self, mock_misp_api: MockMISPApi) -> None:
        """Test that error simulation clears after being triggered."""
        # Configure error
        mock_misp_api.pymisp.simulate_error(500, "Server error")  # type: ignore[union-attr]

        # First call should get the error (but MISPApi will raise, so we catch it)
        try:
            mock_misp_api.search()
        except Exception:
            pass

        # Second call should succeed
        result = mock_misp_api.search()
        assert isinstance(result, dict)
        assert "Attribute" in result

    def test_clear_error_manually(self, mock_misp_api: MockMISPApi) -> None:
        """Test manual error clearing."""
        # Configure error
        mock_misp_api.pymisp.simulate_error(403, "Permission denied")  # type: ignore[union-attr]

        # Clear it manually
        mock_misp_api.pymisp.clear_error()  # type: ignore[union-attr]

        # Search should succeed
        result = mock_misp_api.search()
        assert isinstance(result, dict)
        assert "Attribute" in result

    def test_add_sighting_error_simulation(self, mock_misp_api: MockMISPApi) -> None:
        """Test error simulation for add_sighting."""
        from ioc_lookup.misp_attributes import Attr, AttrType

        # Configure error
        mock_misp_api.pymisp.simulate_error(405, "Method not allowed")  # type: ignore[union-attr]

        attr = Attr(value="test.com", type=AttrType.DOMAIN)

        # add_sighting returns the result directly without error handling
        result = mock_misp_api.pymisp.add_sighting(  # type: ignore[union-attr]
            type(mock_misp_api.pymisp)("", "", True),  # type: ignore[arg-type]
            pythonify=False,
        )
        # The error was consumed, so we need to set it again for proper test
        mock_misp_api.pymisp.simulate_error(405, "Method not allowed")  # type: ignore[union-attr]

        # Direct call to mock should return error dict
        from pymisp.mispevent import MISPSighting

        sighting = MISPSighting()
        sighting["value"] = attr.value
        sighting["type"] = "0"
        sighting["source"] = "test"
        result = mock_misp_api.pymisp.add_sighting(sighting, pythonify=False)  # type: ignore[union-attr]
        assert isinstance(result, dict)
        assert "errors" in result


class TestMockDynamicAttributes:
    """Tests for dynamic attribute handling (verifies bug fix)."""

    def test_search_uses_instance_attributes(self, mock_pymisp: MockPyMISP) -> None:
        """Test that search uses instance _attributes, not global SAMPLE_ATTRIBUTES."""
        # Add a new attribute dynamically
        new_attr = {
            "id": "999",
            "event_id": "999",
            "type": "domain",
            "category": "Network activity",
            "value": "dynamic.test.com",
            "to_ids": True,
            "comment": "Dynamically added",
            "timestamp": "1704067200",
        }
        mock_pymisp._attributes["dynamic.test.com"] = new_attr

        # Search should find the dynamically added attribute
        result = mock_pymisp.search(value="dynamic.test.com")
        assert isinstance(result, dict)
        assert len(result["Attribute"]) == 1
        assert result["Attribute"][0]["value"] == "dynamic.test.com"

    def test_reset_restores_attributes(self, mock_misp_api: MockMISPApi) -> None:
        """Test that reset() restores _attributes to initial state."""
        # Add a dynamic attribute
        mock_misp_api.pymisp._attributes["temp.example.com"] = {  # type: ignore[union-attr]
            "id": "888",
            "event_id": "888",
            "type": "domain",
            "category": "Network activity",
            "value": "temp.example.com",
            "to_ids": True,
            "comment": "Temporary",
            "timestamp": "1704067200",
        }

        # Verify it was added
        result = mock_misp_api.search(value="temp.example.com")
        assert isinstance(result, dict)
        assert len(result["Attribute"]) == 1

        # Reset
        mock_misp_api.reset()

        # Verify it's gone
        result = mock_misp_api.search(value="temp.example.com")
        assert isinstance(result, dict)
        assert len(result["Attribute"]) == 0

    def test_reset_restores_sightings(self, mock_misp_api: MockMISPApi) -> None:
        """Test that reset() restores _sightings to initial state."""
        from ioc_lookup.misp_attributes import Attr, AttrType

        # Remove a sighting
        attr = Attr(
            value="malicious.example.com",
            type=AttrType.DOMAIN,
            search_types=[AttrType.DOMAIN],
        )
        mock_misp_api.remove_sighting(
            attr=attr,
            sighting_type="0",
            source="flask-ioc-lookup_test.org",
        )

        # Verify it's removed
        sightings = mock_misp_api.sighting_lookup(attribute_id="1", source="flask-ioc-lookup_test.org")
        assert len(sightings) == 0

        # Reset
        mock_misp_api.reset()

        # Verify it's restored
        sightings = mock_misp_api.sighting_lookup(attribute_id="1", source="flask-ioc-lookup_test.org")
        assert len(sightings) == 1

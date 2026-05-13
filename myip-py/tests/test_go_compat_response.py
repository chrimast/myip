from fastapi.testclient import TestClient

from app.api.ip import clear_ip_lookup_cache
from app.main import app
from app.services.ip_lookup import IPInfo, StaticIPLookupProvider, get_ip_lookup_provider


def setup_function() -> None:
    app.dependency_overrides.clear()
    clear_ip_lookup_cache()


def test_lookup_response_exposes_frontend_display_fields_for_original_homepage():
    app.dependency_overrides[get_ip_lookup_provider] = lambda: StaticIPLookupProvider(
        IPInfo(
            ip="8.8.8.8",
            country="United States",
            country_code="US",
            region="California",
            city="Mountain View",
            asn="AS15169",
            isp="Google LLC",
            latitude=37.4056,
            longitude=-122.0775,
            provider="test-provider",
            network_type="business",
        )
    )
    try:
        client = TestClient(app)

        response = client.get("/api/ip?8.8.8.8")

        assert response.status_code == 200
        body = response.json()
        assert body["asn_owner"] == "Google LLC"
        assert body["org_domain"] == ""
        assert body["asn_domain"] == ""
        assert body["registry"] == ""
        assert body["reg_region"] == "US"
        assert body["ip_source"] == "原生IP"
        assert body["ip_source_reason"] == ""
        assert body["ip_property"] == "商业IP"
        assert body["ip_property_reason"]
        assert body["ip_property_scores"] == {"机房IP": 0, "家庭IP": 0, "商业IP": 36}
        assert body["risk_reason"]
        assert body["risk_confidence"] == 0.7
        assert body["humanbot_reason"]
        assert body["humanbot_confidence"] == 0.7

    finally:
        app.dependency_overrides.clear()


def test_lookup_response_exposes_go_compatible_legacy_field_aliases():
    app.dependency_overrides[get_ip_lookup_provider] = lambda: StaticIPLookupProvider(
        IPInfo(
            ip="8.8.8.8",
            country="United States",
            country_code="US",
            region="California",
            city="Mountain View",
            asn="AS15169",
            isp="Google LLC",
            latitude=37.4056,
            longitude=-122.0775,
            provider="test-provider",
        )
    )
    try:
        client = TestClient(app)

        response = client.get("/api/ip?8.8.8.8")

        assert response.status_code == 200
        body = response.json()
        assert body["query"] == "8.8.8.8"
        assert body["countryCode"] == "US"
        assert body["regionName"] == "California"
        assert body["lat"] == 37.4056
        assert body["lon"] == -122.0775
        assert body["org"] == "Google LLC"
        assert body["as"] == "AS15169 Google LLC"
        assert body["proxy"] is False
        assert body["hosting"] is False
        assert body["mobile"] is False
        assert body["status"] == "success"
    finally:
        app.dependency_overrides.clear()

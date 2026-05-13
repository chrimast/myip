from fastapi.testclient import TestClient

from app.api.ip import clear_ip_lookup_cache
from app.main import app
from app.services.ip_lookup import IPInfo, StaticIPLookupProvider, get_ip_lookup_provider


def setup_function() -> None:
    app.dependency_overrides.clear()
    clear_ip_lookup_cache()


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

        response = client.get("/api/ip?=8.8.8.8")

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

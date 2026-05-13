from fastapi.testclient import TestClient

from app.api.ip import clear_ip_lookup_cache
from app.main import app
from app.services.ip_lookup import IPInfo, get_ip_lookup_provider


def setup_function() -> None:
    app.dependency_overrides.clear()
    clear_ip_lookup_cache()


class StaticProvider:
    def __init__(self, result: IPInfo) -> None:
        self.result = result

    def lookup(self, ip: str) -> IPInfo:
        return self.result.model_copy(update={"ip": ip})


def test_lookup_response_exposes_intelligence_fields_for_proxy_datacenter():
    app.dependency_overrides[get_ip_lookup_provider] = lambda: StaticProvider(
        IPInfo(
            ip="8.8.8.8",
            isp="Example Cloud Hosting LLC",
            provider="test-provider",
            is_proxy=True,
            is_hosting=True,
        )
    )
    try:
        client = TestClient(app)

        response = client.get("/api/ip?=8.8.8.8")

        assert response.status_code == 200
        body = response.json()
        assert body["ip_property"] == "机房IP"
        assert body["is_proxy"] is True
        assert body["is_vpn"] is False
        assert body["is_tor"] is False
        assert body["is_mobile"] is False
        assert body["is_hosting"] is True
        assert body["risk_score"] >= 50
        assert body["human_percent"] + body["bot_percent"] == 100
        assert body["bot_percent"] > body["human_percent"]
    finally:
        app.dependency_overrides.clear()

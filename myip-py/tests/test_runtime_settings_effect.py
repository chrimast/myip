from fastapi.testclient import TestClient

from app.api.ip import clear_ip_lookup_cache, get_public_ip_lookup_provider
from app.main import app
from app.services.ip_lookup import IPInfo


class CountingProvider:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def lookup(self, ip: str) -> IPInfo:
        self.calls.append(ip)
        return IPInfo(
            ip=ip,
            country="United States",
            country_code="US",
            asn="AS64500",
            isp="Example ISP",
            provider="test-provider",
        )


def setup_function() -> None:
    app.dependency_overrides.clear()
    clear_ip_lookup_cache()


def teardown_function() -> None:
    app.dependency_overrides.clear()
    clear_ip_lookup_cache()


def test_runtime_ip_cache_can_share_ipv4_24_entries(tmp_path, monkeypatch):
    from app.services import admin_config

    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr(admin_config, "PROVIDER_CONFIG_PATH", config_path)
    provider = CountingProvider()
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: provider
    client = TestClient(app)

    response = client.put(
        "/api/admin/runtime-settings",
        json={"cache": {"ip_enabled": True, "ip_ttl_seconds": 120, "ip_cache_granularity": "ipv4_24"}},
    )
    assert response.status_code == 200

    first = client.get("/api/ip?203.0.113.1")
    second = client.get("/api/ip?203.0.113.55")

    assert first.status_code == 200
    assert second.status_code == 200
    assert provider.calls == ["203.0.113.1"]
    assert second.json()["ip"] == "203.0.113.55"
    assert second.json()["query"] == "203.0.113.55"
    assert second.json()["resolved_ip"] == "203.0.113.55"


def test_runtime_ip_cache_can_be_disabled(tmp_path, monkeypatch):
    from app.services import admin_config

    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr(admin_config, "PROVIDER_CONFIG_PATH", config_path)
    provider = CountingProvider()
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: provider
    client = TestClient(app)

    response = client.put(
        "/api/admin/runtime-settings",
        json={"cache": {"ip_enabled": False, "ip_ttl_seconds": 120, "ip_cache_granularity": "ipv4_24"}},
    )
    assert response.status_code == 200

    client.get("/api/ip?203.0.113.1")
    client.get("/api/ip?203.0.113.55")

    assert provider.calls == ["203.0.113.1", "203.0.113.55"]


def test_runtime_ip_rate_limit_can_be_disabled(tmp_path, monkeypatch):
    from app.services import admin_config

    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr(admin_config, "PROVIDER_CONFIG_PATH", config_path)
    provider = CountingProvider()
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: provider
    client = TestClient(app)

    response = client.put(
        "/api/admin/runtime-settings",
        json={"rate_limit": {"ip_enabled": False, "ip_per_minute": 1}},
    )
    assert response.status_code == 200

    first = client.get("/api/ip?203.0.113.1")
    second = client.get("/api/ip?203.0.113.2")

    assert first.status_code == 200
    assert second.status_code == 200

from fastapi.testclient import TestClient

from app.api.ip import clear_ip_lookup_cache, get_public_ip_lookup_provider
from app.main import app
from app.core.config import get_settings
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


class AdminAuthSettings:
    ipapi_is_key = ""
    ipapi_org_key = ""
    ipinfo_token = ""
    ipdata_key = ""
    myip_debug = False
    myip_cache_ttl_seconds = 120
    myip_rate_limit_per_minute = 60
    myip_provider_timeout_seconds = 8.0
    myip_doh_timeout_seconds = 5.0
    myip_doh_providers = "cloudflare,google,quad9"
    myip_admin_username = "admin"
    myip_admin_password = "safe-admin-password"
    myip_admin_session_secret = "test-session-secret-minimum-length"

    def key_status(self):
        return {
            "ipapi_is_key": {"configured": False, "source": "missing"},
            "ipapi_org_key": {"configured": False, "source": "missing"},
            "ipinfo_token": {"configured": False, "source": "missing"},
            "ipdata_key": {"configured": False, "source": "missing"},
        }

    def public_config(self):
        return {}

    def doh_provider_names(self):
        return ["cloudflare", "google", "quad9"]


def admin_client() -> TestClient:
    app.dependency_overrides[get_settings] = lambda: AdminAuthSettings()
    client = TestClient(app)
    assert client.post("/admin/login", data={"username": "admin", "password": "safe-admin-password"}, follow_redirects=False).status_code == 303
    return client


def test_runtime_ip_cache_can_share_ipv4_24_entries(tmp_path, monkeypatch):
    from app.services import admin_config

    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr(admin_config, "PROVIDER_CONFIG_PATH", config_path)
    provider = CountingProvider()
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: provider
    client = admin_client()

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
    client = admin_client()

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
    client = admin_client()

    response = client.put(
        "/api/admin/runtime-settings",
        json={"rate_limit": {"ip_enabled": False, "ip_per_minute": 1}},
    )
    assert response.status_code == 200

    first = client.get("/api/ip?203.0.113.1")
    second = client.get("/api/ip?203.0.113.2")

    assert first.status_code == 200
    assert second.status_code == 200

from fastapi.testclient import TestClient

from app.main import app
from app.api.admin import admin_ip_lookup_provider
from app.services.ip_lookup import IPInfo, IPLookupUnavailable, StaticIPLookupProvider


def test_admin_page_serves_provider_management_shell():
    client = TestClient(app)

    response = client.get("/admin")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert "Provider 管理" in body
    assert "字段管理" in body
    assert "/api/admin/settings" in body
    assert "/api/admin/providers" in body
    assert "/api/admin/fields" in body
    assert "查询调试" in body
    assert "/api/admin/lookup" in body
    assert "Provider 配置" in body
    assert "/api/admin/provider-config" in body


def test_admin_settings_api_exposes_safe_runtime_config_without_secret_values():
    client = TestClient(app)

    response = client.get("/api/admin/settings")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"keys", "config"}
    assert set(body["keys"]) == {"ipapi_is_key", "ipapi_org_key", "ipinfo_token", "ipdata_key"}
    assert body["keys"]["ipapi_is_key"]["source"] in {"env", "missing"}
    assert "value" not in body["keys"]["ipapi_is_key"]
    assert body["config"]["cache_ttl_seconds"] == 120
    assert body["config"]["rate_limit_per_minute"] == 60
    assert body["config"]["provider_timeout_seconds"] == 8.0
    assert body["config"]["doh_providers"] == ["cloudflare", "google", "quad9"]


def test_admin_providers_api_describes_provider_order_keys_and_fields():
    client = TestClient(app)

    response = client.get("/api/admin/providers")

    assert response.status_code == 200
    providers = response.json()
    provider_ids = [provider["id"] for provider in providers]
    assert provider_ids == [
        "ipapi.is",
        "ipwho.is",
        "ip-api.com",
        "ipapi.org",
        "ipinfo.io",
        "ipdata.co",
    ]
    ipapi_is = providers[0]
    assert ipapi_is["role"] == "primary"
    assert ipapi_is["enabled"] is True
    assert ipapi_is["key_name"] == "ipapi_is_key"
    assert "network_type" in ipapi_is["provides"]
    assert "is_abuser" in ipapi_is["provides"]
    ip_api = next(provider for provider in providers if provider["id"] == "ip-api.com")
    assert ip_api["key_name"] is None
    assert ip_api["requires_key"] is False
    assert "network_type" not in ip_api["provides"]
    assert "is_hosting" in ip_api["provides"]


def test_admin_providers_api_includes_effective_provider_config(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.put(
        "/api/admin/provider-config",
        json={"providers": [{"id": "ipwho.is", "enabled": False, "order": 1, "timeout_seconds": 2.5}]},
    )

    response = client.get("/api/admin/providers")

    assert response.status_code == 200
    ipwho = next(provider for provider in response.json() if provider["id"] == "ipwho.is")
    assert ipwho["enabled"] is False
    assert ipwho["order"] == 1
    assert ipwho["timeout_seconds"] == 2.5
    assert ipwho["config_source"] == "json"


def test_admin_fields_api_marks_scoring_and_display_only_fields():
    client = TestClient(app)

    response = client.get("/api/admin/fields")

    assert response.status_code == 200
    fields = {field["field"]: field for field in response.json()}
    assert fields["network_type"]["scoring"] is True
    assert fields["network_type"]["source_type"] == "provider_structured"
    assert fields["network_type"]["providers"]["ipapi.is"] == ["company.type", "asn.type"]
    assert fields["network_type"]["providers"]["ipwho.is"] == [
        "connection.type",
        "connection.connection_type",
    ]
    assert fields["isp"]["scoring"] is False
    assert fields["isp"]["source_type"] == "identity_text"
    assert fields["isp"]["used_for"] == ["display", "compatibility"]
    assert fields["is_hosting"]["scoring"] is True


def test_admin_lookup_api_returns_enriched_result_and_field_sources():
    def fake_provider(_provider_id: str, _timeout_seconds: float | None) -> StaticIPLookupProvider:
        return StaticIPLookupProvider(
            IPInfo(
                ip="8.8.8.8",
                country="United States",
                country_code="US",
                city="Mountain View",
                asn="AS15169",
                asn_owner="Google LLC",
                isp="Google LLC",
                provider="test-provider",
                network_type="hosting",
                reg_region="US",
                is_hosting=True,
                field_sources={
                    "ip": "test-provider",
                    "network_type": "test-provider",
                    "is_hosting": "test-provider",
                    "reg_region": "test-registry",
                },
            )
        )

    app.dependency_overrides[admin_ip_lookup_provider] = lambda: fake_provider
    client = TestClient(app)

    try:
        response = client.get("/api/admin/lookup", params={"target": "8.8.8.8"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["input"] == "8.8.8.8"
    assert body["resolved_ip"] == "8.8.8.8"
    assert body["result"]["ip"] == "8.8.8.8"
    assert body["result"]["ip_property"] == "机房IP"
    assert body["result"]["ip_source"] == "原生IP"
    assert body["field_sources"]["network_type"] == "test-provider"
    assert body["field_sources"]["is_hosting"] == "test-provider"
    assert body["debug"]["network_category"] == "hosting"
    assert body["debug"]["risk_breakdown"]["hosting"] == 20
    assert body["debug"]["provider"] == "test-provider"
    assert body["debug"]["disabled_fields"] == []


def test_admin_lookup_applies_disabled_field_overrides(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.put(
        "/api/admin/provider-config",
        json={
            "providers": [{"id": "ipapi.is", "enabled": True, "order": 1}],
            "field_overrides": {
                "network_type": {"enabled": False},
                "is_hosting": {"enabled": False},
                "asn_owner": {"enabled": False},
            },
        },
    )

    def fake_provider(_provider_id: str, _timeout_seconds: float | None) -> StaticIPLookupProvider:
        return StaticIPLookupProvider(
            IPInfo(
                ip="8.8.8.8",
                provider="test-provider",
                network_type="hosting",
                asn_owner="Google LLC",
                is_hosting=True,
                field_sources={
                    "network_type": "test-provider",
                    "is_hosting": "test-provider",
                    "asn_owner": "test-provider",
                },
            )
        )

    app.dependency_overrides[admin_ip_lookup_provider] = lambda: fake_provider
    try:
        response = client.get("/api/admin/lookup", params={"target": "8.8.8.8"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["result"]["network_type"] is None
    assert body["result"]["asn_owner"] is None
    assert body["result"]["is_hosting"] is False
    assert "network_type" not in body["field_sources"]
    assert "is_hosting" not in body["field_sources"]
    assert "asn_owner" not in body["field_sources"]
    assert body["debug"]["disabled_fields"] == ["asn_owner", "is_hosting", "network_type"]
    assert body["debug"]["network_category"] == "unknown"


def test_admin_lookup_keeps_enabled_field_overrides(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.put(
        "/api/admin/provider-config",
        json={"field_overrides": {"network_type": {"enabled": True}, "is_hosting": {"enabled": True}}},
    )

    def fake_provider(_provider_id: str, _timeout_seconds: float | None) -> StaticIPLookupProvider:
        return StaticIPLookupProvider(
            IPInfo(
                ip="8.8.8.8",
                provider="test-provider",
                network_type="hosting",
                is_hosting=True,
                field_sources={"network_type": "test-provider", "is_hosting": "test-provider"},
            )
        )

    app.dependency_overrides[admin_ip_lookup_provider] = lambda: fake_provider
    try:
        response = client.get("/api/admin/lookup", params={"target": "8.8.8.8"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["result"]["network_type"] == "hosting"
    assert body["result"]["is_hosting"] is True
    assert body["field_sources"]["network_type"] == "test-provider"
    assert body["debug"]["disabled_fields"] == []


def test_admin_lookup_api_rejects_invalid_target():
    client = TestClient(app)

    response = client.get("/api/admin/lookup", params={"target": "=bad"})

    assert response.status_code == 422


def test_admin_lookup_uses_enabled_provider_order_from_config(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.put(
        "/api/admin/provider-config",
        json={
            "providers": [
                {"id": "ipapi.is", "enabled": False, "order": 1},
                {"id": "ipwho.is", "enabled": True, "order": 2},
                {"id": "ip-api.com", "enabled": True, "order": 1, "timeout_seconds": 1.5},
            ]
        },
    )
    calls: list[str] = []

    def fake_provider_factory(provider_id: str, timeout_seconds: float | None):
        calls.append(f"{provider_id}:{timeout_seconds}")
        if provider_id == "ip-api.com":
            return StaticIPLookupProvider(IPInfo(ip="8.8.8.8", provider="ip-api.com", network_type="business"))
        raise AssertionError(f"unexpected provider {provider_id}")

    app.dependency_overrides[admin_ip_lookup_provider] = lambda: fake_provider_factory
    try:
        response = client.get("/api/admin/lookup", params={"target": "8.8.8.8"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["debug"]["provider_config"][0]["id"] == "ip-api.com"
    assert body["debug"]["provider_config"][0]["timeout_seconds"] == 1.5
    assert body["debug"]["provider_config"][1]["id"] == "ipwho.is"
    assert body["debug"]["provider_attempts"] == [
        {"provider": "ip-api.com", "status": "ok", "timeout_seconds": 1.5}
    ]
    assert calls == ["ip-api.com:1.5"]
    assert body["result"]["provider"] == "ip-api.com"


def test_admin_lookup_falls_back_to_next_enabled_provider(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.put(
        "/api/admin/provider-config",
        json={
            "providers": [
                {"id": "ipapi.is", "enabled": False, "order": 99},
                {"id": "ip-api.com", "enabled": False, "order": 99},
                {"id": "ipapi.org", "enabled": False, "order": 99},
                {"id": "ipinfo.io", "enabled": False, "order": 99},
                {"id": "ipwho.is", "enabled": True, "order": 1},
                {"id": "ipdata.co", "enabled": True, "order": 2},
            ]
        },
    )
    calls: list[str] = []

    def fake_provider_factory(provider_id: str, timeout_seconds: float | None):
        calls.append(provider_id)
        if provider_id == "ipwho.is":
            raise IPLookupUnavailable("first provider failed")
        return StaticIPLookupProvider(IPInfo(ip="8.8.8.8", provider=provider_id, is_hosting=True))

    app.dependency_overrides[admin_ip_lookup_provider] = lambda: fake_provider_factory
    try:
        response = client.get("/api/admin/lookup", params={"target": "8.8.8.8"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert calls == ["ipwho.is", "ipdata.co"]
    assert body["debug"]["provider_attempts"] == [
        {"provider": "ipwho.is", "status": "error", "timeout_seconds": None, "error": "first provider failed"},
        {"provider": "ipdata.co", "status": "ok", "timeout_seconds": None},
    ]
    assert body["result"]["provider"] == "ipdata.co"


def test_admin_lookup_returns_502_when_all_enabled_providers_fail(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.put("/api/admin/provider-config", json={"providers": [{"id": "ipapi.is", "enabled": True, "order": 1}]})

    def fake_provider_factory(provider_id: str, timeout_seconds: float | None):
        raise IPLookupUnavailable("provider down")

    app.dependency_overrides[admin_ip_lookup_provider] = lambda: fake_provider_factory
    try:
        response = client.get("/api/admin/lookup", params={"target": "8.8.8.8"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 502


def test_admin_provider_config_api_reads_defaults_without_creating_file(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)

    response = client.get("/api/admin/provider-config")

    assert response.status_code == 200
    body = response.json()
    assert body["version"] == 1
    assert body["storage_path"] == str(config_path)
    assert body["exists"] is False
    assert [provider["id"] for provider in body["providers"]][:2] == ["ipapi.is", "ipwho.is"]
    assert body["providers"][0]["enabled"] is True
    assert body["providers"][0]["order"] == 1
    assert body["providers"][0]["timeout_seconds"] is None
    assert body["field_overrides"] == {}
    assert not config_path.exists()


def test_admin_provider_config_api_persists_safe_overrides(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    payload = {
        "providers": [
            {"id": "ipapi.is", "enabled": True, "order": 2, "timeout_seconds": 3.5},
            {"id": "ipwho.is", "enabled": False, "order": 1, "timeout_seconds": None},
        ],
        "field_overrides": {
            "network_type": {"enabled": True},
            "is_crawler": {"enabled": False},
        },
    }

    response = client.put("/api/admin/provider-config", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert config_path.exists()
    ipwho = next(provider for provider in body["providers"] if provider["id"] == "ipwho.is")
    ipapi = next(provider for provider in body["providers"] if provider["id"] == "ipapi.is")
    assert ipwho["enabled"] is False
    assert ipwho["order"] == 1
    assert ipapi["order"] == 2
    assert ipapi["timeout_seconds"] == 3.5
    assert body["field_overrides"]["is_crawler"]["enabled"] is False
    assert "key" not in config_path.read_text(encoding="utf-8").lower()


def test_admin_provider_config_api_rejects_unknown_provider(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", tmp_path / "provider-config.json")
    client = TestClient(app)

    response = client.put(
        "/api/admin/provider-config",
        json={"providers": [{"id": "unknown", "enabled": True, "order": 1}]},
    )

    assert response.status_code == 422


def test_admin_provider_config_reset_removes_saved_file(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    config_path.write_text('{"version": 1, "providers": []}', encoding="utf-8")
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)

    response = client.post("/api/admin/provider-config/reset")

    assert response.status_code == 200
    body = response.json()
    assert body["exists"] is False
    assert not config_path.exists()

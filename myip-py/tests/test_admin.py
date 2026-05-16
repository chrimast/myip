from fastapi.testclient import TestClient

from app.main import app
from app.api.admin import admin_ip_lookup_provider
from app.services.ip_lookup import IPInfo, StaticIPLookupProvider


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
    def fake_provider() -> StaticIPLookupProvider:
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

    app.dependency_overrides[admin_ip_lookup_provider] = fake_provider
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


def test_admin_lookup_api_rejects_invalid_target():
    client = TestClient(app)

    response = client.get("/api/admin/lookup", params={"target": "=bad"})

    assert response.status_code == 422


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

from fastapi.testclient import TestClient

from app.main import app


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

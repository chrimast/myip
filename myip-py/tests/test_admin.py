import re

import respx
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
    assert "字段开关" in body
    assert "data-field-enabled" in body
    assert "Provider 调用链" in body
    assert "禁用字段" in body
    assert "公开接口模式" in body
    assert "/api/admin/config-status" in body
    assert "恢复默认生产链" in body
    assert "自定义 Provider" in body
    assert "自定义字段" in body
    assert "/api/admin/custom-providers" in body
    assert "/api/admin/custom-fields" in body
    assert "测试自定义 Provider" in body
    assert "/api/admin/custom-providers/preview" in body
    assert "可参与后台" in body
    assert "允许自定义 Provider 用于公开接口" in body
    assert "data-public-custom-providers-enabled" in body
    assert "最后验证" in body
    assert "data-preview-status" in body


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


def test_admin_lookup_can_execute_enabled_custom_json_provider(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.post(
        "/api/admin/custom-providers",
        json={
            "id": "example-provider",
            "name": "Example Provider",
            "enabled": True,
            "order": 1,
            "endpoint": "https://api.example.com/ip/{ip}",
            "provides": ["country", "country_code", "asn", "asn_owner", "isp", "is_proxy", "is_hosting"],
            "field_paths": {
                "country": ["location.country"],
                "country_code": ["location.country_code"],
                "asn": ["asn.number"],
                "asn_owner": ["asn.name"],
                "isp": ["company.name"],
                "is_proxy": ["security.proxy"],
                "is_hosting": ["security.hosting"],
            },
            "transforms": {"asn": "asn_int", "is_proxy": "bool", "is_hosting": "bool"},
        },
    )
    client.put(
        "/api/admin/provider-config",
        json={
            "providers": [
                {"id": "ipapi.is", "enabled": False, "order": 99},
                {"id": "example-provider", "enabled": True, "order": 1, "timeout_seconds": 2.0},
            ],
            "custom_providers": client.get("/api/admin/provider-config").json()["custom_providers"],
        },
    )

    with respx.mock(assert_all_called=True) as router:
        router.get("https://api.example.com/ip/8.8.8.8").respond(
            200,
            json={
                "location": {"country": "United States", "country_code": "US"},
                "asn": {"number": "AS15169", "name": "Google LLC"},
                "company": {"name": "Google"},
                "security": {"proxy": "false", "hosting": "true"},
            },
        )
        response = client.get("/api/admin/lookup", params={"target": "8.8.8.8"})

    assert response.status_code == 200
    body = response.json()
    assert body["result"]["provider"] == "example-provider"
    assert body["result"]["country"] == "United States"
    assert body["result"]["country_code"] == "US"
    assert body["result"]["asn"] == "AS15169"
    assert body["result"]["asn_owner"] == "Google LLC"
    assert body["result"]["is_proxy"] is False
    assert body["result"]["is_hosting"] is True
    assert body["field_sources"]["asn_owner"] == "example-provider:asn.name"
    assert body["debug"]["provider_attempts"] == [
        {"provider": "example-provider", "status": "ok", "timeout_seconds": 2.0}
    ]


def test_public_lookup_does_not_execute_enabled_custom_json_provider_by_default(tmp_path, monkeypatch):
    from app.api.ip import clear_ip_lookup_cache

    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    clear_ip_lookup_cache()
    client.post(
        "/api/admin/custom-providers",
        json={
            "id": "public-blocked-provider",
            "name": "Public Blocked Provider",
            "enabled": True,
            "order": 1,
            "endpoint": "https://api.example.com/ip/{ip}",
            "provides": ["country"],
            "field_paths": {"country": ["country"]},
        },
    )
    client.put(
        "/api/admin/provider-config",
        json={
            "providers": [
                {"id": "ipapi.is", "enabled": False, "order": 99},
                {"id": "ipwho.is", "enabled": False, "order": 99},
                {"id": "ip-api.com", "enabled": False, "order": 99},
                {"id": "ipapi.org", "enabled": False, "order": 99},
                {"id": "ipinfo.io", "enabled": False, "order": 99},
                {"id": "ipdata.co", "enabled": False, "order": 99},
                {"id": "public-blocked-provider", "enabled": True, "order": 1},
            ],
            "custom_providers": client.get("/api/admin/provider-config").json()["custom_providers"],
        },
    )

    with respx.mock(assert_all_called=False) as router:
        route = router.get("https://api.example.com/ip/8.8.8.8").respond(200, json={"country": "United States"})
        response = client.get("/api/ip?8.8.8.8")

    assert response.status_code == 502
    assert route.called is False


def test_public_lookup_can_execute_custom_json_provider_when_explicitly_enabled(tmp_path, monkeypatch):
    from app.api.ip import clear_ip_lookup_cache

    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    clear_ip_lookup_cache()
    client.post(
        "/api/admin/custom-providers",
        json={
            "id": "public-custom-provider",
            "name": "Public Custom Provider",
            "enabled": True,
            "order": 1,
            "endpoint": "https://api.example.com/ip/{ip}",
            "provides": ["country", "country_code", "asn", "asn_owner", "is_proxy", "is_hosting", "fraud_score"],
            "field_paths": {
                "country": ["location.country"],
                "country_code": ["location.country_code"],
                "asn": ["asn.number"],
                "asn_owner": ["asn.name"],
                "is_proxy": ["security.proxy"],
                "is_hosting": ["security.hosting"],
                "fraud_score": ["risk.score"],
            },
            "transforms": {"asn": "asn_int", "is_proxy": "bool", "is_hosting": "bool", "fraud_score": "int"},
        },
    )
    client.put(
        "/api/admin/provider-config",
        json={
            "public_custom_providers_enabled": True,
            "providers": [
                {"id": "ipapi.is", "enabled": False, "order": 99},
                {"id": "ipwho.is", "enabled": False, "order": 99},
                {"id": "ip-api.com", "enabled": False, "order": 99},
                {"id": "ipapi.org", "enabled": False, "order": 99},
                {"id": "ipinfo.io", "enabled": False, "order": 99},
                {"id": "ipdata.co", "enabled": False, "order": 99},
                {"id": "public-custom-provider", "enabled": True, "order": 1, "timeout_seconds": 2.0},
            ],
            "custom_providers": client.get("/api/admin/provider-config").json()["custom_providers"],
        },
    )

    with respx.mock(assert_all_called=True) as router:
        router.get("https://api.example.com/ip/8.8.8.8").respond(
            200,
            json={
                "location": {"country": "United States", "country_code": "US"},
                "asn": {"number": "AS15169", "name": "Google LLC"},
                "security": {"proxy": "false", "hosting": "true"},
                "risk": {"score": "42"},
            },
        )
        response = client.get("/api/ip?8.8.8.8")

    assert response.status_code == 200
    body = response.json()
    assert body["geo_provider"] == "public-custom-provider"
    assert body["country"] == "United States"
    assert body["countryCode"] == "US"
    assert body["asn_owner"] == "Google LLC"
    assert body["as"] == "AS15169"
    assert body["proxy"] is False
    assert body["hosting"] is True
    assert "fraud_score" not in body


def test_admin_custom_provider_preview_fetches_json_and_extracts_mapped_fields(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.post(
        "/api/admin/custom-providers",
        json={
            "id": "example-provider",
            "name": "Example Provider",
            "endpoint": "https://api.example.com/ip/{ip}",
            "provides": ["country", "asn", "asn_owner", "is_proxy", "fraud_score"],
            "field_paths": {
                "country": ["location.country"],
                "asn": ["asn.number"],
                "asn_owner": ["asn.name"],
                "is_proxy": ["security.proxy"],
                "fraud_score": ["risk.score"],
            },
            "transforms": {"asn": "asn_int", "is_proxy": "bool", "fraud_score": "int"},
        },
    )

    with respx.mock(assert_all_called=True) as router:
        router.get("https://api.example.com/ip/8.8.8.8").respond(
            200,
            json={
                "location": {"country": "United States"},
                "asn": {"number": "AS15169", "name": "Google LLC"},
                "security": {"proxy": "true"},
                "risk": {"score": "42"},
            },
        )
        response = client.post(
            "/api/admin/custom-providers/preview",
            json={"ip": "8.8.8.8", "provider_id": "example-provider"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["provider_id"] == "example-provider"
    assert body["url"] == "https://api.example.com/ip/8.8.8.8"
    assert body["normalized"] == {
        "country": "United States",
        "asn": 15169,
        "asn_owner": "Google LLC",
        "is_proxy": True,
        "fraud_score": 42,
    }
    assert body["raw"]["asn"]["name"] == "Google LLC"
    provider = client.get("/api/admin/provider-config").json()["custom_providers"][0]
    assert provider["last_preview"]["status"] == "ok"
    assert provider["last_preview"]["ip"] == "8.8.8.8"
    assert provider["last_preview"]["normalized_fields"] == ["asn", "asn_owner", "country", "fraud_score", "is_proxy"]
    assert provider["last_preview"]["missing_fields"] == []
    assert re.match(r"^\d{4}-\d{2}-\d{2}T", provider["last_preview"]["checked_at"])


def test_admin_custom_provider_preview_records_failure_for_saved_provider(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.post(
        "/api/admin/custom-providers",
        json={
            "id": "failing-provider",
            "name": "Failing Provider",
            "endpoint": "https://api.example.com/ip/{ip}",
            "provides": ["country"],
            "field_paths": {"country": ["country"]},
        },
    )

    with respx.mock(assert_all_called=True) as router:
        router.get("https://api.example.com/ip/8.8.8.8").respond(500, json={"error": "down"})
        response = client.post(
            "/api/admin/custom-providers/preview",
            json={"ip": "8.8.8.8", "provider_id": "failing-provider"},
        )

    assert response.status_code == 502
    provider = client.get("/api/admin/provider-config").json()["custom_providers"][0]
    assert provider["last_preview"]["status"] == "error"
    assert provider["last_preview"]["ip"] == "8.8.8.8"
    assert "custom provider request failed" in provider["last_preview"]["error"]
    assert provider["last_preview"]["normalized_fields"] == []
    assert provider["last_preview"]["missing_fields"] == ["country"]


def test_admin_custom_provider_preview_uses_first_available_path_and_reports_missing():
    client = TestClient(app)

    with respx.mock(assert_all_called=True) as router:
        router.get("https://api.example.com/8.8.4.4").respond(200, json={"company": {"name": "Example ISP"}})
        response = client.post(
            "/api/admin/custom-providers/preview",
            json={
                "ip": "8.8.4.4",
                "provider": {
                    "id": "example-provider",
                    "name": "Example Provider",
                    "endpoint": "https://api.example.com/{ip}",
                    "provides": ["org", "country"],
                    "field_paths": {"org": ["organization.name", "company.name"], "country": ["location.country"]},
                },
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["normalized"] == {"org": "Example ISP"}
    assert body["missing_fields"] == ["country"]
    assert body["field_sources"] == {"org": "company.name"}


def test_admin_custom_provider_preview_rejects_plain_http_endpoint():
    client = TestClient(app)

    response = client.post(
        "/api/admin/custom-providers/preview",
        json={
            "ip": "8.8.8.8",
            "provider": {"id": "bad-provider", "name": "Bad", "endpoint": "http://api.example.com/{ip}", "provides": []},
        },
    )

    assert response.status_code == 422
    assert "https" in response.json()["detail"].lower()


def test_admin_custom_provider_preview_blocks_private_and_metadata_hosts():
    client = TestClient(app)

    for endpoint in ["https://127.0.0.1/{ip}", "https://10.0.0.1/{ip}", "https://169.254.169.254/{ip}"]:
        response = client.post(
            "/api/admin/custom-providers/preview",
            json={
                "ip": "8.8.8.8",
                "provider": {"id": "bad-provider", "name": "Bad", "endpoint": endpoint, "provides": []},
            },
        )
        assert response.status_code == 422
        assert "unsafe" in response.json()["detail"].lower()


def test_admin_custom_provider_preview_rejects_unknown_transform():
    client = TestClient(app)

    response = client.post(
        "/api/admin/custom-providers/preview",
        json={
            "ip": "8.8.8.8",
            "provider": {
                "id": "example-provider",
                "name": "Example Provider",
                "endpoint": "https://api.example.com/{ip}",
                "provides": ["country"],
                "field_paths": {"country": ["country"]},
                "transforms": {"country": "eval"},
            },
        },
    )

    assert response.status_code == 422


def test_admin_custom_provider_preview_requires_valid_ip():
    client = TestClient(app)

    response = client.post(
        "/api/admin/custom-providers/preview",
        json={
            "ip": "not an ip",
            "provider": {"id": "example-provider", "name": "Example", "endpoint": "https://api.example.com/{ip}", "provides": []},
        },
    )

    assert response.status_code == 422


def test_admin_custom_provider_api_persists_metadata_and_merges_provider_list(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    payload = {
        "id": "example-provider",
        "name": "Example Provider",
        "endpoint": "https://api.example.com/{ip}",
        "provides": ["country", "fraud_score"],
        "field_paths": {"country": ["location.country"], "fraud_score": ["risk.score"]},
    }

    response = client.post("/api/admin/custom-providers", json=payload)

    assert response.status_code == 200
    body = response.json()
    custom = body["custom_providers"][0]
    assert custom["id"] == "example-provider"
    assert custom["enabled"] is False
    assert custom["custom"] is True
    assert custom["role"] == "custom metadata"
    assert custom["field_paths"] == payload["field_paths"]

    providers = client.get("/api/admin/providers").json()
    example = next(provider for provider in providers if provider["id"] == "example-provider")
    assert example["name"] == "Example Provider"
    assert example["custom"] is True
    assert example["enabled"] is False
    assert "fraud_score" in example["provides"]


def test_admin_custom_provider_delete_removes_metadata(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.post(
        "/api/admin/custom-providers",
        json={"id": "delete-me", "name": "Delete Me", "endpoint": "https://api.example.com/{ip}", "provides": []},
    )

    response = client.delete("/api/admin/custom-providers/delete-me")

    assert response.status_code == 200
    assert response.json()["custom_providers"] == []
    assert all(provider["id"] != "delete-me" for provider in client.get("/api/admin/providers").json())


def test_admin_custom_provider_api_rejects_builtin_conflict(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", tmp_path / "provider-config.json")
    client = TestClient(app)

    response = client.post(
        "/api/admin/custom-providers",
        json={"id": "ipapi.is", "name": "Conflict", "endpoint": "https://api.example.com/{ip}", "provides": []},
    )

    assert response.status_code == 422


def test_admin_custom_field_api_persists_metadata_and_merges_field_list(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    payload = {
        "field": "fraud_score",
        "label": "欺诈评分",
        "type": "int",
        "source_type": "custom",
        "used_for": ["display", "debug"],
        "providers": {"example-provider": ["risk.score"]},
    }

    response = client.post("/api/admin/custom-fields", json=payload)

    assert response.status_code == 200
    custom = response.json()["custom_fields"][0]
    assert custom["field"] == "fraud_score"
    assert custom["scoring"] is False
    assert custom["custom"] is True

    fields = {field["field"]: field for field in client.get("/api/admin/fields").json()}
    assert fields["fraud_score"]["label"] == "欺诈评分"
    assert fields["fraud_score"]["providers"] == {"example-provider": ["risk.score"]}


def test_admin_custom_field_delete_removes_metadata(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.post("/api/admin/custom-fields", json={"field": "delete_field", "label": "Delete field", "type": "string"})

    response = client.delete("/api/admin/custom-fields/delete_field")

    assert response.status_code == 200
    assert response.json()["custom_fields"] == []
    assert "delete_field" not in {field["field"] for field in client.get("/api/admin/fields").json()}


def test_admin_custom_field_api_rejects_builtin_conflict(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", tmp_path / "provider-config.json")
    client = TestClient(app)

    response = client.post("/api/admin/custom-fields", json={"field": "network_type", "label": "Conflict", "type": "string"})

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
    assert body["custom_providers"] == []
    assert body["custom_fields"] == []
    assert body["public_custom_providers_enabled"] is False
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
        "public_custom_providers_enabled": True,
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
    assert body["public_custom_providers_enabled"] is True
    assert "key" not in config_path.read_text(encoding="utf-8").lower()


def test_admin_provider_config_api_rejects_unknown_provider(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", tmp_path / "provider-config.json")
    client = TestClient(app)

    response = client.put(
        "/api/admin/provider-config",
        json={"providers": [{"id": "unknown", "enabled": True, "order": 1}]},
    )

    assert response.status_code == 422


def test_admin_config_status_reports_default_public_lookup_mode(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)

    response = client.get("/api/admin/config-status")

    assert response.status_code == 200
    body = response.json()
    assert body["public_lookup_mode"] == "default-production-chain"
    assert body["uses_admin_provider_config"] is False
    assert body["provider_config_exists"] is False
    assert body["public_custom_providers_enabled"] is False
    assert body["storage_path"] == str(config_path)
    assert body["warning"] is None


def test_admin_config_status_reports_admin_config_public_lookup_mode(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.put("/api/admin/provider-config", json={"providers": [{"id": "ip-api.com", "enabled": True, "order": 1}]})

    response = client.get("/api/admin/config-status")

    assert response.status_code == 200
    body = response.json()
    assert body["public_lookup_mode"] == "admin-config-chain"
    assert body["uses_admin_provider_config"] is True
    assert body["provider_config_exists"] is True
    assert body["public_custom_providers_enabled"] is False
    assert body["warning"] == "保存的后台 Provider 配置正在影响公开 /api/ip"


def test_admin_config_status_warns_when_public_custom_providers_enabled(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = TestClient(app)
    client.put(
        "/api/admin/provider-config",
        json={"providers": [{"id": "ip-api.com", "enabled": True, "order": 1}], "public_custom_providers_enabled": True},
    )

    response = client.get("/api/admin/config-status")

    assert response.status_code == 200
    body = response.json()
    assert body["public_custom_providers_enabled"] is True
    assert body["warning"] == "保存的后台 Provider 配置正在影响公开 /api/ip，且公开接口允许自定义 Provider"

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

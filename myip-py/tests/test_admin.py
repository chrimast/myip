import re

import pytest
import respx
from fastapi.testclient import TestClient

from app.main import app
from app.api.admin import admin_ip_lookup_provider
from app.core.config import get_settings
from app.services.ip_lookup import IPInfo, IPLookupUnavailable, StaticIPLookupProvider


@pytest.fixture(autouse=True)
def reset_settings_override():
    app.dependency_overrides.pop(get_settings, None)
    yield
    app.dependency_overrides.pop(get_settings, None)


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
    myip_admin_password = "admin"
    myip_admin_session_secret = "test-session-secret"

    def key_status(self):
        return {
            "ipapi_is_key": {"configured": False, "source": "missing"},
            "ipapi_org_key": {"configured": False, "source": "missing"},
            "ipinfo_token": {"configured": False, "source": "missing"},
            "ipdata_key": {"configured": False, "source": "missing"},
        }

    def public_config(self):
        return {
            "debug": self.myip_debug,
            "cache_ttl_seconds": self.myip_cache_ttl_seconds,
            "rate_limit_per_minute": self.myip_rate_limit_per_minute,
            "provider_timeout_seconds": self.myip_provider_timeout_seconds,
            "doh_timeout_seconds": self.myip_doh_timeout_seconds,
            "doh_providers": ["cloudflare", "google", "quad9"],
        }

    def doh_provider_names(self):
        return ["cloudflare", "google", "quad9"]


def enable_admin_auth() -> None:
    app.dependency_overrides[get_settings] = lambda: AdminAuthSettings()


def admin_client() -> TestClient:
    client = TestClient(app)
    login = client.post("/admin/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
    assert login.status_code == 303
    return client


def test_admin_page_requires_login_when_admin_password_is_configured():
    enable_admin_auth()
    client = TestClient(app)

    response = client.get("/admin")

    assert response.status_code == 401
    assert "后台登录" in response.text
    assert "name=\"username\"" in response.text
    assert "name=\"password\"" in response.text


def test_admin_api_requires_login_when_admin_password_is_configured():
    enable_admin_auth()
    client = TestClient(app)

    response = client.get("/api/admin/settings")

    assert response.status_code == 401
    assert response.json() == {"detail": "Admin authentication required"}


def test_admin_login_session_allows_page_and_api_access():
    enable_admin_auth()
    client = TestClient(app)

    login = client.post("/admin/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)

    assert login.status_code == 303
    assert login.headers["location"] == "/admin"
    assert client.get("/admin").status_code == 200
    assert client.get("/api/admin/settings").status_code == 200


def test_admin_logout_clears_login_session():
    enable_admin_auth()
    client = TestClient(app)
    assert client.post("/admin/login", data={"username": "admin", "password": "admin"}, follow_redirects=False).status_code == 303

    logout = client.post("/admin/logout", follow_redirects=False)

    assert logout.status_code == 303
    assert logout.headers["location"] == "/admin"
    assert client.get("/api/admin/settings").status_code == 401


def test_admin_auth_defaults_to_admin_admin_and_can_be_changed_after_login(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    enable_admin_auth()
    client = TestClient(app)

    login = client.post("/admin/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)

    assert login.status_code == 303
    assert client.get("/api/admin/auth-config").json() == {"username": "admin", "password_configured": True}
    runtime_save = client.put(
        "/api/admin/runtime-settings",
        json={"cache": {"ip_enabled": False, "ip_ttl_seconds": 30, "ip_cache_granularity": "single_ip", "bgp_enabled": True, "bgp_ttl_seconds": 900}},
    )
    assert runtime_save.status_code == 200
    assert client.get("/api/admin/provider-config").status_code == 200

    update = client.put("/api/admin/auth-config", json={"username": "root", "password": "new-pass"})
    assert update.status_code == 200
    assert update.json() == {"username": "root", "password_configured": True}
    assert "new-pass" not in config_path.read_text(encoding="utf-8")

    old_session = client.get("/api/admin/settings")
    assert old_session.status_code == 401
    client.cookies.clear()
    assert client.post("/admin/login", data={"username": "admin", "password": "admin"}, follow_redirects=False).status_code == 401
    assert client.post("/admin/login", data={"username": "root", "password": "new-pass"}, follow_redirects=False).status_code == 303
    assert client.get("/api/admin/settings").status_code == 200

def test_admin_page_serves_provider_management_shell():
    client = admin_client()

    response = client.get("/admin")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert "Provider 管理" in body
    assert "修改后台账号" in body
    assert "data-admin-auth-settings" in body
    assert "/api/admin/auth-config" in body
    assert "默认用户名 admin / 默认密码 admin" in body
    assert "管理控制台" in body
    assert "1. 网站概览" in body
    assert "2. 字段与数据源映射" in body
    assert "3. Provider 管理" in body
    assert "功能页面" not in body
    assert "data-page-card-nav" not in body
    assert "data-floating-settings-nav" in body
    assert "悬浮设置导航" in body
    assert "sticky" in body
    assert 'href="#site-overview"' in body
    assert 'href="#runtime-settings"' in body
    assert 'href="#mapping-workspace"' in body
    assert 'href="#new-data-source"' in body
    assert 'href="#provider-management"' in body
    assert 'href="#lookup-debug"' in body
    assert "运行生效" in body
    assert "数据源与字段" in body
    assert "移动端会降级为横向滚动导航" in body
    assert "floating-settings-nav compact" in body
    assert "data-nav-compact" in body
    assert "data-nav-mobile-compact" in body
    assert "grid-template-columns:repeat(6,minmax(0,1fr))" in body
    assert "white-space:nowrap" in body
    assert "nav:not(.floating-settings-nav)" in body
    assert "nav { display:grid; grid-template-columns:1fr; }" not in body
    assert ".floating-settings-nav { display:flex; flex-wrap:nowrap; top:0" in body
    assert "gap:1px; overflow-x:auto" in body
    assert ".floating-settings-nav p { display:none; }" in body
    assert ".floating-settings-nav a { display:inline-flex; flex:0 0 auto; width:max-content; min-width:max-content; padding:5px 5px; overflow:visible; text-overflow:clip; white-space:nowrap; word-break:keep-all; }" in body
    assert ".floating-settings-nav strong { font-size:13px; white-space:nowrap; word-break:keep-all; }" in body
    assert "grid-template-columns:repeat(6,minmax(0,1fr)); top:0" not in body
    assert "gap:2px; overflow-x:auto" not in body
    assert ".floating-settings-nav strong { font-size:12px; }" not in body
    assert ".floating-settings-nav strong { font-size:11px; }" not in body
    assert ".floating-settings-nav strong { font-size:10px; }" not in body
    assert "min-width:150px" not in body
    assert "min-width:170px" not in body
    assert "data-nav-category=\"overview\"" in body
    assert "data-nav-category=\"runtime\"" in body
    assert "data-nav-category=\"mapping\"" in body
    assert "data-nav-category=\"new-source\"" in body
    assert "data-nav-category=\"provider\"" in body
    assert "data-nav-category=\"debug\"" in body
    assert body.index('data-floating-settings-nav') < body.index('id="site-overview"')
    assert "data-page-card=\"site-overview\"" not in body
    assert "集中查看公开模式、运行配置和配置状态" not in body
    assert "从验证结果生成字段来源" not in body
    assert "网站概览" in body
    assert "总览与公开接口控制已合并" in body
    assert "data-site-overview" in body
    assert "data-overview-status-card" in body
    assert "data-public-control-card" in body
    assert "字段视图" in body
    assert "Provider 总览" in body
    assert "Provider 视图与原 Provider 概览已合并" in body
    assert "Provider 配置已合并到 Provider 总览" in body
    assert "调用链顺序" in body
    assert "data-provider-move-up" in body
    assert "data-provider-move-down" in body
    assert "data-provider-timeout-preset" in body
    assert "快速 1s" in body
    assert "标准 2s" in body
    assert "宽松 5s" in body
    assert "data-provider-runtime-summary" in body
    assert "provider-control-row" in body
    assert "field-source-control-row" in body
    assert ".provider-control-row, .field-source-control-row { display:flex" in body
    assert ".provider-control-row button, .field-source-control-row button" in body
    assert "grid-template-columns:1fr; } .provider-control-row" in body
    assert body.index('data-provider-view') > body.index('id="provider-management"')
    assert body.index('Provider 总览') < body.index('保存与公开控制')
    assert "新增数据源" in body
    assert "按字段查看评分字段" not in body
    assert "添加自定义 Provider、测试返回 JSON" not in body
    assert "data-mapping-workspace" in body
    assert "data-field-view" in body
    assert "data-provider-view" in body
    assert "data-new-data-source" in body
    assert "从测试结果生成字段映射" in body
    assert "data-apply-preview-mapping" in body
    assert "data-provider-source-row" in body
    assert "data-field-provider-select" in body
    assert "data-field-path-input" in body
    assert "高级调试" in body
    assert "4. 运行设置" not in body
    assert "运行设置已并入网站概览" in body
    assert "data-site-runtime-settings" in body
    assert body.index('data-site-runtime-settings') < body.index('id="mapping-workspace"')
    assert "缓存设置" in body
    assert "访问限制设置" in body
    assert "DNS / DoH 设置" in body
    assert "BGP 图谱设置" in body
    assert "缓存有效期" in body
    assert "5 分钟" in body
    assert "1 小时" in body
    assert "缓存范围" in body
    assert "仅相同 IP" in body
    assert "同一 IPv4 /24 网段" in body
    assert "data-runtime-preset" in body
    assert "普通：60 次/分钟" in body
    assert "严格：20 次/分钟" in body
    assert "DoH 解析服务顺序" in body
    assert "data-doh-provider-order" in body
    assert "优先 IPv4" in body
    assert "优先 IPv6" in body
    assert "图谱复杂度" in body
    assert "简洁" in body
    assert "标准" in body
    assert "详细" in body
    assert "data-bgp-complexity" in body
    assert "data-runtime-settings" in body
    assert "runtime-settings-grid vertical" in body
    assert "runtime-settings-grid vertical subpanel-grid" not in body
    assert "data-runtime-settings-vertical" in body
    assert "grid-template-columns:1fr" in body
    assert "runtime-setting-row" in body
    assert "runtime-panel-body" in body
    assert "data-runtime-panel-body" in body
    assert ".runtime-panel-body { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr))" in body
    assert ".runtime-setting-row { display:grid; grid-template-columns:max-content minmax(92px,1fr)" in body
    assert ".runtime-setting-row.compact-toggle { grid-template-columns:max-content min-content" in body
    assert "runtime-panel-heading" in body
    assert "runtime-heading-toggle" in body
    assert "data-runtime-heading-toggle" in body
    assert 'data-runtime-heading-toggle><input type="checkbox" data-runtime="cache.ip_enabled"' in body
    assert 'data-runtime-heading-toggle><input type="checkbox" data-runtime="rate_limit.ip_enabled"' in body
    assert 'data-runtime-heading-toggle><input type="checkbox" data-runtime="dns.doh_enabled"' in body
    assert 'data-runtime-heading-toggle><input type="checkbox" data-runtime="bgp.enabled"' in body
    assert 'pill runtime-setting-row"><input type="checkbox" data-runtime="cache.ip_enabled"' not in body
    assert 'pill runtime-setting-row"><input type="checkbox" data-runtime="rate_limit.ip_enabled"' not in body
    assert 'pill runtime-setting-row"><input type="checkbox" data-runtime="dns.doh_enabled"' not in body
    assert 'pill runtime-setting-row"><input type="checkbox" data-runtime="bgp.enabled"' not in body
    assert "runtime-preset-row" in body
    assert ".runtime-setting-row { display:grid; grid-template-columns:max-content minmax(92px,1fr)" in body
    assert ".runtime-preset-row { display:grid; grid-template-columns:repeat(3,minmax(0,1fr))" in body
    assert "input, select, textarea, button { width:100%; margin-right:0; }" in body
    assert ".runtime-heading-toggle { width:auto; } .runtime-heading-toggle input { width:auto; }" in body
    assert ".runtime-setting-row { grid-template-columns:max-content minmax(88px,1fr); gap:4px; font-size:12px; }" in body
    assert ".runtime-panel-body { grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; }" in body
    assert ".runtime-setting-row input:not([type=\"checkbox\"]), .runtime-setting-row select { min-width:0; width:72px;" in body
    assert "data-cache-settings" in body
    assert "data-rate-limit-settings" in body
    assert "data-dns-settings" in body
    assert "data-bgp-settings" in body
    assert "/api/admin/runtime-settings" in body
    assert "data-advanced-debug" in body
    assert "当前公开接口正在使用" in body
    assert "启用 Provider" in body
    assert "验证风险" in body
    assert "Provider 卡片" not in body
    assert "data-provider-card" in body
    assert "步骤 1：基本信息" in body
    assert "自动生成 Provider ID" in body
    assert "data-autofill-provider-id" in body
    assert "步骤 2：Endpoint" in body
    assert "接口地址需要包含 {ip}" in body
    assert "data-endpoint-template-help" in body
    assert "步骤 3：字段映射" in body
    assert "步骤 4：测试验证" in body
    assert "步骤 5：启用" in body
    assert "只保存，不启用" in body
    assert "启用到后台调试" in body
    assert "启用到公开接口，需要验证保护" in body
    assert "data-custom-provider-enable-scope" in body
    assert "字段筛选" in body
    assert "data-field-filter" in body
    assert "data-field-summary-row" in body
    assert "data-field-detail" in body
    assert "Provider 覆盖摘要" in body
    assert "data-provider-coverage-summary" in body
    assert "data-provider-field-details" in body
    assert "映射问题提示" in body
    assert "data-mapping-issues" in body
    assert "字段管理" not in body
    assert "字段视图" in body
    assert "固定字段名称" not in body
    assert "字段优先级" in body
    assert "字段名保持 snake_case" not in body
    assert "每个字段卡片会展示 provider" not in body
    assert "data-field-catalog" in body
    assert "data-field-card" in body
    assert "data-field-mapping" in body
    assert "data-scoring-field" in body
    assert "参与评分" in body
    assert "评分字段" in body
    assert "非评分字段" in body
    assert "data-scoring-fields" in body
    assert "data-display-fields" in body
    assert "data-field-groups-grid" in body
    assert "field-groups-grid" in body
    assert "字段开关已合并到评分字段和非评分字段" in body
    assert "编辑字段映射" in body
    assert "保存字段映射" in body
    assert "可视化来源编辑" in body
    assert "添加来源" in body
    assert "data-field-source-list" in body
    assert "data-field-source-move-up" in body
    assert "data-field-source-move-down" in body
    assert "高级 JSON 编辑" in body
    assert "默认建议使用上面的来源列表" in body
    assert "data-field-mapping-editor" in body
    assert "data-save-field-mappings" in body
    assert "/api/admin/field-mappings" in body
    assert "/api/admin/settings" in body
    assert "/api/admin/providers" in body
    assert "/api/admin/fields" in body
    assert "查询调试" in body
    assert "/api/admin/lookup" in body
    assert "<h3>Provider 配置</h3>" not in body
    assert "/api/admin/provider-config" in body
    assert "id=\"provider-config\"" not in body
    assert "<h3 style=\"margin-top:18px\">字段开关</h3>" not in body
    assert "data-field-enabled" in body
    assert "Provider 调用链" in body
    assert "禁用字段" in body
    assert "公开接口模式" in body
    assert "/api/admin/config-status" in body
    assert "恢复默认生产链" in body
    assert "providerConfigReset:'/api/admin/provider-config/reset'" in body
    assert "fetch(endpoints.providerConfigReset, {method:'POST'})" in body
    assert "字段与数据源映射" in body
    assert "自定义 Provider" in body
    assert "自定义字段" in body
    assert "/api/admin/custom-providers" in body
    assert "/api/admin/custom-fields" in body
    assert "测试自定义 Provider" in body
    assert "/api/admin/custom-providers/preview" in body
    assert "可参与后台" in body
    assert "允许自定义 Provider 用于公开接口" in body
    assert "要求自定义 Provider 验证成功后才用于公开接口" in body
    assert "data-public-custom-providers-enabled" in body
    assert "data-require-custom-provider-preview-ok" in body
    assert "data-public-custom-provider-warnings" in body
    assert "最后验证" in body
    assert "data-preview-status" in body
    assert "操作反馈" in body
    assert "id=\"admin-feedback\"" in body
    assert "data-confirm-reset" in body
    assert "重置会删除当前保存的后台配置" in body
    assert "data-form-help" in body
    assert "示例：" in body
    assert "JSON 校验" in body
    assert "没有已保存的自定义 Provider" in body
    assert "没有已保存的自定义字段" in body
    assert "清空表单" in body
    assert "data-clear-custom-provider-form" in body
    assert "data-clear-custom-field-form" in body
    assert "color-scheme: light" in body
    assert "data-light-admin-theme" in body
    assert "data-mobile-layout" in body
    assert "@media (max-width:720px)" in body
    assert "data-mobile-provider-config-list" in body
    assert "data-provider-config-panel" in body
    assert "provider-management-stack" in body
    assert "保存与公开控制" in body
    assert "运行设置会随保存配置写入同一份 JSON" not in body
    assert "data-runtime-settings-panel" in body
    assert "provider-config-mobile-row" in body
    assert "provider-config-mobile-controls" in body
    assert "data-provider-config-mobile-three-col" in body
    assert "grid-template-columns:repeat(3,minmax(0,1fr))" in body
    assert "provider-config-control" in body
    assert "data-provider-config-id" in body
    assert "provider-config-control-label" in body
    assert "provider-config-control-input" in body
    assert ">配置</strong>" not in body
    assert "provider-config-inline-controls" in body
    assert "grid-template-columns:minmax(96px,.9fr) minmax(0,2.1fr)" in body
    assert "minmax(0,1fr)" in body
    assert "collectProviderConfig().runtime_settings" in body
    assert body.index('id="mapping-workspace"') < body.index('id="provider-management"')
    assert "数据接口导航" not in body
    assert "data-api-nav" not in body
    assert "data-api-page=\"settings\"" not in body
    assert "接口页面：/api/admin/settings" not in body
    assert "data-api-response" not in body
    assert "认证方式" in body
    assert "无需认证" in body
    assert "API Key" in body
    assert "Bearer Token" in body
    assert "data-custom-provider-auth-type" in body
    assert "data-custom-provider-auth-name" in body
    assert "data-custom-provider-auth-value" in body
    assert "Key / Token 只保存在后台配置" in body
    assert "测试与公开调用会按认证方式携带请求头" in body
    assert "预览和公开调用是否真正使用它，后续再接入请求头/参数" not in body
    assert "Provider 健康检查" in body
    assert "data-provider-health" in body
    assert "data-provider-health-status" in body
    assert "/api/admin/provider-health" in body
    assert "配置导入/导出" in body
    assert "data-config-import-export" in body
    assert "/api/admin/provider-config/export" in body
    assert "/api/admin/provider-config/import" in body
    assert "API Key 指引" in body
    assert "data-api-key-guidance" in body
    assert "data-admin-shell" in body
    assert "admin-shell" in body
    assert "console-hero" in body
    assert "section-shell" in body
    assert "section-heading" in body
    assert "section-eyebrow" in body
    assert "section-lead" in body
    assert "category-overview" in body
    assert "category-mapping" in body
    assert "category-provider" in body
    assert "category-debug" in body
    assert "功能分区" in body
    assert "状态总览" in body
    assert "映射工作台" in body
    assert "调用链排查" in body


def test_admin_settings_api_exposes_safe_runtime_config_without_secret_values():
    client = admin_client()

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


def test_admin_builtin_api_keys_can_be_saved_and_used_without_leaking_secret(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()

    saved = client.put("/api/admin/api-keys", json={"ipinfo_token": "saved-token", "ipdata_key": ""})

    assert saved.status_code == 200
    body = saved.json()
    assert body["ipinfo_token"] == {"configured": True, "source": "admin"}
    assert body["ipdata_key"] == {"configured": False, "source": "missing"}
    assert "saved-token" not in config_path.read_text(encoding="utf-8")
    assert client.get("/api/admin/settings").json()["keys"]["ipinfo_token"] == {"configured": True, "source": "admin"}

    from app.services.ip_lookup import IPAPIIsLookupProvider

    provider = IPAPIIsLookupProvider()
    with respx.mock(assert_all_called=True) as router:
        route = router.get("https://ipinfo.io/8.8.8.8/json").respond(
            200,
            json={"ip": "8.8.8.8", "asn": {"asn": "AS15169", "name": "Google LLC"}},
        )
        result = provider._lookup_ipinfo("8.8.8.8")

    assert route.called
    assert route.calls[0].request.url.params["token"] == "saved-token"
    assert result.provider == "ipinfo.io"


def test_admin_runtime_settings_status_reports_live_effect_and_cache_clear(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    client.put(
        "/api/admin/runtime-settings",
        json={"cache": {"ip_enabled": False, "ip_ttl_seconds": 30}, "dns": {"doh_providers": ["quad9"], "timeout_seconds": 2}},
    )

    response = client.get("/api/admin/runtime-status")

    assert response.status_code == 200
    body = response.json()
    assert body["effective"]["cache"]["ip_enabled"] is False
    assert body["effective"]["dns"]["doh_providers"] == ["quad9"]
    assert body["modules"]["ip_lookup"]["cache"] == "disabled"
    assert body["modules"]["dns"]["provider_order"] == ["quad9"]
    assert body["actions"]["can_clear_cache"] is True

    cleared = client.post("/api/admin/runtime/cache/clear")
    assert cleared.status_code == 200
    assert cleared.json()["cleared"] == ["ip_lookup", "bgp"]


def test_admin_provider_health_includes_latency_checked_at_and_http_status(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    client.put(
        "/api/admin/provider-config",
        json={
            "providers": [
                {"id": "ip-api.com", "enabled": True, "order": 1, "timeout_seconds": 1.0},
                {"id": "ipapi.is", "enabled": False, "order": 2},
                {"id": "ipwho.is", "enabled": False, "order": 3},
                {"id": "ipapi.org", "enabled": False, "order": 4},
                {"id": "ipinfo.io", "enabled": False, "order": 5},
                {"id": "ipdata.co", "enabled": False, "order": 6},
            ]
        },
    )

    with respx.mock(assert_all_called=True) as router:
        router.get("http://ip-api.com/json/8.8.8.8").respond(200, json={"status": "success", "query": "8.8.8.8", "country": "United States"})
        response = client.get("/api/admin/provider-health?ip=8.8.8.8")

    assert response.status_code == 200
    item = next(item for item in response.json()["providers"] if item["id"] == "ip-api.com")
    assert item["checked_at"].startswith("20")
    assert item["latency_ms"] >= 0
    assert item["http_status"] == 200
    assert item["last_success"] is True


def test_admin_provider_config_import_preview_reports_diff_without_writing(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()

    response = client.post(
        "/api/admin/provider-config/import/preview",
        json={"config": {"providers": [{"id": "ipwho.is", "enabled": False, "order": 1}]}},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["diff"]["providers"]["changed"] == ["ipwho.is"]
    assert body["will_write"] is False
    assert config_path.exists() is False


def test_admin_page_exposes_enhanced_admin_tools_and_e2e_hooks():
    body = admin_client().get("/admin").text

    assert "data-admin-api-key-manager" in body
    assert "/api/admin/api-keys" in body
    assert "data-runtime-status-panel" in body
    assert "/api/admin/runtime-status" in body
    assert "data-clear-runtime-cache" in body
    assert "data-health-latency" in body
    assert "data-health-http-status" in body
    assert "data-import-preview" in body
    assert "/api/admin/provider-config/import/preview" in body
    assert "data-json-tree-picker" in body
    assert "data-e2e-admin-login" in body
    assert "data-e2e-save-provider-config" in body
    assert "data-e2e-save-runtime-settings" in body
    assert "data-e2e-custom-provider-preview" in body


def test_admin_runtime_settings_defaults_and_persistence(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()

    defaults = client.get("/api/admin/runtime-settings")

    assert defaults.status_code == 200
    assert defaults.json() == {
        "cache": {"ip_enabled": True, "ip_ttl_seconds": 120, "ip_cache_granularity": "ipv4_24", "bgp_enabled": True, "bgp_ttl_seconds": 300},
        "rate_limit": {"ip_enabled": True, "ip_per_minute": 60, "bgp_enabled": False, "bgp_per_minute": 60},
        "dns": {
            "system_dns_enabled": False,
            "doh_enabled": True,
            "doh_providers": ["cloudflare", "google", "quad9"],
            "timeout_seconds": 5.0,
            "ip_version_preference": "ipv4_first",
        },
        "bgp": {
            "enabled": True,
            "default_upstream_limit": 20,
            "max_upstream_limit": 50,
            "show_tier1": True,
            "show_edge_state": True,
            "cache_ttl_seconds": 300,
        },
    }

    saved = client.put(
        "/api/admin/runtime-settings",
        json={
            "cache": {"ip_enabled": False, "ip_ttl_seconds": 30, "ip_cache_granularity": "single_ip", "bgp_enabled": True, "bgp_ttl_seconds": 900},
            "rate_limit": {"ip_enabled": True, "ip_per_minute": 120, "bgp_enabled": True, "bgp_per_minute": 30},
            "dns": {
                "system_dns_enabled": True,
                "doh_enabled": True,
                "doh_providers": ["quad9", "cloudflare"],
                "timeout_seconds": 2.5,
                "ip_version_preference": "ipv6_first",
            },
            "bgp": {
                "enabled": True,
                "default_upstream_limit": 15,
                "max_upstream_limit": 40,
                "show_tier1": False,
                "show_edge_state": False,
                "cache_ttl_seconds": 900,
            },
        },
    )

    assert saved.status_code == 200
    body = saved.json()
    assert body["cache"]["ip_enabled"] is False
    assert body["rate_limit"]["bgp_enabled"] is True
    assert body["dns"]["doh_providers"] == ["quad9", "cloudflare"]
    assert body["dns"]["ip_version_preference"] == "ipv6_first"
    assert body["bgp"]["max_upstream_limit"] == 40
    assert client.get("/api/admin/provider-config").json()["runtime_settings"] == body


def test_admin_runtime_settings_reject_invalid_values(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()

    response = client.put(
        "/api/admin/runtime-settings",
        json={
            "cache": {"ip_ttl_seconds": 0},
            "dns": {"doh_providers": ["cloudflare", "unknown"], "ip_version_preference": "ipv10"},
        },
    )

    assert response.status_code == 422


def test_admin_providers_api_describes_provider_order_keys_and_fields():
    client = admin_client()

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
    client = admin_client()
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
    client = admin_client()

    response = client.get("/api/admin/fields")

    assert response.status_code == 200
    fields = {field["field"]: field for field in response.json()}
    assert fields["network_type"]["scoring"] is True
    assert fields["network_type"]["source_type"] == "provider_structured"
    assert fields["network_type"]["providers"]["ipapi.is"] == ["company.type", "asn.type"]
    assert fields["network_type"]["provider_mappings"][0] == {"provider": "ipapi.is", "paths": ["company.type", "asn.type"], "priority": 1}
    assert fields["network_type"]["provider_mappings"][1]["provider"] == "ipwho.is"
    assert fields["network_type"]["provider_priority"][:2] == ["ipapi.is", "ipwho.is"]
    assert fields["network_type"]["scoring_details"]["participates"] is True
    assert fields["network_type"]["scoring_details"]["signals"] == ["ip_property", "risk_confidence", "humanbot_confidence"]
    assert fields["network_type"]["display_name"] == "network_type"
    assert fields["network_type"]["mapping_source"] == "default"
    assert fields["network_type"]["providers"]["ipwho.is"] == [
        "connection.type",
        "connection.connection_type",
    ]
    assert fields["isp"]["scoring"] is False
    assert fields["isp"]["source_type"] == "identity_text"
    assert fields["isp"]["used_for"] == ["display", "compatibility"]
    assert fields["isp"]["scoring_details"]["participates"] is False
    assert fields["isp"]["provider_priority"] == ["ipapi.is", "ipwho.is", "ipinfo.io", "ipdata.co", "ip-api.com", "ipapi.org"]
    assert fields["asn_owner"]["providers"]["ipapi.is"] == ["asn.org"]
    assert fields["asn_owner"]["providers"]["ipinfo.io"] == ["asn.name", "asn_name", "as_name"]
    assert fields["asn_owner"]["providers"]["ipwho.is"] == ["connection.isp"]
    assert fields["asn_owner"]["provider_priority"][:3] == ["ipapi.is", "ipinfo.io", "ipdata.co"]
    assert fields["org"]["providers"]["ipapi.is"] == ["company.name"]
    assert fields["org"]["providers"]["ipinfo.io"] == ["hostname"]
    assert fields["org"]["providers"]["ipwho.is"] == ["connection.org"]
    assert fields["ip_source"]["scoring_details"]["rule"] == "比较注册归属地 reg_region 与实际出口 country_code/country"
    assert fields["is_hosting"]["scoring"] is True


def test_admin_field_mappings_api_persists_provider_paths_and_priority(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()

    saved = client.put(
        "/api/admin/field-mappings",
        json={
            "network_type": {
                "providers": {
                    "ipwho.is": ["connection.connection_type"],
                    "ipapi.is": ["asn.type"],
                },
                "provider_priority": ["ipwho.is", "ipapi.is"],
            },
            "asn_owner": {
                "providers": {"ipinfo.io": ["asn.name"], "ipapi.is": ["asn.org"]},
                "provider_priority": ["ipinfo.io", "ipapi.is"],
            },
        },
    )

    assert saved.status_code == 200
    assert saved.json()["network_type"]["provider_priority"] == ["ipwho.is", "ipapi.is"]
    fields = {field["field"]: field for field in client.get("/api/admin/fields").json()}
    assert fields["network_type"]["providers"] == {
        "ipwho.is": ["connection.connection_type"],
        "ipapi.is": ["asn.type"],
    }
    assert fields["network_type"]["provider_mappings"] == [
        {"provider": "ipwho.is", "paths": ["connection.connection_type"], "priority": 1},
        {"provider": "ipapi.is", "paths": ["asn.type"], "priority": 2},
    ]
    assert fields["network_type"]["mapping_source"] == "admin"
    assert client.get("/api/admin/provider-config").json()["field_mappings"]["asn_owner"]["provider_priority"] == ["ipinfo.io", "ipapi.is"]


def test_admin_field_mappings_api_rejects_unknown_fields_and_providers(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()

    response = client.put(
        "/api/admin/field-mappings",
        json={"unknown_field": {"providers": {"ipapi.is": ["asn.type"]}}},
    )
    assert response.status_code == 422

    response = client.put(
        "/api/admin/field-mappings",
        json={"network_type": {"providers": {"unknown-provider": ["asn.type"]}}},
    )
    assert response.status_code == 422


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
    client = admin_client()

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
    client = admin_client()
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
    client = admin_client()
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
    client = admin_client()

    response = client.get("/api/admin/lookup", params={"target": "=bad"})

    assert response.status_code == 422


def test_admin_lookup_uses_enabled_provider_order_from_config(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
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
    client = admin_client()
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
    client = admin_client()
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
    client = admin_client()
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
    client = admin_client()
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
    client = admin_client()
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


def test_public_lookup_skips_unverified_custom_provider_when_strict_preview_guard_enabled(tmp_path, monkeypatch):
    from app.api.ip import clear_ip_lookup_cache

    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    clear_ip_lookup_cache()
    client.post(
        "/api/admin/custom-providers",
        json={
            "id": "unverified-public-provider",
            "name": "Unverified Public Provider",
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
            "public_custom_providers_enabled": True,
            "require_custom_provider_preview_ok": True,
            "providers": [
                {"id": "ipapi.is", "enabled": False, "order": 99},
                {"id": "ipwho.is", "enabled": False, "order": 99},
                {"id": "ip-api.com", "enabled": False, "order": 99},
                {"id": "ipapi.org", "enabled": False, "order": 99},
                {"id": "ipinfo.io", "enabled": False, "order": 99},
                {"id": "ipdata.co", "enabled": False, "order": 99},
                {"id": "unverified-public-provider", "enabled": True, "order": 1},
            ],
            "custom_providers": client.get("/api/admin/provider-config").json()["custom_providers"],
        },
    )

    with respx.mock(assert_all_called=False) as router:
        route = router.get("https://api.example.com/ip/8.8.8.8").respond(200, json={"country": "United States"})
        response = client.get("/api/ip?8.8.8.8")

    assert response.status_code == 502
    assert route.called is False


def test_public_lookup_executes_verified_custom_provider_with_strict_preview_guard_enabled(tmp_path, monkeypatch):
    from app.api.ip import clear_ip_lookup_cache

    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    clear_ip_lookup_cache()
    client.put(
        "/api/admin/provider-config",
        json={
            "public_custom_providers_enabled": True,
            "require_custom_provider_preview_ok": True,
            "providers": [
                {"id": "ipapi.is", "enabled": False, "order": 99},
                {"id": "ipwho.is", "enabled": False, "order": 99},
                {"id": "ip-api.com", "enabled": False, "order": 99},
                {"id": "ipapi.org", "enabled": False, "order": 99},
                {"id": "ipinfo.io", "enabled": False, "order": 99},
                {"id": "ipdata.co", "enabled": False, "order": 99},
                {"id": "verified-public-provider", "enabled": True, "order": 1},
            ],
            "custom_providers": [
                {
                    "id": "verified-public-provider",
                    "name": "Verified Public Provider",
                    "endpoint": "https://api.example.com/ip/{ip}",
                    "provides": ["country"],
                    "field_paths": {"country": ["country"]},
                    "last_preview": {
                        "status": "ok",
                        "ip": "8.8.8.8",
                        "checked_at": "2026-05-17T00:00:00+00:00",
                        "normalized_fields": ["country"],
                        "missing_fields": [],
                    },
                }
            ],
        },
    )

    with respx.mock(assert_all_called=True) as router:
        router.get("https://api.example.com/ip/8.8.8.8").respond(200, json={"country": "United States"})
        response = client.get("/api/ip?8.8.8.8")

    assert response.status_code == 200
    assert response.json()["geo_provider"] == "verified-public-provider"


def test_admin_provider_config_export_and_import_round_trip_redacted(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    saved = client.post(
        "/api/admin/custom-providers",
        json={
            "id": "export-provider",
            "name": "Export Provider",
            "endpoint": "https://api.example.com/ip/{ip}",
            "provides": ["country"],
            "field_paths": {"country": ["country"]},
            "auth": {"type": "api_key", "name": "x-api-key", "value": "secret-for-export"},
        },
    )
    assert saved.status_code == 200

    exported = client.get("/api/admin/provider-config/export")

    assert exported.status_code == 200
    body = exported.json()
    assert body["kind"] == "myip-py-admin-provider-config"
    assert body["config"]["custom_providers"][0]["auth"] == {"type": "api_key", "name": "x-api-key", "configured": True}
    assert "secret-for-export" not in str(body)

    reset = client.post("/api/admin/provider-config/reset")
    assert reset.status_code == 200
    imported = client.post("/api/admin/provider-config/import", json={"config": body["config"]})

    assert imported.status_code == 200
    assert imported.json()["custom_providers"][0]["id"] == "export-provider"
    assert imported.json()["custom_providers"][0]["auth"]["configured"] is False


def test_admin_provider_config_import_rejects_invalid_payload(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", tmp_path / "provider-config.json")
    client = admin_client()

    response = client.post("/api/admin/provider-config/import", json={"config": {"providers": [{"id": "missing-provider"}]}})

    assert response.status_code == 422


def test_custom_provider_auth_is_used_for_preview_and_redacted_from_admin_payloads(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()

    created = client.post(
        "/api/admin/custom-providers",
        json={
            "id": "auth-provider",
            "name": "Auth Provider",
            "endpoint": "https://api.example.com/ip/{ip}",
            "provides": ["country"],
            "field_paths": {"country": ["country"]},
            "auth": {"type": "bearer_token", "name": "Authorization", "value": "secret-token"},
        },
    )
    assert created.status_code == 200

    with respx.mock(assert_all_called=True) as router:
        route = router.get("https://api.example.com/ip/8.8.8.8").respond(200, json={"country": "United States"})
        response = client.post(
            "/api/admin/custom-providers/preview",
            json={"ip": "8.8.8.8", "provider_id": "auth-provider"},
        )

    assert response.status_code == 200
    assert route.calls[0].request.headers["authorization"] == "Bearer secret-token"
    provider_config = client.get("/api/admin/provider-config").json()["custom_providers"][0]
    provider_catalog = next(provider for provider in client.get("/api/admin/providers").json() if provider["id"] == "auth-provider")
    assert provider_config["auth"] == {"type": "bearer_token", "name": "Authorization", "configured": True}
    assert "secret-token" not in str(provider_config)
    assert provider_catalog["auth"] == {"type": "bearer_token", "name": "Authorization", "configured": True}


def test_custom_provider_api_key_auth_uses_named_header_without_leaking_secret(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()

    response = client.post(
        "/api/admin/custom-providers",
        json={
            "id": "api-key-provider",
            "name": "API Key Provider",
            "endpoint": "https://api.example.com/ip/{ip}",
            "provides": ["country"],
            "field_paths": {"country": ["country"]},
            "auth": {"type": "api_key", "name": "x-api-key", "value": "api-secret"},
        },
    )
    assert response.status_code == 200

    with respx.mock(assert_all_called=True) as router:
        route = router.get("https://api.example.com/ip/8.8.8.8").respond(200, json={"country": "United States"})
        preview = client.post("/api/admin/custom-providers/preview", json={"ip": "8.8.8.8", "provider_id": "api-key-provider"})

    assert preview.status_code == 200
    assert route.calls[0].request.headers["x-api-key"] == "api-secret"
    assert "api-secret" not in str(client.get("/api/admin/provider-config").json())


def test_admin_provider_health_reports_enabled_provider_status(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    client.put(
        "/api/admin/provider-config",
        json={
            "providers": [
                {"id": "ip-api.com", "enabled": True, "order": 1, "timeout_seconds": 1.0},
                {"id": "ipapi.is", "enabled": False, "order": 2},
                {"id": "ipwho.is", "enabled": False, "order": 3},
                {"id": "ipapi.org", "enabled": False, "order": 4},
                {"id": "ipinfo.io", "enabled": False, "order": 5},
                {"id": "ipdata.co", "enabled": False, "order": 6},
            ]
        },
    )

    with respx.mock(assert_all_called=True) as router:
        router.get("http://ip-api.com/json/8.8.8.8").respond(200, json={"status": "success", "query": "8.8.8.8", "country": "United States"})
        response = client.get("/api/admin/provider-health?ip=8.8.8.8")

    assert response.status_code == 200
    body = response.json()
    assert body["checked_ip"] == "8.8.8.8"
    assert body["summary"] == {"ok": 1, "error": 0, "disabled": 5}
    ip_api = next(item for item in body["providers"] if item["id"] == "ip-api.com")
    assert ip_api["status"] == "ok"
    assert ip_api["enabled"] is True
    assert ip_api["fields"]
    ipwho = next(item for item in body["providers"] if item["id"] == "ipwho.is")
    assert ipwho["status"] == "disabled"


def test_admin_provider_health_records_provider_error_without_raising(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    client.put(
        "/api/admin/provider-config",
        json={
            "providers": [
                {"id": "ip-api.com", "enabled": True, "order": 1, "timeout_seconds": 1.0},
                {"id": "ipapi.is", "enabled": False, "order": 2},
                {"id": "ipwho.is", "enabled": False, "order": 3},
                {"id": "ipapi.org", "enabled": False, "order": 4},
                {"id": "ipinfo.io", "enabled": False, "order": 5},
                {"id": "ipdata.co", "enabled": False, "order": 6},
            ]
        },
    )

    with respx.mock(assert_all_called=True) as router:
        router.get("http://ip-api.com/json/8.8.8.8").respond(500, json={"status": "fail"})
        response = client.get("/api/admin/provider-health?ip=8.8.8.8")

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["error"] == 1
    item = next(item for item in body["providers"] if item["id"] == "ip-api.com")
    assert item["status"] == "error"
    assert item["error"]


def test_admin_custom_provider_preview_fetches_json_and_extracts_mapped_fields(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
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


def test_admin_custom_provider_preview_can_apply_extracted_paths_to_field_mappings(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    client.post(
        "/api/admin/custom-providers",
        json={
            "id": "mapping-provider",
            "name": "Mapping Provider",
            "endpoint": "https://api.example.com/ip/{ip}",
            "provides": ["asn_owner", "org", "is_proxy"],
            "field_paths": {
                "asn_owner": ["asn.name"],
                "org": ["company.name"],
                "is_proxy": ["risk.proxy"],
            },
            "transforms": {"is_proxy": "bool"},
        },
    )

    with respx.mock(assert_all_called=True) as router:
        router.get("https://api.example.com/ip/8.8.8.8").respond(
            200,
            json={"asn": {"name": "Example ASN"}, "company": {"name": "Example Inc"}, "risk": {"proxy": "false"}},
        )
        response = client.post(
            "/api/admin/custom-providers/preview",
            json={"ip": "8.8.8.8", "provider_id": "mapping-provider", "apply_field_mappings": True},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["applied_field_mappings"] == {
        "asn_owner": {"provider": "mapping-provider", "paths": ["asn.name"]},
        "is_proxy": {"provider": "mapping-provider", "paths": ["risk.proxy"]},
        "org": {"provider": "mapping-provider", "paths": ["company.name"]},
    }
    fields = {field["field"]: field for field in client.get("/api/admin/fields").json()}
    assert fields["asn_owner"]["mapping_source"] == "admin"
    assert fields["asn_owner"]["provider_mappings"][0] == {
        "provider": "mapping-provider",
        "paths": ["asn.name"],
        "priority": 1,
    }
    assert fields["org"]["provider_mappings"][0]["provider"] == "mapping-provider"
    assert fields["is_proxy"]["provider_mappings"][0]["provider"] == "mapping-provider"


def test_admin_custom_provider_preview_records_failure_for_saved_provider(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
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
    client = admin_client()

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
    client = admin_client()

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
    client = admin_client()

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
    client = admin_client()

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
    client = admin_client()

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
    client = admin_client()
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
    client = admin_client()
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
    client = admin_client()

    response = client.post(
        "/api/admin/custom-providers",
        json={"id": "ipapi.is", "name": "Conflict", "endpoint": "https://api.example.com/{ip}", "provides": []},
    )

    assert response.status_code == 422


def test_admin_custom_field_api_persists_metadata_and_merges_field_list(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
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
    client = admin_client()
    client.post("/api/admin/custom-fields", json={"field": "delete_field", "label": "Delete field", "type": "string"})

    response = client.delete("/api/admin/custom-fields/delete_field")

    assert response.status_code == 200
    assert response.json()["custom_fields"] == []
    assert "delete_field" not in {field["field"] for field in client.get("/api/admin/fields").json()}


def test_admin_custom_field_api_rejects_builtin_conflict(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", tmp_path / "provider-config.json")
    client = admin_client()

    response = client.post("/api/admin/custom-fields", json={"field": "network_type", "label": "Conflict", "type": "string"})

    assert response.status_code == 422


def test_admin_provider_config_api_reads_defaults_without_creating_file(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()

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
    assert body["require_custom_provider_preview_ok"] is False
    assert not config_path.exists()


def test_admin_provider_config_api_persists_safe_overrides(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
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
        "require_custom_provider_preview_ok": True,
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
    assert body["require_custom_provider_preview_ok"] is True
    assert "key" not in config_path.read_text(encoding="utf-8").lower()


def test_admin_provider_config_api_rejects_unknown_provider(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", tmp_path / "provider-config.json")
    client = admin_client()

    response = client.put(
        "/api/admin/provider-config",
        json={"providers": [{"id": "unknown", "enabled": True, "order": 1}]},
    )

    assert response.status_code == 422


def test_admin_provider_config_api_rejects_strict_preview_without_public_custom_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", tmp_path / "provider-config.json")
    client = admin_client()

    response = client.put(
        "/api/admin/provider-config",
        json={"require_custom_provider_preview_ok": True, "public_custom_providers_enabled": False},
    )

    assert response.status_code == 422
    assert "public custom providers" in response.json()["detail"]


def test_admin_config_status_reports_default_public_lookup_mode(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()

    response = client.get("/api/admin/config-status")

    assert response.status_code == 200
    body = response.json()
    assert body["public_lookup_mode"] == "default-production-chain"
    assert body["uses_admin_provider_config"] is False
    assert body["provider_config_exists"] is False
    assert body["public_custom_providers_enabled"] is False
    assert body["require_custom_provider_preview_ok"] is False
    assert body["public_custom_provider_warnings"] == []
    assert body["storage_path"] == str(config_path)
    assert body["warning"] is None


def test_admin_config_status_reports_admin_config_public_lookup_mode(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    client.put("/api/admin/provider-config", json={"providers": [{"id": "ip-api.com", "enabled": True, "order": 1}]})

    response = client.get("/api/admin/config-status")

    assert response.status_code == 200
    body = response.json()
    assert body["public_lookup_mode"] == "admin-config-chain"
    assert body["uses_admin_provider_config"] is True
    assert body["provider_config_exists"] is True
    assert body["public_custom_providers_enabled"] is False
    assert body["require_custom_provider_preview_ok"] is False
    assert body["public_custom_provider_warnings"] == []
    assert body["warning"] == "保存的后台 Provider 配置正在影响公开 /api/ip"


def test_admin_config_status_warns_when_public_custom_providers_enabled(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    client.put(
        "/api/admin/provider-config",
        json={"providers": [{"id": "ip-api.com", "enabled": True, "order": 1}], "public_custom_providers_enabled": True},
    )

    response = client.get("/api/admin/config-status")

    assert response.status_code == 200
    body = response.json()
    assert body["public_custom_providers_enabled"] is True
    assert body["require_custom_provider_preview_ok"] is False
    assert body["public_custom_provider_warnings"] == []
    assert body["warning"] == "保存的后台 Provider 配置正在影响公开 /api/ip，且公开接口允许自定义 Provider"


def test_admin_config_status_warns_about_enabled_unverified_public_custom_provider(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    client.post(
        "/api/admin/custom-providers",
        json={
            "id": "unverified-provider",
            "name": "Unverified Provider",
            "endpoint": "https://api.example.com/ip/{ip}",
            "provides": ["country"],
            "field_paths": {"country": ["country"]},
        },
    )
    client.put(
        "/api/admin/provider-config",
        json={
            "public_custom_providers_enabled": True,
            "providers": [{"id": "unverified-provider", "enabled": True, "order": 1}],
            "custom_providers": client.get("/api/admin/provider-config").json()["custom_providers"],
        },
    )

    response = client.get("/api/admin/config-status")

    assert response.status_code == 200
    body = response.json()
    assert body["public_custom_provider_warnings"] == ["unverified-provider 最近未验证"]
    assert body["warning"] == "保存的后台 Provider 配置正在影响公开 /api/ip，且公开接口允许自定义 Provider；公开自定义 Provider 存在验证风险"


def test_admin_config_status_warns_about_enabled_failed_public_custom_provider(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    client.put(
        "/api/admin/provider-config",
        json={
            "public_custom_providers_enabled": True,
            "providers": [{"id": "failed-provider", "enabled": True, "order": 1}],
            "custom_providers": [
                {
                    "id": "failed-provider",
                    "name": "Failed Provider",
                    "endpoint": "https://api.example.com/ip/{ip}",
                    "provides": ["country"],
                    "field_paths": {"country": ["country"]},
                    "last_preview": {
                        "status": "error",
                        "ip": "8.8.8.8",
                        "checked_at": "2026-05-17T00:00:00+00:00",
                        "normalized_fields": [],
                        "missing_fields": ["country"],
                        "error": "custom provider request failed",
                    },
                }
            ],
        },
    )

    response = client.get("/api/admin/config-status")

    assert response.status_code == 200
    body = response.json()
    assert body["public_custom_provider_warnings"] == ["failed-provider 最近验证失败"]
    assert "公开自定义 Provider 存在验证风险" in body["warning"]

def test_admin_provider_config_reset_removes_saved_file(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    config_path.write_text('{"version": 1, "providers": []}', encoding="utf-8")
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()

    response = client.post("/api/admin/provider-config/reset")

    assert response.status_code == 200
    body = response.json()
    assert body["exists"] is False
    assert not config_path.exists()

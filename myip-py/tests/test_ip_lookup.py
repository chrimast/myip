from fastapi.testclient import TestClient
import httpx
import socket

import app.api.ip as ip_api
from app.api.ip import clear_ip_lookup_cache, get_public_ip_lookup_provider
from app.main import app
from app.core.config import get_settings
from app.services.ip_lookup import (
    IPAPIIsLookupProvider,
    IPInfo,
    IPLookupUnavailable,
    StaticIPLookupProvider,
    enrich_ip_intelligence,
    get_ip_lookup_provider,
)


def setup_function() -> None:
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
        return {}

    def doh_provider_names(self):
        return ["cloudflare", "google", "quad9"]


def admin_client() -> TestClient:
    app.dependency_overrides[get_settings] = lambda: AdminAuthSettings()
    client = TestClient(app)
    assert client.post("/admin/login", data={"username": "admin", "password": "admin"}, follow_redirects=False).status_code == 303
    return client


def test_lookup_explicit_ip_returns_normalized_provider_result():
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: StaticIPLookupProvider(
        IPInfo(
            ip="8.8.8.8",
            country="United States",
            country_code="US",
            region="California",
            city="Mountain View",
            asn="AS15169",
            asn_owner="Google LLC",
            org="Google LLC",
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
        assert response.json() == {
            "ip": "8.8.8.8",
            "country": "United States",
            "country_code": "US",
            "region": "California",
            "city": "Mountain View",
            "asn": "AS15169",
            "isp": "Google LLC",
            "latitude": 37.4056,
            "longitude": -122.0775,
            "provider": "test-provider",
            "network_type": None,
            "ip_source": "原生IP",
            "ip_source_reason": "缺少注册归属地，默认按实际出口地理位置视为一致",
            "ip_property": "家庭IP",
            "ip_property_reason": "机房IP:0, 家庭IP:3, 商业IP:0",
            "ip_property_scores": {"机房IP": 0, "家庭IP": 3, "商业IP": 0},
            "risk_score": 10,
            "risk_reason": "基于代理/VPN/TOR/托管网络/爬虫/滥用信号与注册地差异综合评估",
            "risk_breakdown": {"base": 10},
            "risk_confidence": 0.45,
            "human_percent": 98.0,
            "bot_percent": 2.0,
            "humanbot_reason": "基于 IP 属性和风险信号估算人机流量比例",
            "humanbot_breakdown": {"human": 98.0, "bot": 2.0},
            "humanbot_confidence": 0.4,
            "is_proxy": False,
            "is_vpn": False,
            "is_tor": False,
            "is_mobile": False,
            "is_hosting": False,
            "is_crawler": False,
            "is_abuser": False,
            "input": "8.8.8.8",
            "resolved_ip": "8.8.8.8",
            "resolved_ips": ["8.8.8.8"],
            "dns_provider": None,
            "geo_provider": "test-provider",
            "query": "8.8.8.8",
            "countryCode": "US",
            "regionName": "California",
            "lat": 37.4056,
            "lon": -122.0775,
            "org": "Google LLC",
            "as": "AS15169 Google LLC",
            "asn_owner": "Google LLC",
            "asn_domain": "",
            "org_domain": "",
            "registry": "",
            "reg_region": "US",
            "proxy": False,
            "hosting": False,
            "mobile": False,
            "status": "success",
        }
    finally:
        app.dependency_overrides.clear()


def test_lookup_uses_saved_admin_provider_order_when_config_exists(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    client.put(
        "/api/admin/provider-config",
        json={
            "providers": [
                {"id": "ipapi.is", "enabled": False, "order": 99},
                {"id": "ipwho.is", "enabled": False, "order": 99},
                {"id": "ip-api.com", "enabled": True, "order": 1, "timeout_seconds": 1.5},
                {"id": "ipapi.org", "enabled": False, "order": 99},
                {"id": "ipinfo.io", "enabled": False, "order": 99},
                {"id": "ipdata.co", "enabled": False, "order": 99},
            ]
        },
    )
    calls: list[tuple[str, dict[str, str] | None, float]] = []

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "status": "success",
                "query": "8.8.8.8",
                "country": "United States",
                "countryCode": "US",
                "regionName": "California",
                "city": "Mountain View",
                "lat": 37.4056,
                "lon": -122.0775,
                "isp": "Google LLC",
                "org": "Google LLC",
                "as": "AS15169 Google LLC",
                "mobile": False,
                "proxy": False,
                "hosting": True,
            }

    def fake_get(url: str, *, params: dict[str, str] | None = None, timeout: float) -> FakeResponse:
        calls.append((url, params, timeout))
        return FakeResponse()

    monkeypatch.setattr(httpx, "get", fake_get)

    response = client.get("/api/ip?8.8.8.8")

    assert response.status_code == 200
    assert calls == [
        (
            "http://ip-api.com/json/8.8.8.8",
            {"fields": "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting"},
            1.5,
        )
    ]
    assert response.json()["provider"] == "ip-api.com"
    assert response.json()["hosting"] is True


def test_lookup_applies_saved_admin_field_overrides_when_config_exists(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr("app.services.admin_config.PROVIDER_CONFIG_PATH", config_path)
    client = admin_client()
    client.put(
        "/api/admin/provider-config",
        json={"field_overrides": {"network_type": {"enabled": False}, "is_hosting": {"enabled": False}}},
    )
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: StaticIPLookupProvider(
        IPInfo(
            ip="8.8.8.8",
            country="United States",
            country_code="US",
            provider="test-provider",
            network_type="hosting",
            is_hosting=True,
        )
    )
    try:
        response = client.get("/api/ip?8.8.8.8")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["network_type"] is None
    assert body["is_hosting"] is False
    assert body["hosting"] is False
    assert body["ip_property"] == "家庭IP"
    assert body["risk_breakdown"] == {"base": 10}


def test_lookup_supports_raw_ip_query_without_equals_sign():
    class EchoProvider:
        def lookup(self, ip: str) -> IPInfo:
            return IPInfo(ip=ip, country="United States", provider="test-provider")

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: EchoProvider()
    try:
        client = TestClient(app, client=("203.0.113.9", 54321))

        response = client.get("/api/ip?8.8.8.8")

        assert response.status_code == 200
        assert response.json()["ip"] == "8.8.8.8"
    finally:
        app.dependency_overrides.clear()


def test_lookup_without_ip_uses_request_client_host():
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: StaticIPLookupProvider(
        IPInfo(ip="203.0.113.9", country="Exampleland", provider="test-provider")
    )
    try:
        client = TestClient(app, client=("203.0.113.9", 54321))

        response = client.get("/api/ip")

        assert response.status_code == 200
        assert response.json()["ip"] == "203.0.113.9"
        assert response.json()["country"] == "Exampleland"
    finally:
        app.dependency_overrides.clear()




def test_lookup_without_ip_prefers_forwarded_headers_and_falls_back_to_server_public_ip(monkeypatch):
    calls: list[str] = []

    class EchoProvider:
        def lookup(self, ip: str) -> IPInfo:
            calls.append(ip)
            return IPInfo(ip=ip, country="Exampleland", provider="test-provider")

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: EchoProvider()
    try:
        client = TestClient(app, client=("127.0.0.1", 54321))

        forwarded = client.get("/api/ip", headers={"X-Forwarded-For": "8.8.4.4, 10.0.0.1"})
        real_ip = client.get("/api/ip", headers={"X-Real-IP": "1.1.1.1"})

        class FakeResponse:
            def raise_for_status(self) -> None:
                return None

            @property
            def text(self) -> str:
                return "9.9.9.9"

        monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: FakeResponse())
        fallback = client.get("/api/ip")

        assert forwarded.status_code == 200
        assert real_ip.status_code == 200
        assert fallback.status_code == 200
        assert calls == ["8.8.4.4", "1.1.1.1", "9.9.9.9"]
    finally:
        app.dependency_overrides.clear()

def test_lookup_domain_response_includes_resolution_metadata(monkeypatch):
    class FakeDNSResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "Status": 0,
                "Answer": [
                    {"type": 1, "data": "93.184.216.34"},
                    {"type": 28, "data": "2606:2800:220:1:248:1893:25c8:1946"},
                ],
            }

    def fail_getaddrinfo(host: str, port: int | None, *, type: int = 0) -> list[tuple]:
        raise AssertionError("system DNS should not be called")

    class EchoProvider:
        def lookup(self, ip: str) -> IPInfo:
            return IPInfo(ip=ip, country="United States", provider="test-provider")

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)
    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: FakeDNSResponse())
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: EchoProvider()
    try:
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/api/ip?example.com")

        assert response.status_code == 200
        assert response.json()["input"] == "example.com"
        assert response.json()["resolved_ip"] == "93.184.216.34"
        assert response.json()["resolved_ips"] == [
            "93.184.216.34",
            "2606:2800:220:1:248:1893:25c8:1946",
        ]
        assert response.json()["dns_provider"] == "cloudflare"
        assert response.json()["geo_provider"] == "test-provider"
    finally:
        app.dependency_overrides.clear()


def test_lookup_resolves_keyless_domain_before_calling_provider(monkeypatch):
    calls: list[str] = []

    class FakeDNSResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34"}]}

    def fail_getaddrinfo(host: str, port: int | None, *, type: int = 0) -> list[tuple]:
        raise AssertionError("system DNS should not be called")

    class EchoProvider:
        def lookup(self, ip: str) -> IPInfo:
            calls.append(ip)
            return IPInfo(ip=ip, country="United States", provider="test-provider")

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)
    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: FakeDNSResponse())
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: EchoProvider()
    try:
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/api/ip?example.com")

        assert response.status_code == 200
        assert response.json()["ip"] == "93.184.216.34"
        assert calls == ["93.184.216.34"]
    finally:
        app.dependency_overrides.clear()


def test_lookup_resolves_raw_domain_without_equals_before_calling_provider(monkeypatch):
    calls: list[str] = []

    class FakeDNSResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"Status": 0, "Answer": [{"type": 28, "data": "2606:2800:220:1:248:1893:25c8:1946"}]}

    def fail_getaddrinfo(host: str, port: int | None, *, type: int = 0) -> list[tuple]:
        raise AssertionError("system DNS should not be called")

    class EchoProvider:
        def lookup(self, ip: str) -> IPInfo:
            calls.append(ip)
            return IPInfo(ip=ip, country="United States", provider="test-provider")

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)
    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: FakeDNSResponse())
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: EchoProvider()
    try:
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/api/ip?example.com")

        assert response.status_code == 200
        assert response.json()["ip"] == "2606:2800:220:1:248:1893:25c8:1946"
        assert calls == ["2606:2800:220:1:248:1893:25c8:1946"]
    finally:
        app.dependency_overrides.clear()


def test_lookup_returns_502_when_dns_resolvers_are_unavailable(monkeypatch):
    def timeout_getaddrinfo(host: str, port: int | None, *, type: int = 0) -> list[tuple]:
        raise socket.timeout()

    def fail_doh(*args: object, **kwargs: object) -> object:
        raise httpx.ConnectError("DoH unavailable")

    monkeypatch.setattr(socket, "getaddrinfo", timeout_getaddrinfo)
    monkeypatch.setattr(httpx, "get", fail_doh)
    try:
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/api/ip?example.com")

        assert response.status_code == 502
        assert response.json() == {"detail": "DNS resolvers are temporarily unavailable"}
    finally:
        app.dependency_overrides.clear()



def test_lookup_rejects_keyless_equals_query_before_calling_provider():
    class FailingProvider:
        def lookup(self, ip: str) -> IPInfo:
            raise AssertionError("provider should not be called for removed keyless-equals query")

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: FailingProvider()
    try:
        client = TestClient(app, raise_server_exceptions=False)

        for url in ("/api/ip?=8.8.8.8", "/api/ip?=example.com"):
            response = client.get(url)

            assert response.status_code == 422
            assert response.json()["detail"][0]["loc"][:2] == ["query", "ip"]
    finally:
        app.dependency_overrides.clear()

def test_lookup_rejects_invalid_keyless_queries_before_calling_provider():
    class FailingProvider:
        def lookup(self, ip: str) -> IPInfo:
            raise AssertionError("provider should not be called for invalid IP")

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: FailingProvider()
    try:
        client = TestClient(app, raise_server_exceptions=False)

        for url in ("/api/ip?not-an-ip",):
            response = client.get(url)

            assert response.status_code == 422
            assert response.json()["detail"][0]["loc"][:2] == ["query", "ip"]
    finally:
        app.dependency_overrides.clear()


def test_lookup_rejects_invalid_raw_ip_query_before_calling_provider():
    class FailingProvider:
        def lookup(self, ip: str) -> IPInfo:
            raise AssertionError("provider should not be called for invalid raw IP")

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: FailingProvider()
    try:
        client = TestClient(app, client=("203.0.113.9", 54321), raise_server_exceptions=False)

        response = client.get("/api/ip?not-an-ip")

        assert response.status_code == 422
        assert response.json()["detail"][0]["loc"][:2] == ["query", "ip"]
    finally:
        app.dependency_overrides.clear()


def test_lookup_private_ip_returns_local_result_without_calling_provider():
    class FailingProvider:
        def lookup(self, ip: str) -> IPInfo:
            raise AssertionError("provider should not be called for private IP")

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: FailingProvider()
    try:
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/api/ip?192.168.1.1")

        assert response.status_code == 200
        assert response.json() == {
            "ip": "192.168.1.1",
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "asn": None,
            "isp": "Private network",
            "latitude": None,
            "longitude": None,
            "provider": "local",
            "network_type": None,
            "ip_source": "原生IP",
            "ip_source_reason": "缺少注册归属地，默认按实际出口地理位置视为一致",
            "ip_property": "家庭IP",
            "ip_property_reason": "机房IP:0, 家庭IP:3, 商业IP:0",
            "ip_property_scores": {"机房IP": 0, "家庭IP": 3, "商业IP": 0},
            "risk_score": 10,
            "risk_reason": "基于代理/VPN/TOR/托管网络/爬虫/滥用信号与注册地差异综合评估",
            "risk_breakdown": {"base": 10},
            "risk_confidence": 0.45,
            "human_percent": 98.0,
            "bot_percent": 2.0,
            "humanbot_reason": "基于 IP 属性和风险信号估算人机流量比例",
            "humanbot_breakdown": {"human": 98.0, "bot": 2.0},
            "humanbot_confidence": 0.4,
            "is_proxy": False,
            "is_vpn": False,
            "is_tor": False,
            "is_mobile": False,
            "is_hosting": False,
            "is_crawler": False,
            "is_abuser": False,
            "input": "192.168.1.1",
            "resolved_ip": "192.168.1.1",
            "resolved_ips": ["192.168.1.1"],
            "dns_provider": None,
            "geo_provider": "local",
            "query": "192.168.1.1",
            "countryCode": None,
            "regionName": None,
            "lat": None,
            "lon": None,
            "org": "Private network",
            "as": "Private network",
            "asn_owner": "Private network",
            "asn_domain": "",
            "org_domain": "",
            "registry": "",
            "reg_region": "",
            "proxy": False,
            "hosting": False,
            "mobile": False,
            "status": "success",
        }
    finally:
        app.dependency_overrides.clear()


def test_lookup_ipv6_local_ips_return_local_result_without_calling_provider():
    class FailingProvider:
        def lookup(self, ip: str) -> IPInfo:
            raise AssertionError("provider should not be called for local IPv6")

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: FailingProvider()
    try:
        client = TestClient(app, raise_server_exceptions=False)

        for ip in ("::1", "fc00::1", "fe80::1"):
            response = client.get(f"/api/ip?{ip}")

            assert response.status_code == 200
            assert response.json()["ip"] == ip
            assert response.json()["provider"] == "local"
            assert response.json()["isp"] == "Private network"
    finally:
        app.dependency_overrides.clear()


def test_lookup_ipv4_link_local_returns_local_result_without_calling_provider():
    class FailingProvider:
        def lookup(self, ip: str) -> IPInfo:
            raise AssertionError("provider should not be called for IPv4 link-local")

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: FailingProvider()
    try:
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/api/ip?169.254.1.1")

        assert response.status_code == 200
        assert response.json()["ip"] == "169.254.1.1"
        assert response.json()["provider"] == "local"
        assert response.json()["isp"] == "Private network"
    finally:
        app.dependency_overrides.clear()


def test_default_provider_queries_ipapi_is_and_maps_response(monkeypatch):
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "ip": "8.8.8.8",
                "location": {
                    "country": {"name": "United States", "code": "US"},
                    "state": "California",
                    "city": "Mountain View",
                    "latitude": 37.4056,
                    "longitude": -122.0775,
                },
                "asn": {"asn": 15169, "org": "Google LLC"},
                "company": {"name": "Google LLC"},
            }

    seen: dict[str, object] = {}

    def fake_get(url: str, *, params: dict[str, str] | None = None, timeout: float) -> FakeResponse:
        seen.setdefault("calls", []).append((url, params, timeout))
        seen["url"] = url
        seen["params"] = params
        seen["timeout"] = timeout
        if url == "https://ipinfo.io/8.8.8.8/json":
            raise httpx.HTTPStatusError(
                "server error",
                request=httpx.Request("GET", "https://example.test"),
                response=httpx.Response(503),
            )
        if url == "https://api.ipdata.co/8.8.8.8":
            raise httpx.HTTPStatusError(
                "server error",
                request=httpx.Request("GET", "https://example.test"),
                response=httpx.Response(503),
            )
        return FakeResponse()

    monkeypatch.setattr(httpx, "get", fake_get)

    client = TestClient(app)
    response = client.get("/api/ip?8.8.8.8")

    assert response.status_code == 200
    assert seen["calls"] == [
        ("https://api.ipapi.is", {"q": "8.8.8.8"}, 8.0),
        ("https://ipinfo.io/8.8.8.8/json", None, 8.0),
        ("https://api.ipdata.co/8.8.8.8", None, 8.0),
    ]
    assert response.json() == {
        "ip": "8.8.8.8",
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "Mountain View",
        "asn": "AS15169",
        "isp": "Google LLC",
        "latitude": 37.4056,
        "longitude": -122.0775,
        "provider": "ipapi.is",
        "network_type": None,
            "ip_source": "原生IP",
            "ip_source_reason": "注册归属地/注册机构与实际出口地理位置一致: 未知注册机构/US vs US",
            "ip_property": "家庭IP",
            "ip_property_reason": "机房IP:0, 家庭IP:3, 商业IP:0",
            "ip_property_scores": {"机房IP": 0, "家庭IP": 3, "商业IP": 0},
            "risk_score": 10,
            "risk_reason": "基于代理/VPN/TOR/托管网络/爬虫/滥用信号与注册地差异综合评估",
            "risk_breakdown": {"base": 10},
            "risk_confidence": 0.5,
            "human_percent": 98.0,
            "bot_percent": 2.0,
            "humanbot_reason": "基于 IP 属性和风险信号估算人机流量比例",
            "humanbot_breakdown": {"human": 98.0, "bot": 2.0},
            "humanbot_confidence": 0.4,
"is_proxy": False,
        "is_vpn": False,
        "is_tor": False,
        "is_mobile": False,
        "is_hosting": False,
        "is_crawler": False,
        "is_abuser": False,
        "input": "8.8.8.8",
        "resolved_ip": "8.8.8.8",
        "resolved_ips": ["8.8.8.8"],
        "dns_provider": None,
        "geo_provider": "ipapi.is",
        "query": "8.8.8.8",
        "countryCode": "US",
        "regionName": "California",
        "lat": 37.4056,
        "lon": -122.0775,
        "org": "Google LLC",
        "as": "AS15169 Google LLC",
        "asn_owner": "Google LLC",
        "asn_domain": "",
        "org_domain": "",
        "registry": "",
        "reg_region": "US",
        "proxy": False,
        "hosting": False,
        "mobile": False,
        "status": "success",
    }


def test_default_provider_includes_configured_api_keys(monkeypatch):
    calls: list[tuple[str, dict[str, str] | None]] = []

    class FakeResponse:
        def __init__(self, payload: dict, status_code: int = 200) -> None:
            self.payload = payload
            self.status_code = status_code

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "server error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

        def json(self) -> dict:
            return self.payload

    def fake_get(
        url: str,
        *,
        params: dict[str, str] | None = None,
        timeout: float,
    ) -> FakeResponse:
        calls.append((url, params))
        if url == "https://api.ipapi.is":
            return FakeResponse({}, status_code=503)
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse({"success": False, "message": "nope"})
        if url == "http://ip-api.com/json/8.8.8.8":
            return FakeResponse({"status": "fail", "message": "nope"})
        if url == "https://ipapi.org/api/ip/8.8.8.8":
            return FakeResponse({}, status_code=503)
        if url == "https://ipinfo.io/8.8.8.8/json":
            return FakeResponse({}, status_code=503)
        if url == "https://api.ipdata.co/8.8.8.8":
            return FakeResponse(
                {
                    "ip": "8.8.8.8",
                    "country_name": "United States",
                }
            )
        raise AssertionError(url)

    monkeypatch.setenv("IPAPI_IS_KEY", "ipapi-is-secret")
    monkeypatch.setenv("IPAPI_ORG_KEY", "ipapi-org-secret")
    monkeypatch.setenv("IPINFO_TOKEN", "ipinfo-secret")
    monkeypatch.setenv("IPDATA_KEY", "ipdata-secret")
    monkeypatch.setattr(httpx, "get", fake_get)

    provider = IPAPIIsLookupProvider()

    result = provider.lookup("8.8.8.8")

    assert result.provider == "ipdata.co"
    assert calls == [
        ("https://api.ipapi.is", {"q": "8.8.8.8", "key": "ipapi-is-secret"}),
        ("https://ipwho.is/8.8.8.8", None),
        (
            "http://ip-api.com/json/8.8.8.8",
            {"fields": "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting"},
        ),
        ("https://ipapi.org/api/ip/8.8.8.8", {"key": "ipapi-org-secret"}),
        ("https://ipinfo.io/8.8.8.8/json", {"token": "ipinfo-secret"}),
        ("https://api.ipdata.co/8.8.8.8", {"api-key": "ipdata-secret"}),
    ]


def test_ipapi_is_provider_falls_back_to_ipwho_when_primary_fails(monkeypatch):
    calls: list[tuple[str, dict[str, str] | None]] = []

    class FakeResponse:
        def __init__(self, payload: dict, status_code: int = 200) -> None:
            self.payload = payload
            self.status_code = status_code

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "server error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

        def json(self) -> dict:
            return self.payload

    def fake_get(
        url: str,
        *,
        params: dict[str, str] | None = None,
        timeout: float,
    ) -> FakeResponse:
        calls.append((url, params))
        if url == "https://api.ipapi.is":
            return FakeResponse({}, status_code=503)
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse(
                {
                    "success": True,
                    "ip": "8.8.8.8",
                    "country": "United States",
                    "country_code": "US",
                    "region": "California",
                    "city": "Mountain View",
                    "latitude": 37.4056,
                    "longitude": -122.0775,
                    "connection": {
                        "asn": 15169,
                        "isp": "Google LLC",
                        "org": "Google LLC",
                        "domain": "google.com",
                    },
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == [
        ("https://api.ipapi.is", {"q": "8.8.8.8"}),
        ("https://ipwho.is/8.8.8.8", None),
    ]
    assert result == IPInfo(
        ip="8.8.8.8",
        country="United States",
        country_code="US",
        region="California",
        city="Mountain View",
        asn="AS15169",
        asn_owner="Google LLC",
        org="Google LLC",
        isp="Google LLC",
        latitude=37.4056,
        longitude=-122.0775,
        provider="ipwho.is",
        asn_domain="google.com",
        org_domain="google.com",
        field_sources={
            "ip": "ipwho.is",
            "country": "ipwho.is",
            "country_code": "ipwho.is",
            "region": "ipwho.is",
            "city": "ipwho.is",
            "asn": "ipwho.is",
            "asn_owner": "ipwho.is",
            "org": "ipwho.is",
            "isp": "ipwho.is",
            "latitude": "ipwho.is",
            "longitude": "ipwho.is",
            "asn_domain": "ipwho.is",
            "org_domain": "ipwho.is",
        },
    )


def test_ipapi_is_provider_falls_back_to_ipwho_when_primary_omits_ip(monkeypatch):
    calls: list[tuple[str, dict[str, str] | None]] = []

    class FakeResponse:
        def __init__(self, payload: dict) -> None:
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self.payload

    def fake_get(
        url: str,
        *,
        params: dict[str, str] | None = None,
        timeout: float,
    ) -> FakeResponse:
        calls.append((url, params))
        if url == "https://api.ipapi.is":
            return FakeResponse({"location": {"country": {"name": "Unknown"}}})
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse(
                {
                    "success": True,
                    "ip": "8.8.8.8",
                    "country": "United States",
                    "country_code": "US",
                    "connection": {"asn": 15169, "isp": "Google LLC", "domain": "google.com"},
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == [
        ("https://api.ipapi.is", {"q": "8.8.8.8"}),
        ("https://ipwho.is/8.8.8.8", None),
        (
            "http://ip-api.com/json/8.8.8.8",
            {"fields": "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting"},
        ),
        ("https://ipapi.org/api/ip/8.8.8.8", None),
    ]
    assert result.provider == "ipwho.is"
    assert result.ip == "8.8.8.8"
    assert result.country == "United States"


def test_providers_reject_mismatched_response_ips_and_fallback(monkeypatch):
    calls: list[tuple[str, dict[str, str] | None]] = []

    class FakeResponse:
        def __init__(self, payload: dict) -> None:
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self.payload

    def fake_get(
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float,
    ) -> FakeResponse:
        calls.append((url, params))
        if url == "https://api.ipapi.is":
            return FakeResponse({"ip": "1.1.1.1", "country": "Wrong"})
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse({"success": True, "ip": "1.1.1.1", "country": "Wrong"})
        if url == "http://ip-api.com/json/8.8.8.8":
            return FakeResponse({"status": "success", "query": "1.1.1.1", "country": "Wrong"})
        if url in {
            "https://ipapi.org/api/ip/8.8.8.8",
            "https://ipinfo.io/8.8.8.8/json",
            "https://api.ipdata.co/8.8.8.8",
        }:
            return FakeResponse({"ip": "1.1.1.1", "country": "Wrong"})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/api/ip?8.8.8.8")

    assert response.status_code == 502
    assert response.json() == {"detail": "IP lookup providers are temporarily unavailable"}
    assert calls == [
        ("https://api.ipapi.is", {"q": "8.8.8.8"}),
        ("https://ipwho.is/8.8.8.8", None),
        (
            "http://ip-api.com/json/8.8.8.8",
            {"fields": "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting"},
        ),
        ("https://ipapi.org/api/ip/8.8.8.8", None),
        ("https://ipinfo.io/8.8.8.8/json", None),
        ("https://api.ipdata.co/8.8.8.8", None),
    ]


def test_provider_falls_back_through_ipapi_org_ipinfo_and_ipdata(monkeypatch):
    calls: list[tuple[str, dict[str, str] | None]] = []

    class FakeResponse:
        def __init__(self, payload: dict, status_code: int = 200) -> None:
            self.payload = payload
            self.status_code = status_code

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "server error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

        def json(self) -> dict:
            return self.payload

    def fake_get(
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float,
    ) -> FakeResponse:
        calls.append((url, params))
        if url == "https://api.ipapi.is":
            return FakeResponse({}, status_code=503)
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse({"success": False, "message": "rate limited"})
        if url == "http://ip-api.com/json/8.8.8.8":
            return FakeResponse({"status": "fail", "message": "reserved range"})
        if url == "https://ipapi.org/api/ip/8.8.8.8":
            return FakeResponse({"ip": "1.1.1.1", "country": "Wrong"})
        if url == "https://ipinfo.io/8.8.8.8/json":
            return FakeResponse({"ip": "1.1.1.1", "country": "Wrong"})
        if url == "https://api.ipdata.co/8.8.8.8":
            return FakeResponse(
                {
                    "ip": "8.8.8.8",
                    "country_name": "United States",
                    "country_code": "US",
                    "region": "California",
                    "city": "Mountain View",
                    "asn": {"asn": "AS15169", "name": "Google LLC", "domain": "google.com"},
                    "latitude": 37.4056,
                    "longitude": -122.0775,
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == [
        ("https://api.ipapi.is", {"q": "8.8.8.8"}),
        ("https://ipwho.is/8.8.8.8", None),
        (
            "http://ip-api.com/json/8.8.8.8",
            {"fields": "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting"},
        ),
        ("https://ipapi.org/api/ip/8.8.8.8", None),
        ("https://ipinfo.io/8.8.8.8/json", None),
        ("https://api.ipdata.co/8.8.8.8", None),
    ]
    assert result == IPInfo(
        ip="8.8.8.8",
        country="United States",
        country_code="US",
        region="California",
        city="Mountain View",
        asn="AS15169",
        asn_owner="Google LLC",
        org="Google LLC",
        isp="Google LLC",
        latitude=37.4056,
        longitude=-122.0775,
        provider="ipdata.co",
        asn_domain="google.com",
        field_sources={
            "ip": "ipdata.co",
            "country": "ipdata.co",
            "country_code": "ipdata.co",
            "region": "ipdata.co",
            "city": "ipdata.co",
            "asn": "ipdata.co",
            "asn_owner": "ipdata.co",
            "org": "ipdata.co",
            "isp": "ipdata.co",
            "latitude": "ipdata.co",
            "longitude": "ipdata.co",
            "asn_domain": "ipdata.co",
        },
    )


def test_provider_falls_back_to_ip_api_com_when_first_two_providers_fail(monkeypatch):
    calls: list[tuple[str, dict[str, str] | None]] = []

    class FakeResponse:
        def __init__(self, payload: dict, status_code: int = 200) -> None:
            self.payload = payload
            self.status_code = status_code

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "server error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

        def json(self) -> dict:
            return self.payload

    def fake_get(
        url: str,
        *,
        params: dict[str, str] | None = None,
        timeout: float,
    ) -> FakeResponse:
        calls.append((url, params))
        if url == "https://api.ipapi.is":
            return FakeResponse({}, status_code=503)
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse({"success": False, "message": "rate limited"})
        if url == "http://ip-api.com/json/8.8.8.8":
            return FakeResponse(
                {
                    "status": "success",
                    "query": "8.8.8.8",
                    "country": "United States",
                    "countryCode": "US",
                    "regionName": "California",
                    "city": "Mountain View",
                    "lat": 37.4223,
                    "lon": -122.085,
                    "isp": "Google LLC",
                    "as": "AS15169 Google LLC",
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == [
        ("https://api.ipapi.is", {"q": "8.8.8.8"}),
        ("https://ipwho.is/8.8.8.8", None),
        (
            "http://ip-api.com/json/8.8.8.8",
            {"fields": "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting"},
        ),
        ("https://ipinfo.io/8.8.8.8/json", None),
        ("https://api.ipdata.co/8.8.8.8", None),
    ]
    assert result == IPInfo(
        ip="8.8.8.8",
        country="United States",
        country_code="US",
        region="California",
        city="Mountain View",
        asn="AS15169",
        asn_owner="Google LLC",
        org="Google LLC",
        isp="Google LLC",
        latitude=37.4223,
        longitude=-122.085,
        provider="ip-api.com",
        field_sources={
            "ip": "ip-api.com",
            "country": "ip-api.com",
            "country_code": "ip-api.com",
            "region": "ip-api.com",
            "city": "ip-api.com",
            "asn": "ip-api.com",
            "asn_owner": "ip-api.com",
            "org": "ip-api.com",
            "isp": "ip-api.com",
            "latitude": "ip-api.com",
            "longitude": "ip-api.com",
        },
    )


def test_provider_falls_back_to_ip_api_com_when_ipwho_omits_ip(monkeypatch):
    calls: list[tuple[str, dict[str, str] | None]] = []

    class FakeResponse:
        def __init__(self, payload: dict, status_code: int = 200) -> None:
            self.payload = payload
            self.status_code = status_code

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "server error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

        def json(self) -> dict:
            return self.payload

    def fake_get(
        url: str,
        *,
        params: dict[str, str] | None = None,
        timeout: float,
    ) -> FakeResponse:
        calls.append((url, params))
        if url == "https://api.ipapi.is":
            return FakeResponse({}, status_code=503)
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse({"success": True, "country": "Unknown"})
        if url == "http://ip-api.com/json/8.8.8.8":
            return FakeResponse(
                {
                    "status": "success",
                    "query": "8.8.8.8",
                    "country": "United States",
                    "countryCode": "US",
                    "isp": "Google LLC",
                    "as": "AS15169 Google LLC",
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == [
        ("https://api.ipapi.is", {"q": "8.8.8.8"}),
        ("https://ipwho.is/8.8.8.8", None),
        (
            "http://ip-api.com/json/8.8.8.8",
            {"fields": "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting"},
        ),
        ("https://ipapi.org/api/ip/8.8.8.8", None),
    ]
    assert result.provider == "ip-api.com"
    assert result.ip == "8.8.8.8"
    assert result.country == "United States"


def test_lookup_returns_502_when_all_real_providers_fail(monkeypatch):
    calls: list[tuple[str, dict[str, str] | None]] = []

    class FakeResponse:
        def __init__(self, payload: dict, status_code: int = 200) -> None:
            self.payload = payload
            self.status_code = status_code

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "server error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

        def json(self) -> dict:
            return self.payload

    def fake_get(
        url: str,
        *,
        params: dict[str, str] | None = None,
        timeout: float,
    ) -> FakeResponse:
        calls.append((url, params))
        if url == "https://api.ipapi.is":
            return FakeResponse({}, status_code=503)
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse({"success": False, "message": "rate limited"})
        if url == "http://ip-api.com/json/8.8.8.8":
            return FakeResponse({"status": "fail", "message": "reserved range"})
        if url in {
            "https://ipapi.org/api/ip/8.8.8.8",
            "https://ipinfo.io/8.8.8.8/json",
            "https://api.ipdata.co/8.8.8.8",
        }:
            return FakeResponse({}, status_code=503)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/api/ip?8.8.8.8")

    assert response.status_code == 502
    assert response.json() == {"detail": "IP lookup providers are temporarily unavailable"}
    assert calls == [
        ("https://api.ipapi.is", {"q": "8.8.8.8"}),
        ("https://ipwho.is/8.8.8.8", None),
        (
            "http://ip-api.com/json/8.8.8.8",
            {"fields": "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting"},
        ),
        ("https://ipapi.org/api/ip/8.8.8.8", None),
        ("https://ipinfo.io/8.8.8.8/json", None),
        ("https://api.ipdata.co/8.8.8.8", None),
    ]


def test_lookup_returns_502_when_ip_api_com_success_omits_query(monkeypatch):
    calls: list[tuple[str, dict[str, str] | None]] = []

    class FakeResponse:
        def __init__(self, payload: dict, status_code: int = 200) -> None:
            self.payload = payload
            self.status_code = status_code

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "server error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

        def json(self) -> dict:
            return self.payload

    def fake_get(
        url: str,
        *,
        params: dict[str, str] | None = None,
        timeout: float,
    ) -> FakeResponse:
        calls.append((url, params))
        if url == "https://api.ipapi.is":
            return FakeResponse({}, status_code=503)
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse({"success": False, "message": "rate limited"})
        if url == "http://ip-api.com/json/8.8.8.8":
            return FakeResponse({"status": "success", "country": "United States"})
        if url in {
            "https://ipapi.org/api/ip/8.8.8.8",
            "https://ipinfo.io/8.8.8.8/json",
            "https://api.ipdata.co/8.8.8.8",
        }:
            return FakeResponse({}, status_code=503)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/api/ip?8.8.8.8")

    assert response.status_code == 502
    assert response.json() == {"detail": "IP lookup providers are temporarily unavailable"}
    assert calls == [
        ("https://api.ipapi.is", {"q": "8.8.8.8"}),
        ("https://ipwho.is/8.8.8.8", None),
        (
            "http://ip-api.com/json/8.8.8.8",
            {"fields": "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting"},
        ),
        ("https://ipapi.org/api/ip/8.8.8.8", None),
        ("https://ipinfo.io/8.8.8.8/json", None),
        ("https://api.ipdata.co/8.8.8.8", None),
    ]


def test_lookup_caches_same_ip_result_and_does_not_call_provider_twice():
    calls = 0

    class CountingProvider:
        def lookup(self, ip: str) -> IPInfo:
            nonlocal calls
            calls += 1
            return IPInfo(ip=ip, country="United States", provider="test-provider")

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: CountingProvider()
    try:
        client = TestClient(app)

        first = client.get("/api/ip?8.8.8.8")
        second = client.get("/api/ip?8.8.8.8")

        assert first.status_code == 200
        assert second.status_code == 200
        assert calls == 1
        assert first.json() == second.json()
    finally:
        app.dependency_overrides.clear()


def test_lookup_refreshes_cache_after_ttl_expires(monkeypatch):
    now = 1000.0
    calls = 0

    def fake_monotonic() -> float:
        return now

    class CountingProvider:
        def lookup(self, ip: str) -> IPInfo:
            nonlocal calls
            calls += 1
            return IPInfo(ip=ip, country=f"Result {calls}", provider="test-provider")

    monkeypatch.setattr(ip_api, "IP_LOOKUP_CACHE_TTL_SECONDS", 10)
    monkeypatch.setattr(ip_api.time, "monotonic", fake_monotonic)
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: CountingProvider()
    try:
        client = TestClient(app)

        first = client.get("/api/ip?8.8.8.8")
        now = 1005.0
        cached = client.get("/api/ip?8.8.8.8")
        now = 1011.0
        refreshed = client.get("/api/ip?8.8.8.8")

        assert first.status_code == 200
        assert cached.status_code == 200
        assert refreshed.status_code == 200
        assert calls == 2
        assert first.json()["country"] == "Result 1"
        assert cached.json()["country"] == "Result 1"
        assert refreshed.json()["country"] == "Result 2"
    finally:
        app.dependency_overrides.clear()


def test_lookup_does_not_cache_provider_failure():
    calls = 0

    class FlakyProvider:
        def lookup(self, ip: str) -> IPInfo:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise IPLookupUnavailable("temporary outage")
            return IPInfo(ip=ip, country="United States", provider="test-provider")

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: FlakyProvider()
    try:
        client = TestClient(app, raise_server_exceptions=False)

        failed = client.get("/api/ip?8.8.8.8")
        recovered = client.get("/api/ip?8.8.8.8")

        assert failed.status_code == 502
        assert recovered.status_code == 200
        assert recovered.json()["ip"] == "8.8.8.8"
        assert calls == 2
    finally:
        app.dependency_overrides.clear()


def test_lookup_rate_limits_same_client_after_configured_limit(monkeypatch):
    now = 2000.0

    def fake_monotonic() -> float:
        return now

    class CountingProvider:
        def lookup(self, ip: str) -> IPInfo:
            return IPInfo(ip=ip, country="United States", provider="test-provider")

    monkeypatch.setattr(ip_api, "IP_LOOKUP_RATE_LIMIT_PER_MINUTE", 2, raising=False)
    monkeypatch.setattr(ip_api.time, "monotonic", fake_monotonic)
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: CountingProvider()
    try:
        client = TestClient(app, client=("198.51.100.88", 54321))

        first = client.get("/api/ip?8.8.8.8")
        second = client.get("/api/ip?8.8.8.8")
        limited = client.get("/api/ip?8.8.8.8")

        assert first.status_code == 200
        assert second.status_code == 200
        assert limited.status_code == 429
        assert limited.json() == {"detail": "Rate limit exceeded"}
    finally:
        app.dependency_overrides.clear()


def test_lookup_rate_limit_window_expiry_allows_requests_again(monkeypatch):
    now = 3000.0

    def fake_monotonic() -> float:
        return now

    class CountingProvider:
        def lookup(self, ip: str) -> IPInfo:
            return IPInfo(ip=ip, country="United States", provider="test-provider")

    monkeypatch.setattr(ip_api, "IP_LOOKUP_RATE_LIMIT_PER_MINUTE", 2, raising=False)
    monkeypatch.setattr(ip_api.time, "monotonic", fake_monotonic)
    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: CountingProvider()
    try:
        client = TestClient(app, client=("198.51.100.89", 54321))

        first = client.get("/api/ip?8.8.8.8")
        second = client.get("/api/ip?8.8.8.8")
        limited = client.get("/api/ip?8.8.8.8")
        now = 3060.0
        allowed_after_window = client.get("/api/ip?8.8.8.8")

        assert first.status_code == 200
        assert second.status_code == 200
        assert limited.status_code == 429
        assert allowed_after_window.status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_lookup_response_includes_registry_and_registration_region():
    class EchoProvider:
        def lookup(self, ip: str) -> IPInfo:
            return IPInfo(
                ip=ip,
                country="United States",
                country_code="US",
                asn="AS15169",
                isp="Google LLC",
                provider="test-provider",
                registry="ARIN",
                reg_region="US",
            )

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: EchoProvider()
    try:
        client = TestClient(app)

        response = client.get("/api/ip?8.8.8.8")

        assert response.status_code == 200
        assert response.json()["registry"] == "ARIN"
        assert response.json()["reg_region"] == "US"
    finally:
        app.dependency_overrides.clear()


def test_lookup_response_includes_asn_and_org_domains():
    class EchoProvider:
        def lookup(self, ip: str) -> IPInfo:
            return IPInfo(
                ip=ip,
                country="United States",
                country_code="US",
                asn="AS15169",
                isp="Google LLC",
                provider="test-provider",
                asn_domain="google.com",
                org_domain="google.com",
            )

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: EchoProvider()
    try:
        client = TestClient(app)

        response = client.get("/api/ip?8.8.8.8")

        assert response.status_code == 200
        assert response.json()["asn_domain"] == "google.com"
        assert response.json()["org_domain"] == "google.com"
    finally:
        app.dependency_overrides.clear()


def test_lookup_prefers_independent_registry_lookup_for_registration_fields(monkeypatch):
    from app.api import ip as ip_api

    class ProviderWithWrongProviderRegistry:
        def lookup(self, ip: str) -> IPInfo:
            return IPInfo(
                ip=ip,
                country="Netherlands",
                country_code="NL",
                asn="AS15169",
                isp="Google LLC",
                provider="fake",
                network_type="hosting",
                registry="RIPE NCC",
                reg_region="NL",
            )

    class FakeRegistryResult:
        registry = "ARIN"
        reg_region = "US"
        source = "ripestat"

    class FakeRegistryClient:
        def lookup(self, ip: str) -> FakeRegistryResult:
            assert ip == "8.8.8.8"
            return FakeRegistryResult()

    app.dependency_overrides[get_public_ip_lookup_provider] = lambda: ProviderWithWrongProviderRegistry()
    monkeypatch.setattr(ip_api, "get_registry_lookup_client", lambda: FakeRegistryClient())
    clear_ip_lookup_cache()
    try:
        response = TestClient(app).get("/api/ip?8.8.8.8")
    finally:
        app.dependency_overrides.clear()
        clear_ip_lookup_cache()

    assert response.status_code == 200
    body = response.json()
    assert body["registry"] == "ARIN"
    assert body["reg_region"] == "US"
    assert body["ip_property"] == "机房IP"
    assert body["ip_source"] == "广播IP"

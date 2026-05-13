from fastapi.testclient import TestClient
import httpx
import socket

import app.api.ip as ip_api
from app.api.ip import clear_ip_lookup_cache
from app.main import app
from app.services.ip_lookup import (
    IPAPIIsLookupProvider,
    IPInfo,
    IPLookupUnavailable,
    StaticIPLookupProvider,
    get_ip_lookup_provider,
)


def setup_function() -> None:
    app.dependency_overrides.clear()
    clear_ip_lookup_cache()


def test_lookup_explicit_ip_returns_normalized_provider_result():
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
            "ip_source_reason": "",
            "ip_property": "商业IP",
            "ip_property_reason": "机房IP:0, 家庭IP:0, 商业IP:6",
            "ip_property_scores": {"机房IP": 0, "家庭IP": 0, "商业IP": 6},
            "risk_score": 10,
            "risk_reason": "基于代理/VPN/TOR/托管网络与网络类型综合评估",
            "risk_breakdown": {"base": 10},
            "risk_confidence": 0.7,
            "human_percent": 83.0,
            "bot_percent": 17.0,
            "humanbot_reason": "基于 IP 属性和风险信号估算人机流量比例",
            "humanbot_breakdown": {"human": 83.0, "bot": 17.0},
            "humanbot_confidence": 0.7,
            "is_proxy": False,
            "is_vpn": False,
            "is_tor": False,
            "is_mobile": False,
            "is_hosting": False,
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


def test_lookup_supports_raw_ip_query_without_equals_sign():
    class EchoProvider:
        def lookup(self, ip: str) -> IPInfo:
            return IPInfo(ip=ip, country="United States", provider="test-provider")

    app.dependency_overrides[get_ip_lookup_provider] = lambda: EchoProvider()
    try:
        client = TestClient(app, client=("203.0.113.9", 54321))

        response = client.get("/api/ip?8.8.8.8")

        assert response.status_code == 200
        assert response.json()["ip"] == "8.8.8.8"
    finally:
        app.dependency_overrides.clear()


def test_lookup_without_ip_uses_request_client_host():
    app.dependency_overrides[get_ip_lookup_provider] = lambda: StaticIPLookupProvider(
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



def test_lookup_domain_response_includes_resolution_metadata(monkeypatch):
    def fake_getaddrinfo(host: str, port: int | None, *, type: int = 0) -> list[tuple]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0)),
        ]

    class EchoProvider:
        def lookup(self, ip: str) -> IPInfo:
            return IPInfo(ip=ip, country="United States", provider="test-provider")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    app.dependency_overrides[get_ip_lookup_provider] = lambda: EchoProvider()
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
        assert response.json()["dns_provider"] == "system"
        assert response.json()["geo_provider"] == "test-provider"
    finally:
        app.dependency_overrides.clear()


def test_lookup_resolves_keyless_domain_before_calling_provider(monkeypatch):
    calls: list[str] = []

    def fake_getaddrinfo(host: str, port: int | None, *, type: int = 0) -> list[tuple]:
        assert host == "example.com"
        assert port is None
        assert type == socket.SOCK_STREAM
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0)),
        ]

    class EchoProvider:
        def lookup(self, ip: str) -> IPInfo:
            calls.append(ip)
            return IPInfo(ip=ip, country="United States", provider="test-provider")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    app.dependency_overrides[get_ip_lookup_provider] = lambda: EchoProvider()
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

    def fake_getaddrinfo(host: str, port: int | None, *, type: int = 0) -> list[tuple]:
        assert host == "example.com"
        assert port is None
        assert type == socket.SOCK_STREAM
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0))]

    class EchoProvider:
        def lookup(self, ip: str) -> IPInfo:
            calls.append(ip)
            return IPInfo(ip=ip, country="United States", provider="test-provider")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    app.dependency_overrides[get_ip_lookup_provider] = lambda: EchoProvider()
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


def test_lookup_rejects_invalid_keyless_queries_before_calling_provider():
    class FailingProvider:
        def lookup(self, ip: str) -> IPInfo:
            raise AssertionError("provider should not be called for invalid IP")

    app.dependency_overrides[get_ip_lookup_provider] = lambda: FailingProvider()
    try:
        client = TestClient(app, raise_server_exceptions=False)

        for url in ("/api/ip?not-an-ip", "/api/ip?"):
            response = client.get(url)

            assert response.status_code == 422
            assert response.json()["detail"][0]["loc"][:2] == ["query", "ip"]
    finally:
        app.dependency_overrides.clear()


def test_lookup_rejects_invalid_raw_ip_query_before_calling_provider():
    class FailingProvider:
        def lookup(self, ip: str) -> IPInfo:
            raise AssertionError("provider should not be called for invalid raw IP")

    app.dependency_overrides[get_ip_lookup_provider] = lambda: FailingProvider()
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

    app.dependency_overrides[get_ip_lookup_provider] = lambda: FailingProvider()
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
            "ip_source_reason": "",
            "ip_property": "家庭IP",
            "ip_property_reason": "机房IP:0, 家庭IP:3, 商业IP:0",
            "ip_property_scores": {"机房IP": 0, "家庭IP": 3, "商业IP": 0},
            "risk_score": 10,
            "risk_reason": "基于代理/VPN/TOR/托管网络与网络类型综合评估",
            "risk_breakdown": {"base": 10},
            "risk_confidence": 0.7,
            "human_percent": 98.0,
            "bot_percent": 2.0,
            "humanbot_reason": "基于 IP 属性和风险信号估算人机流量比例",
            "humanbot_breakdown": {"human": 98.0, "bot": 2.0},
            "humanbot_confidence": 0.7,
            "is_proxy": False,
            "is_vpn": False,
            "is_tor": False,
            "is_mobile": False,
            "is_hosting": False,
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

    app.dependency_overrides[get_ip_lookup_provider] = lambda: FailingProvider()
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

    app.dependency_overrides[get_ip_lookup_provider] = lambda: FailingProvider()
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

    def fake_get(url: str, *, params: dict[str, str], timeout: float) -> FakeResponse:
        seen["url"] = url
        seen["params"] = params
        seen["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(httpx, "get", fake_get)

    client = TestClient(app)
    response = client.get("/api/ip?8.8.8.8")

    assert response.status_code == 200
    assert seen == {
        "url": "https://api.ipapi.is",
        "params": {"q": "8.8.8.8"},
        "timeout": 8.0,
    }
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
        "ip_source_reason": "",
        "ip_property": "商业IP",
        "ip_property_reason": "机房IP:0, 家庭IP:0, 商业IP:6",
        "ip_property_scores": {"机房IP": 0, "家庭IP": 0, "商业IP": 6},
        "risk_score": 10,
        "risk_reason": "基于代理/VPN/TOR/托管网络与网络类型综合评估",
        "risk_breakdown": {"base": 10},
        "risk_confidence": 0.7,
        "human_percent": 83.0,
        "bot_percent": 17.0,
        "humanbot_reason": "基于 IP 属性和风险信号估算人机流量比例",
        "humanbot_breakdown": {"human": 83.0, "bot": 17.0},
        "humanbot_confidence": 0.7,
        "is_proxy": False,
        "is_vpn": False,
        "is_tor": False,
        "is_mobile": False,
        "is_hosting": False,
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
        isp="Google LLC",
        latitude=37.4056,
        longitude=-122.0775,
        provider="ipwho.is",
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
                    "connection": {"asn": 15169, "isp": "Google LLC"},
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == [
        ("https://api.ipapi.is", {"q": "8.8.8.8"}),
        ("https://ipwho.is/8.8.8.8", None),
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
                    "asn": {"asn": "AS15169", "name": "Google LLC"},
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
        isp="Google LLC",
        latitude=37.4056,
        longitude=-122.0775,
        provider="ipdata.co",
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
    ]
    assert result == IPInfo(
        ip="8.8.8.8",
        country="United States",
        country_code="US",
        region="California",
        city="Mountain View",
        asn="AS15169",
        isp="Google LLC",
        latitude=37.4223,
        longitude=-122.085,
        provider="ip-api.com",
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

    app.dependency_overrides[get_ip_lookup_provider] = lambda: CountingProvider()
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
    app.dependency_overrides[get_ip_lookup_provider] = lambda: CountingProvider()
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

    app.dependency_overrides[get_ip_lookup_provider] = lambda: FlakyProvider()
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
    app.dependency_overrides[get_ip_lookup_provider] = lambda: CountingProvider()
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
    app.dependency_overrides[get_ip_lookup_provider] = lambda: CountingProvider()
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

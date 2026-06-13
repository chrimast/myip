import socket

import httpx
import pytest
from fastapi.exceptions import RequestValidationError

from app.services.target_ip import (
    DNSResolutionError,
    normalize_ip_or_resolve_domain,
    resolve_domain,
    resolve_target,
    target_ip_from_query,
    unique_socket_ips,
)


def test_resolve_target_uses_doh_without_calling_system_dns(monkeypatch):
    calls: list[str] = []

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "Status": 0,
                "Answer": [
                    {"type": 1, "data": "93.184.216.34"},
                    {"type": 1, "data": "93.184.216.34"},
                    {"type": 28, "data": "2606:2800:220:1:248:1893:25c8:1946"},
                ],
            }

    def fail_getaddrinfo(host: str, port: int | None, *, type: int = 0) -> list[tuple]:
        raise AssertionError("system DNS should not be called")

    def fake_get(url: str, *, params: dict[str, str], headers: dict[str, str], timeout: float) -> FakeResponse:
        calls.append(url)
        return FakeResponse()

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)
    monkeypatch.setattr(httpx, "get", fake_get)

    result = resolve_target("example.com")

    assert calls == ["https://cloudflare-dns.com/dns-query"]
    assert result.input == "example.com"
    assert result.selected_ip == "93.184.216.34"
    assert result.resolved_ips == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]
    assert result.dns_provider == "cloudflare"


def test_resolve_target_uses_cloudflare_doh(monkeypatch):
    calls: list[tuple[str, dict[str, str]]] = []

    class FakeResponse:
        def __init__(self, payload: dict) -> None:
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self.payload

    def fake_get(url: str, *, params: dict[str, str], headers: dict[str, str], timeout: float) -> FakeResponse:
        calls.append((url, params))
        assert headers == {"accept": "application/dns-json"}
        assert timeout == 5.0
        if url == "https://cloudflare-dns.com/dns-query":
            return FakeResponse(
                {
                    "Status": 0,
                    "Answer": [
                        {"type": 1, "data": "93.184.216.34"},
                        {"type": 1, "data": "93.184.216.34"},
                        {"type": 28, "data": "2606:2800:220:1:248:1893:25c8:1946"},
                    ],
                }
            )
        raise AssertionError(f"unexpected DoH URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = resolve_target("example.com")

    assert calls == [("https://cloudflare-dns.com/dns-query", {"name": "example.com", "type": "A"})]
    assert result.selected_ip == "93.184.216.34"
    assert result.resolved_ips == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]
    assert result.dns_provider == "cloudflare"


def test_resolve_target_falls_back_across_doh_providers(monkeypatch):
    calls: list[str] = []

    def fake_getaddrinfo(host: str, port: int | None, *, type: int = 0) -> list[tuple]:
        raise socket.gaierror("system DNS unavailable")

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

    def fake_get(url: str, *, params: dict[str, str], headers: dict[str, str], timeout: float) -> FakeResponse:
        calls.append(url)
        if url == "https://cloudflare-dns.com/dns-query":
            return FakeResponse({}, status_code=503)
        if url == "https://dns.google/resolve":
            return FakeResponse({"Status": 3})
        if url == "https://dns.quad9.net/dns-query":
            return FakeResponse({"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34"}]})
        raise AssertionError(f"unexpected DoH URL: {url}")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(httpx, "get", fake_get)

    result = resolve_target("example.com")

    assert calls == [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
        "https://dns.quad9.net/dns-query",
    ]
    assert result.selected_ip == "93.184.216.34"
    assert result.dns_provider == "quad9"


def test_target_ip_from_query_rejects_keyless_equals_and_resolves_raw_domain(monkeypatch):
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34"}]}

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: FakeResponse())

    with pytest.raises(RequestValidationError):
        target_ip_from_query("=example.com", "203.0.113.9")
    assert target_ip_from_query("example.com", "203.0.113.9") == "93.184.216.34"


def test_resolve_target_extracts_hostname_from_url(monkeypatch):
    seen: list[dict[str, str]] = []

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34"}]}

    def fake_get(url: str, *, params: dict[str, str], headers: dict[str, str], timeout: float) -> FakeResponse:
        seen.append(params)
        return FakeResponse()

    monkeypatch.setattr(httpx, "get", fake_get)

    result = resolve_target("https://example.com/path?q=1")

    assert seen == [{"name": "example.com", "type": "A"}]
    assert result.input == "https://example.com/path?q=1"
    assert result.selected_ip == "93.184.216.34"


def test_target_resolution_uses_configured_doh_timeout_and_provider_order(monkeypatch):
    calls: list[tuple[str, float]] = []

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34"}]}

    def fake_getaddrinfo(host: str, port: int | None, *, type: int = 0) -> list[tuple]:
        raise socket.timeout()

    def fake_get(url: str, *, params: dict[str, str], headers: dict[str, str], timeout: float) -> FakeResponse:
        calls.append((url, timeout))
        return FakeResponse()

    monkeypatch.setenv("MYIP_DOH_TIMEOUT_SECONDS", "1.5")
    monkeypatch.setenv("MYIP_DOH_PROVIDERS", "google,cloudflare")
    monkeypatch.setattr(httpx, "get", fake_get)

    resolution = resolve_domain("example.com")

    assert resolution.selected_ip == "93.184.216.34"
    assert resolution.dns_provider == "google"
    assert calls == [("https://dns.google/resolve", 1.5)]



def test_resolve_domain_uses_admin_runtime_doh_order_timeout_and_ipv6_preference(tmp_path, monkeypatch):
    from app.services import admin_config

    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr(admin_config, "PROVIDER_CONFIG_PATH", config_path)
    admin_config.save_runtime_settings(
        {"dns": {"doh_providers": ["quad9", "cloudflare"], "timeout_seconds": 2.5, "ip_version_preference": "ipv6_first"}}
    )
    calls: list[tuple[str, float]] = []

    class FakeResponse:
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

    def fake_get(url: str, *, params: dict[str, str], headers: dict[str, str], timeout: float) -> FakeResponse:
        calls.append((url, timeout))
        return FakeResponse()

    monkeypatch.setattr(httpx, "get", fake_get)

    resolution = resolve_domain("example.com")

    assert resolution.selected_ip == "2606:2800:220:1:248:1893:25c8:1946"
    assert resolution.resolved_ips == ["2606:2800:220:1:248:1893:25c8:1946", "93.184.216.34"]
    assert resolution.dns_provider == "quad9"
    assert calls == [("https://dns.quad9.net/dns-query", 2.5)]


def test_invalid_domain_input_is_422_without_dns_lookup(monkeypatch):
    def fail_getaddrinfo(host: str, port: int | None, *, type: int = 0) -> list[tuple]:
        raise AssertionError("DNS should not be called for malformed input")

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)

    with pytest.raises(RequestValidationError):
        normalize_ip_or_resolve_domain("not-an-ip")


def test_dns_name_not_found_is_422(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *, type=0: (_ for _ in ()).throw(socket.gaierror()))
    monkeypatch.setenv("MYIP_DOH_PROVIDERS", "")

    with pytest.raises(RequestValidationError) as exc_info:
        normalize_ip_or_resolve_domain("missing.example")

    assert exc_info.value.errors()[0]["type"] == "dns_name_not_found"


def test_dns_resolver_failure_raises_dns_resolution_error(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *, type=0: (_ for _ in ()).throw(socket.timeout()))
    monkeypatch.setenv("MYIP_DOH_PROVIDERS", "cloudflare")

    def fail_get(*args: object, **kwargs: object) -> object:
        raise httpx.ConnectError("DoH unavailable")

    monkeypatch.setattr(httpx, "get", fail_get)

    with pytest.raises(DNSResolutionError):
        normalize_ip_or_resolve_domain("example.com")


def test_unique_socket_ips_deduplicates_a_and_aaaa_results():
    result = unique_socket_ips(
        [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0)),
        ]
    )

    assert result == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]

import httpx
from fastapi.testclient import TestClient

from app.main import app, clear_vis_network_cache


class FakeResponse:
    def __init__(self, body: bytes, *, content_type: str = "application/javascript; charset=utf-8") -> None:
        self.status_code = 200
        self.content = body
        self.headers = {"Content-Type": content_type}

    def raise_for_status(self) -> None:
        return None


def test_vis_network_is_fetched_from_cdn_cached_with_etag_and_not_local_file(monkeypatch):
    clear_vis_network_cache()
    calls: list[str] = []
    body = b"/* vis Network from CDN */ window.vis = { Network: function(){} };"

    def fake_get(url: str, *, headers: dict[str, str], timeout: float) -> FakeResponse:
        calls.append(url)
        assert headers["User-Agent"] == "myip/1.0 (+vis-cache)"
        assert timeout == 10.0
        return FakeResponse(body)

    monkeypatch.setattr(httpx, "get", fake_get)
    client = TestClient(app)

    first = client.get("/vis-network.min.js")
    assert first.status_code == 200
    assert first.content == body
    assert first.headers["etag"].startswith('W/"')
    assert first.headers["cache-control"] == "public, max-age=604800"
    assert calls == ["https://cdn.jsdelivr.net/npm/vis-network/standalone/umd/vis-network.min.js"]

    second = client.get("/vis-network.min.js")
    assert second.status_code == 200
    assert second.content == body
    assert calls == ["https://cdn.jsdelivr.net/npm/vis-network/standalone/umd/vis-network.min.js"]

    not_modified = client.get("/vis-network.min.js", headers={"If-None-Match": first.headers["etag"]})
    assert not_modified.status_code == 304
    assert not_modified.content == b""
    assert calls == ["https://cdn.jsdelivr.net/npm/vis-network/standalone/umd/vis-network.min.js"]


def test_vis_network_falls_back_to_second_cdn(monkeypatch):
    clear_vis_network_cache()
    calls: list[str] = []
    body = b"window.vis = { Network: function(){} };"

    def fake_get(url: str, *, headers: dict[str, str], timeout: float) -> FakeResponse:
        calls.append(url)
        if "cdn.jsdelivr.net" in url:
            raise httpx.ConnectError("primary down")
        return FakeResponse(body)

    monkeypatch.setattr(httpx, "get", fake_get)
    response = TestClient(app).get("/vis-network.min.js")

    assert response.status_code == 200
    assert response.content == body
    assert calls == [
        "https://cdn.jsdelivr.net/npm/vis-network/standalone/umd/vis-network.min.js",
        "https://unpkg.com/vis-network/standalone/umd/vis-network.min.js",
    ]


def test_gzip_compresses_when_accepted():
    response = TestClient(app).get("/", headers={"Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert response.headers["content-encoding"] == "gzip"
    assert "Accept-Encoding" in response.headers["vary"]
    assert "IP检测 - IP信息查询" in response.text


def test_gzip_response_has_single_content_length_header():
    response = TestClient(app).get("/", headers={"Accept-Encoding": "gzip"})

    assert response.headers.get_list("content-length") == [response.headers["content-length"]]


def test_api_ip_sets_etag_and_returns_304(monkeypatch):
    from app.api import ip as ip_module
    from app.services.ip_lookup import IPInfo

    class StaticProvider:
        def lookup(self, ip: str) -> IPInfo:
            return IPInfo(ip=ip, country="United States", country_code="US", provider="test-provider")

    ip_module.clear_ip_lookup_cache()
    app.dependency_overrides[ip_module.get_public_ip_lookup_provider] = lambda: StaticProvider()
    try:
        client = TestClient(app)
        first = client.get("/api/ip?8.8.8.8")
        assert first.status_code == 200
        assert first.headers["etag"].startswith('"')
        assert "If-None-Match" in first.headers["vary"]

        second = client.get("/api/ip?8.8.8.8", headers={"If-None-Match": first.headers["etag"]})
        assert second.status_code == 304
        assert second.content == b""
    finally:
        app.dependency_overrides.clear()
        ip_module.clear_ip_lookup_cache()

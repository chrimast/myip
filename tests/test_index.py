from fastapi.testclient import TestClient

from app.main import app, clear_vis_network_cache


def test_vis_network_asset_is_fetched_with_original_cdn_fallback_logic(monkeypatch):
    class FakeResponse:
        content = b"window.vis = { Network: function Network() {} };"
        headers = {"content-type": "application/javascript"}

        def raise_for_status(self) -> None:
            return None

    seen: list[str] = []

    def fake_get(url: str, *, headers: dict[str, str], timeout: float) -> FakeResponse:
        seen.append(url)
        assert "User-Agent" in headers
        return FakeResponse()

    monkeypatch.setattr("app.services.vis_network.httpx.get", fake_get)
    clear_vis_network_cache()

    client = TestClient(app)

    response = client.get("/vis-network.min.js")

    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert "Network" in response.text
    assert seen == ["https://cdn.jsdelivr.net/npm/vis-network/standalone/umd/vis-network.min.js"]


def test_index_serves_original_go_homepage_layout():
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert "IP检测 - IP信息查询" in body
    assert "IPI.LI" in body
    assert "输入 IP 或域名查询风险" in body
    assert "本机IP" in body
    assert "查询目标" in body
    assert "地理位置" in body
    assert "ASN 号码" in body
    assert "人机流量比" in body
    assert "IP风险系数" in body
    assert "BGP 拓扑图" in body
    assert "SECURITY INTELLIGENCE BY IPI.LI" in body
    assert "id=\"ipInput\"" in body
    assert "id=\"btnAnalyze\"" in body
    assert "/api/ip" in body

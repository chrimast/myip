from fastapi.testclient import TestClient

from app.main import app


def test_local_vis_network_asset_is_served_for_offline_graph_rendering():
    client = TestClient(app)

    response = client.get("/vis-network.min.js")

    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert "vis" in response.text.lower()
    assert "Network" in response.text


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

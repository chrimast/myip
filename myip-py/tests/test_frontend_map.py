from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

INDEX_HTML = Path(__file__).resolve().parents[1] / "app" / "static" / "index.html"


def test_homepage_map_uses_local_leaflet_with_mainland_accessible_amap_tiles():
    body = INDEX_HTML.read_text(encoding="utf-8")

    assert "www.openstreetmap.org/export/embed.html" not in body
    assert "tile.openstreetmap.org" not in body
    assert "unpkg.com/leaflet" not in body
    assert "cdn.jsdelivr.net/npm/leaflet" not in body
    assert "/static/vendor/leaflet/leaflet.css" in body
    assert "/static/vendor/leaflet/leaflet.js" in body
    assert "data-map-provider=\"amap-leaflet\"" in body
    assert "webrd01.is.autonavi.com/appmaptile" in body
    assert "function initLeafletMap" in body
    assert "function updateLeafletMap" in body
    assert "L.map" in body
    assert "L.tileLayer" in body
    assert "L.marker" in body
    assert "zoomControl" in body
    assert "高德地图瓦片" in body


def test_leaflet_vendor_assets_are_local_files():
    vendor = INDEX_HTML.parents[0] / "vendor" / "leaflet"

    assert (vendor / "leaflet.js").is_file()
    assert (vendor / "leaflet.css").is_file()
    assert (vendor / "images" / "marker-icon.png").is_file()
    assert (vendor / "images" / "marker-icon-2x.png").is_file()
    assert (vendor / "images" / "marker-shadow.png").is_file()
    assert (vendor / "images" / "layers.png").is_file()
    assert (vendor / "images" / "layers-2x.png").is_file()


def test_leaflet_static_assets_are_served_by_app():
    client = TestClient(app)

    for path in [
        "/static/vendor/leaflet/leaflet.css",
        "/static/vendor/leaflet/leaflet.js",
        "/static/vendor/leaflet/images/marker-icon.png",
        "/static/vendor/leaflet/images/layers.png",
    ]:
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.content

from fastapi.testclient import TestClient

from app.main import app


def test_health_endpoint_is_removed():
    client = TestClient(app)

    response = client.get("/api/health")

    assert response.status_code == 404

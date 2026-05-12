from fastapi.testclient import TestClient

from app.main import app


def test_health_returns_ok_and_config_without_secret_values():
    client = TestClient(app)

    response = client.get("/api/health")

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert "time" in data
    assert "keys" in data
    assert "config" in data
    body = response.text
    assert "IPAPI_IS_KEY" not in body
    assert "IPINFO_TOKEN" not in body


def test_health_reports_key_configuration_without_values(monkeypatch):
    monkeypatch.setenv("IPAPI_IS_KEY", "dummy-test-token")

    client = TestClient(app)
    response = client.get("/api/health")

    assert response.status_code == 200
    data = response.json()
    assert data["keys"]["ipapi_is_key"]["configured"] is True
    assert data["keys"]["ipapi_is_key"]["source"] == "env"
    assert "dummy-test-token" not in response.text

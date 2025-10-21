import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_proxy_get(client):
    response = client.get("/proxy?url=https://httpbin.org/json")
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")


def test_proxy_invalid_url(client):
    response = client.get("/proxy?url=invalid-url")
    assert response.status_code == 400


def test_proxy_blocked_domain(client):
    response = client.get("/proxy?url=http://localhost:8080")
    assert response.status_code == 403


def test_proxy_post(client):
    data = {
        "url": "https://httpbin.org/post",
        "method": "POST",
        "body": '{"test": "data"}',
        "headers": {"Content-Type": "application/json"},
    }
    response = client.post("/proxy", json=data)
    if response.status_code != 200:
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
    assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__])

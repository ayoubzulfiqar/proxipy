import pytest
from fastapi.testclient import TestClient

from app.app import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


class TestMetricsEndpoints:
    def test_metrics_endpoint(self, client: TestClient):
        response = client.get("/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "total_requests" in data
        assert "requests_by_method" in data
        assert "errors_by_type" in data
        assert "avg_response_time" in data
        assert "active_connections" in data
        assert "uptime" in data

    def test_prometheus_metrics_endpoint(self, client: TestClient):
        response = client.get("/metrics/prometheus")
        assert response.status_code == 200
        text = response.text
        assert "proxipy_requests_total" in text
        assert "proxipy_errors_total" in text
        assert "proxipy_active_connections" in text
        assert response.headers["content-type"].startswith("text/plain")


class TestWebSocketProxy:
    def test_websocket_proxy_text_message(self, client: TestClient):
        with client.websocket_connect("/websocket") as websocket:
            websocket.send_text("hello")
            data = websocket.receive_text()
            assert data == "Proxied: hello"

    def test_websocket_proxy_binary_message(self, client: TestClient):
        with client.websocket_connect("/websocket") as websocket:
            websocket.send_bytes(b"binary-payload")
            data = websocket.receive_bytes()
            assert data == b"Proxied: binary-payload"

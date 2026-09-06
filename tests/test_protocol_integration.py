import base64
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.app import app
from app.config import settings
from app.protocols import protocol_proxy


@pytest.fixture
def client():
    return TestClient(app)


class TestProtocolIntegration:
    def test_tcp_endpoint_disabled_by_default(self, client):
        settings.PROTOCOL_TCP_ENABLED = False
        response = client.post(
            "/proxy/tcp",
            json={"host": "127.0.0.1", "port": 1234, "data": "ping"},
        )
        assert response.status_code == 403

    def test_udp_endpoint_disabled_by_default(self, client):
        settings.PROTOCOL_UDP_ENABLED = False
        response = client.post(
            "/proxy/udp",
            json={"host": "127.0.0.1", "port": 1234, "data": "ping"},
        )
        assert response.status_code == 403

    def test_grpc_endpoint_disabled_by_default(self, client):
        settings.PROTOCOL_GRPC_ENABLED = False
        response = client.post(
            "/proxy/grpc",
            json={"url": "http://example.com", "method": "POST", "body": "data"},
        )
        assert response.status_code == 403

    def test_tcp_endpoint_success(self, client):
        settings.PROTOCOL_TCP_ENABLED = True
        with patch.object(protocol_proxy, "proxy_tcp_request", new_callable=AsyncMock) as mock_proxy:
            mock_proxy.return_value = b"ok"
            response = client.post(
                "/proxy/tcp",
                json={"host": "127.0.0.1", "port": 1234, "data": "ping"},
            )
            assert response.status_code == 200
            assert response.json()["content"] == "ok"

    def test_udp_endpoint_success(self, client):
        settings.PROTOCOL_UDP_ENABLED = True
        with patch.object(protocol_proxy, "proxy_udp_request", new_callable=AsyncMock) as mock_proxy:
            mock_proxy.return_value = b"udp-ack"
            response = client.post(
                "/proxy/udp",
                json={"host": "127.0.0.1", "port": 1234, "data": "ping"},
            )
            assert response.status_code == 200
            assert response.json()["content"] == "udp-ack"

    def test_grpc_endpoint_success(self, client):
        settings.PROTOCOL_GRPC_ENABLED = True
        mock_router = AsyncMock()
        mock_router.proxy_request = AsyncMock(return_value=b"grpc-resp")
        with patch.object(protocol_proxy, "router", mock_router):
            response = client.post(
                "/proxy/grpc",
                json={"url": "http://example.com", "method": "POST", "body": "data"},
            )
            assert response.status_code == 200
            assert response.json()["content"] == "grpc-resp"

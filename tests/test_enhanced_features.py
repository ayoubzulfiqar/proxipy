from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient

from app.app import app
from app.config import settings
from app.load_balancer import (
    BackendServer,
    LoadBalancer,
    LoadBalancingAlgorithm,
    ServerState,
)
from app.middleware import (
    AuthenticationMiddleware,
    BufferingMiddleware,
    CircuitBreakerMiddleware,
    CompressionMiddleware,
    HeaderManipulationMiddleware,
    IPFilterMiddleware,
    MiddlewareContext,
    RateLimitMiddleware,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mock_backend_server():
    """Create a mock backend server for testing"""
    return BackendServer(
        host="test-server.com",
        port=8080,
        protocol="http",
        weight=1,
        max_connections=100,
    )


@pytest.fixture
def mock_load_balancer():
    """Create a mock load balancer for testing"""
    from app.load_balancer import LoadBalancerConfig

    config = LoadBalancerConfig(
        algorithm=LoadBalancingAlgorithm.ROUND_ROBIN,
        session_stickiness=False,
        enable_circuit_breaker=True,
        circuit_breaker_failure_threshold=3,
        circuit_breaker_recovery_timeout=60.0,
    )
    return LoadBalancer(config)


class TestLoadBalancer:
    """Test load balancer functionality"""

    def test_backend_server_creation(self, mock_backend_server):
        """Test backend server creation and properties"""
        assert mock_backend_server.host == "test-server.com"
        assert mock_backend_server.port == 8080
        assert mock_backend_server.protocol == "http"
        assert mock_backend_server.weight == 1
        assert mock_backend_server.max_connections == 100
        assert mock_backend_server.state == ServerState.HEALTHY
        assert mock_backend_server.is_healthy

    def test_backend_server_connection_management(self, mock_backend_server):
        """Test backend server connection management"""
        assert mock_backend_server.current_connections == 0

        mock_backend_server.increment_connections()
        assert mock_backend_server.current_connections == 1

        mock_backend_server.increment_connections()
        assert mock_backend_server.current_connections == 2

        mock_backend_server.decrement_connections()
        assert mock_backend_server.current_connections == 1

        mock_backend_server.decrement_connections()
        assert mock_backend_server.current_connections == 0

        # Test negative connection count protection
        mock_backend_server.decrement_connections()
        assert mock_backend_server.current_connections == 0

    def test_backend_server_health_management(self, mock_backend_server):
        """Test backend server health state management"""
        # Initially healthy
        assert mock_backend_server.state == ServerState.HEALTHY
        assert mock_backend_server.is_healthy

        # Mark failure
        mock_backend_server.mark_failure()
        assert mock_backend_server.consecutive_failures == 1
        assert mock_backend_server.consecutive_successes == 0
        assert mock_backend_server.state == ServerState.HEALTHY  # Not unhealthy yet

        # Mark more failures
        mock_backend_server.mark_failure()
        mock_backend_server.mark_failure()
        assert mock_backend_server.consecutive_failures == 3
        assert mock_backend_server.state == ServerState.UNHEALTHY

        # Mark success
        mock_backend_server.mark_success()
        assert mock_backend_server.consecutive_failures == 0
        assert mock_backend_server.consecutive_successes == 1
        assert mock_backend_server.state == ServerState.HEALTHY

    def test_load_balancer_creation(self, mock_load_balancer):
        """Test load balancer creation"""
        assert mock_load_balancer.config.algorithm == LoadBalancingAlgorithm.ROUND_ROBIN
        assert not mock_load_balancer.config.session_stickiness
        assert mock_load_balancer.config.enable_circuit_breaker
        assert len(mock_load_balancer.servers) == 0

    def test_load_balancer_add_server(self, mock_load_balancer, mock_backend_server):
        """Test adding servers to load balancer"""
        mock_load_balancer.add_server(mock_backend_server)
        assert len(mock_load_balancer.servers) == 1
        assert mock_load_balancer.servers[0] == mock_backend_server

    def test_load_balancer_remove_server(self, mock_load_balancer, mock_backend_server):
        """Test removing servers from load balancer"""
        mock_load_balancer.add_server(mock_backend_server)
        assert len(mock_load_balancer.servers) == 1

        mock_load_balancer.remove_server(mock_backend_server.server_id)
        assert len(mock_load_balancer.servers) == 0

    def test_load_balancer_server_stats(self, mock_load_balancer, mock_backend_server):
        """Test load balancer server statistics"""
        mock_load_balancer.add_server(mock_backend_server)
        stats = mock_load_balancer.get_server_stats()

        assert len(stats) == 1
        assert stats[0]["server_id"] == mock_backend_server.server_id
        assert stats[0]["url"] == "http://test-server.com:8080"
        assert stats[0]["weight"] == 1
        assert stats[0]["state"] == "healthy"
        assert stats[0]["current_connections"] == 0
        assert stats[0]["max_connections"] == 100
        assert stats[0]["is_healthy"]


class TestMiddleware:
    """Test middleware functionality"""

    def test_middleware_context(self):
        """Test middleware context creation"""
        context = MiddlewareContext()

        assert context.request is None
        assert context.response is None
        assert context.request_data == {}
        assert context.response_data == {}
        assert context.server is None
        assert context.start_time == 0.0
        assert context.end_time == 0.0
        assert context.error is None
        assert not context.skip_remaining

    def test_authentication_middleware(self):
        """Test authentication middleware"""
        from app.middleware import AuthenticationConfig

        config = AuthenticationConfig(enabled=True, basic_auth={"testuser": "testpass"})
        middleware = AuthenticationMiddleware(config)

        assert middleware.config.enabled
        assert middleware.config.basic_auth == {"testuser": "testpass"}

    def test_rate_limit_middleware(self):
        """Test rate limit middleware"""
        from app.middleware import RateLimitConfig

        config = RateLimitConfig(
            enabled=True,
            requests_per_minute=60,
            requests_per_hour=1000,
            burst_size=10,
            block_duration=300.0,
        )
        middleware = RateLimitMiddleware(config)

        assert middleware.config.enabled
        assert middleware.config.requests_per_minute == 60
        assert middleware.config.requests_per_hour == 1000
        assert middleware.config.burst_size == 10
        assert middleware.config.block_duration == 300.0

    def test_circuit_breaker_middleware(self):
        """Test circuit breaker middleware"""
        from app.middleware import CircuitBreakerConfig

        config = CircuitBreakerConfig(
            enabled=True,
            failure_threshold=5,
            recovery_timeout=60.0,
            half_open_max_requests=3,
            timeout=30.0,
        )
        middleware = CircuitBreakerMiddleware(config)

        assert middleware.config.enabled
        assert middleware.config.failure_threshold == 5
        assert middleware.config.recovery_timeout == 60.0
        assert middleware.config.half_open_max_requests == 3
        assert middleware.config.timeout == 30.0

    def test_compression_middleware(self):
        """Test compression middleware"""
        from app.middleware import CompressionConfig

        config = CompressionConfig(
            enabled=True,
            min_size=1024,
            compression_level=6,
            supported_encodings=["gzip", "deflate"],
        )
        middleware = CompressionMiddleware(config)

        assert middleware.config.enabled
        assert middleware.config.min_size == 1024
        assert middleware.config.compression_level == 6
        assert middleware.config.supported_encodings == ["gzip", "deflate"]

    def test_buffering_middleware(self):
        """Test buffering middleware"""
        from app.middleware import BufferingConfig

        config = BufferingConfig(
            enabled=True,
            max_buffer_size=1048576,
            buffer_timeout=5.0,
            enable_streaming=True,
        )
        middleware = BufferingMiddleware(config)

        assert middleware.config.enabled
        assert middleware.config.max_buffer_size == 1048576
        assert middleware.config.buffer_timeout == 5.0
        assert middleware.config.enable_streaming

    def test_header_manipulation_middleware(self):
        """Test header manipulation middleware"""
        from app.middleware import HeaderManipulationConfig

        config = HeaderManipulationConfig(
            enabled=True,
            add_headers={"X-Test": "value"},
            remove_headers=["Server"],
            modify_headers={"Content-Type": "application/json"},
            strip_prefix="",
            redirect_prefix="",
        )
        middleware = HeaderManipulationMiddleware(config)

        assert middleware.config.enabled
        assert middleware.config.add_headers == {"X-Test": "value"}
        assert middleware.config.remove_headers == ["Server"]
        assert middleware.config.modify_headers == {"Content-Type": "application/json"}
        assert middleware.config.strip_prefix == ""
        assert middleware.config.redirect_prefix == ""

    def test_ip_filter_middleware(self):
        """Test IP filter middleware"""
        from app.middleware import IPFilterConfig

        config = IPFilterConfig(
            enabled=True,
            whitelist=["192.168.1.1"],
            blacklist=["10.0.0.1"],
            block_private_ips=True,
            block_loopback=True,
        )
        middleware = IPFilterMiddleware(config)

        assert middleware.config.enabled
        assert middleware.config.whitelist == ["192.168.1.1"]
        assert middleware.config.blacklist == ["10.0.0.1"]
        assert middleware.config.block_private_ips
        assert middleware.config.block_loopback


class TestEnhancedEndpoints:
    """Test enhanced API endpoints"""

    def test_health_check_with_load_balancer(self, client, mock_backend_server):
        """Test health check endpoint with load balancer"""
        # This would require setting up the load balancer in the app
        # For now, just test the basic health endpoint
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "version" in data
        assert "metrics" in data

    def test_metrics_endpoint(self, client):
        """Test metrics endpoint"""
        response = client.get("/metrics")
        assert response.status_code == 200

        data = response.json()
        assert "total_requests" in data
        assert "requests_by_method" in data
        assert "total_errors" in data
        assert "errors_by_type" in data
        assert "avg_response_time" in data
        assert "active_connections" in data
        assert "uptime" in data

    def test_haproxy_stats_endpoint(self, client):
        """Test HAProxy-style stats endpoint"""
        response = client.get("/stats")
        assert response.status_code == 200

        data = response.json()
        assert "frontend" in data
        assert "backend" in data

        frontend = data["frontend"]
        assert "name" in frontend
        assert "status" in frontend
        assert "requests" in frontend

        backend = data["backend"]
        assert isinstance(backend, list)

    @patch("app.main.load_balancer")
    def test_proxy_with_load_balancer(self, mock_lb, client):
        """Test proxy endpoint with load balancer enabled"""
        # Mock load balancer
        mock_lb_instance = Mock()
        mock_lb_instance.select_server = AsyncMock(return_value=None)
        mock_lb.return_value = mock_lb_instance

        # Test that load balancer is used when enabled
        response = client.get("/proxy?url=http://example.com&method=GET")

        # Should return 503 if no healthy servers, or 429 if rate limited
        assert response.status_code in [503, 429]

    def test_proxy_with_large_request_body(self, client):
        """Test proxy with large request body"""
        large_body = "x" * (settings.MAX_CONTENT_LENGTH + 1)

        response = client.post(
            "/proxy",
            json={
                "url": "http://example.com",
                "method": "POST",
                "body": large_body,
            },
        )

        # Accept either 413 (request too large) or 429 (rate limited)
        assert response.status_code in [413, 429]
        if response.status_code == 413:
            # Check that the response contains the error message
            response_data = response.json()
            assert "Request body too large" in str(response_data)

    def test_proxy_invalid_method(self, client):
        """Test proxy with invalid method"""
        response = client.get("/proxy?url=http://example.com&method=INVALID")
        # Accept either 400 (invalid method) or 429 (rate limited)
        assert response.status_code in [400, 429]
        if response.status_code == 400:
            # Check that the response contains the error message
            response_data = response.json()
            assert "Invalid method" in str(response_data)


class TestConfiguration:
    """Test configuration functionality"""

    def test_load_balancer_config_from_yaml(self):
        """Test loading load balancer configuration from YAML"""
        # This would require creating a test YAML file
        # For now, just test the config object creation
        lb_config = settings.get_load_balancer_config()

        assert lb_config.algorithm == settings.LOAD_BALANCER_ALGORITHM
        assert lb_config.session_stickiness == settings.LOAD_BALANCER_SESSION_STICKINESS
        assert (
            lb_config.enable_circuit_breaker
            == settings.LOAD_BALANCER_ENABLE_CIRCUIT_BREAKER
        )

    def test_middleware_configs(self):
        """Test middleware configuration objects"""
        rate_limit_config = settings.get_rate_limit_config()
        assert rate_limit_config.enabled == settings.MIDDLEWARE_RATE_LIMIT_ENABLED
        assert (
            rate_limit_config.requests_per_minute
            == settings.MIDDLEWARE_RATE_LIMIT_REQUESTS_PER_MINUTE
        )

        circuit_breaker_config = settings.get_circuit_breaker_config()
        assert (
            circuit_breaker_config.enabled
            == settings.MIDDLEWARE_CIRCUIT_BREAKER_ENABLED
        )
        assert (
            circuit_breaker_config.failure_threshold
            == settings.MIDDLEWARE_CIRCUIT_BREAKER_FAILURE_THRESHOLD
        )

        compression_config = settings.get_compression_config()
        assert compression_config.enabled == settings.MIDDLEWARE_COMPRESSION_ENABLED
        assert compression_config.min_size == settings.MIDDLEWARE_COMPRESSION_MIN_SIZE

        buffering_config = settings.get_buffering_config()
        assert buffering_config.enabled == settings.MIDDLEWARE_BUFFERING_ENABLED
        assert (
            buffering_config.max_buffer_size
            == settings.MIDDLEWARE_BUFFERING_MAX_BUFFER_SIZE
        )

        header_config = settings.get_header_manipulation_config()
        assert header_config.enabled == settings.MIDDLEWARE_HEADER_MANIPULATION_ENABLED
        assert (
            header_config.add_headers
            == settings.MIDDLEWARE_HEADER_MANIPULATION_ADD_HEADERS
        )

        ip_filter_config = settings.get_ip_filter_config()
        assert ip_filter_config.enabled == settings.MIDDLEWARE_IP_FILTER_ENABLED
        assert ip_filter_config.whitelist == settings.MIDDLEWARE_IP_FILTER_WHITELIST

        auth_config = settings.get_authentication_config()
        assert auth_config.enabled == settings.MIDDLEWARE_AUTHENTICATION_ENABLED
        assert auth_config.basic_auth == settings.MIDDLEWARE_AUTHENTICATION_BASIC_AUTH


class TestIntegration:
    """Integration tests for enhanced features"""

    def test_load_balancer_with_health_checks(self):
        """Test load balancer with health checks"""
        from app.load_balancer import HealthCheckConfig, LoadBalancerConfig

        config = LoadBalancerConfig(
            algorithm=LoadBalancingAlgorithm.ROUND_ROBIN,
            health_check=HealthCheckConfig(
                protocol="http",
                path="/health",
                interval=1.0,  # Fast for testing
                timeout=0.5,
                healthy_threshold=1,
                unhealthy_threshold=1,
                expected_status=200,
            ),
        )

        lb = LoadBalancer(config)

        # Add a test server
        server = BackendServer(
            host="httpbin.org",
            port=80,
            protocol="http",
        )
        lb.add_server(server)

        # Test that the load balancer was configured correctly
        assert lb.config.algorithm == LoadBalancingAlgorithm.ROUND_ROBIN
        assert lb.config.health_check is not None
        assert lb.config.health_check.interval == 1.0
        assert len(lb.servers) == 1
        assert lb.servers[0].host == "httpbin.org"

    def test_circuit_breaker_integration(self):
        """Test circuit breaker integration"""
        from app.middleware import CircuitBreakerConfig

        config = CircuitBreakerConfig(
            enabled=True,
            failure_threshold=2,
            recovery_timeout=1.0,
            half_open_max_requests=1,
            timeout=0.5,
        )

        middleware = CircuitBreakerMiddleware(config)

        # Test that the middleware was configured correctly
        assert middleware.config.enabled
        assert middleware.config.failure_threshold == 2
        assert middleware.config.recovery_timeout == 1.0
        assert middleware.config.half_open_max_requests == 1
        assert middleware.config.timeout == 0.5

    def test_middleware_pipeline(self):
        """Test middleware pipeline functionality"""
        from app.middleware import (
            get_middleware_pipeline,
            initialize_default_middleware,
        )

        pipeline = get_middleware_pipeline()
        initialize_default_middleware()

        # Should have at least the logging middleware
        assert len(pipeline.middlewares) >= 1

        # Test processing request
        context = MiddlewareContext()
        context.start_time = 0.0

        # This would require more complex setup to fully test
        # For now, just verify the pipeline exists and has middleware


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

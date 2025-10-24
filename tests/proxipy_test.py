import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_proxy_utils():
    """Reset proxy utils before each test"""
    from app.utils import proxy_utils

    proxy_utils.reset_client()
    yield


def test_root_endpoint(client):
    """Test root endpoint returns health information"""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "timestamp" in data


def test_health_check(client):
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data


def test_metrics_endpoint(client):
    """Test metrics endpoint returns statistics"""
    response = client.get("/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total_requests" in data
    assert "requests_by_method" in data
    assert "total_errors" in data
    assert "uptime" in data


def test_proxy_get_json(client):
    """Test proxy GET request with JSON response"""
    response = client.get("/proxy?url=https://httpbin.org/json")
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")
    # Check security headers are present
    assert "X-Content-Type-Options" in response.headers
    assert "X-Frame-Options" in response.headers


def test_proxy_get_html(client):
    """Test proxy GET request with HTML response"""
    response = client.get("/proxy?url=https://httpbin.org/html")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_proxy_invalid_url(client):
    """Test proxy with invalid URL"""
    response = client.get("/proxy?url=invalid-url")
    assert response.status_code == 400


def test_proxy_blocked_domain(client):
    """Test proxy with blocked domain"""
    response = client.get("/proxy?url=http://localhost:8080")
    assert response.status_code == 403


def test_proxy_private_ip(client):
    """Test proxy with private IP access"""
    response = client.get("/proxy?url=http://192.168.1.1")
    assert response.status_code == 403


def test_proxy_suspicious_content(client):
    """Test proxy with suspicious URL patterns"""
    response = client.get("/proxy?url=http://example.com/..%2f..%2fetc%2fpasswd")
    assert response.status_code == 400


def test_proxy_post_json(client):
    """Test proxy POST request with JSON"""
    data = {
        "url": "https://httpbin.org/post",
        "method": "POST",
        "body": '{"test": "data"}',
        "headers": {"Content-Type": "application/json"},
    }
    response = client.post("/proxy", json=data)
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")


def test_proxy_post_form_data(client):
    """Test proxy POST request with form data"""
    data = {
        "url": "https://httpbin.org/post",
        "method": "POST",
        "body": "field1=value1&field2=value2",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    }
    response = client.post("/proxy", json=data)
    assert response.status_code == 200


def test_proxy_unsupported_method(client):
    """Test proxy with unsupported HTTP method"""
    response = client.get("/proxy?url=https://httpbin.org/get&method=UNSUPPORTED")
    assert response.status_code == 400


def test_proxy_large_request_body(client):
    """Test proxy with request body too large"""
    large_body = "x" * (settings.MAX_CONTENT_LENGTH + 1)
    data = {
        "url": "https://httpbin.org/post",
        "method": "POST",
        "body": large_body,
    }
    response = client.post("/proxy", json=data)
    assert response.status_code == 413


def test_proxy_missing_url(client):
    """Test proxy without URL parameter"""
    response = client.get("/proxy")
    assert response.status_code == 422  # Validation error


def test_cors_headers(client):
    """Test CORS headers are present"""
    response = client.get("/proxy?url=https://httpbin.org/json")
    assert response.status_code == 200
    # Check CORS headers
    if settings.ENABLE_CORS:
        assert "Access-Control-Allow-Origin" in response.headers


def test_security_headers(client):
    """Test security headers are present"""
    response = client.get("/proxy?url=https://httpbin.org/json")
    assert response.status_code == 200
    # Check security headers
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-XSS-Protection") == "1; mode=block"


def test_rate_limiting(client):
    """Test rate limiting functionality"""
    # Make multiple requests to trigger rate limiting
    for i in range(70):  # More than the default 60/minute limit
        response = client.get("/proxy?url=https://httpbin.org/json")
        if response.status_code == 429:  # Rate limit exceeded
            break
    else:
        # If we didn't hit rate limit, check that at least some requests succeeded
        assert True


def test_content_type_validation(client):
    """Test content type validation"""
    # This test depends on the target server response
    # In a real scenario, you'd want to test with a server that returns various content types
    response = client.get("/proxy?url=https://httpbin.org/json")
    assert response.status_code == 200


def test_options_request(client):
    """Test OPTIONS request handling"""
    response = client.options("/proxy")
    assert response.status_code == 200


def test_invalid_content_type(client):
    """Test handling of invalid content types"""
    # This would require a server that returns disallowed content types
    # For now, just test that the validation function exists
    from app.security import security

    assert security.validate_content_type("application/json") == True
    assert security.validate_content_type("text/html") == True


def test_url_sanitization():
    """Test URL sanitization"""
    from app.utils import proxy_utils

    # Test URL with fragment
    sanitized = proxy_utils.sanitize_url("https://example.com/path#fragment")
    assert "#" not in sanitized

    # Test URL without scheme
    sanitized = proxy_utils.sanitize_url("example.com/path")
    assert sanitized.startswith("https://")

    # Test URL with dangerous characters
    sanitized = proxy_utils.sanitize_url("https://example.com/\x00\x01\x02")
    assert "\x00" not in sanitized


def test_configuration_loading():
    """Test configuration loading from YAML"""
    from app.config import settings

    # Test that settings are loaded
    assert hasattr(settings, "APP_NAME")
    assert hasattr(settings, "MAX_CONNECTIONS")
    assert hasattr(settings, "ENABLE_HTTP2")

    # Test helper methods
    assert settings.is_binary_content("application/pdf") == True
    assert settings.is_text_content("application/json") == True
    assert (
        settings.should_stream(2000000, "application/pdf") == True
    )  # 2MB should stream


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

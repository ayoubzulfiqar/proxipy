# Proxipy API Reference

This document provides comprehensive API documentation for the Proxipy CORS proxy server.

## Table of Contents

- [Core Endpoints](#core-endpoints)
- [Proxy Endpoints](#proxy-endpoints)
- [Health & Monitoring](#health--monitoring)
- [Request/Response Models](#requestresponse-models)
- [Error Handling](#error-handling)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)

## Core Endpoints

### Root Endpoint

**GET** `/`

Returns basic server information and version details.

**Response:**

```json
{
  "status": "healthy",
  "version": "2.0.0",
  "timestamp": "2024-10-20 15:30:45"
}
```

**Status Codes:**

- `200 OK` - Server is running normally

### Health Check

**GET** `/health`

Comprehensive health check including load balancer and middleware status.

**Response:**

```json
{
  "status": "healthy",
  "timestamp": 1697823456.789,
  "version": "2.0.0",
  "load_balancer": {
    "enabled": true,
    "algorithm": "round_robin",
    "total_servers": 2,
    "healthy_servers": 2,
    "unhealthy_servers": 0
  },
  "middleware": {
    "enabled": true,
    "middleware_count": 5
  },
  "metrics": {
    "total_requests": 1234,
    "requests_by_method": {
      "GET": 800,
      "POST": 434
    },
    "total_errors": 12,
    "errors_by_type": {
      "RateLimitExceeded": 5,
      "ConnectionError": 7
    },
    "avg_response_time": 125.4,
    "active_connections": 15,
    "uptime": 3600.5
  }
}
```

**Status Codes:**

- `200 OK` - Server is healthy
- `503 Service Unavailable` - Server or dependencies are unhealthy

### Metrics Endpoint

**GET** `/metrics`

Returns detailed performance metrics and statistics.

**Response:**

```json
{
  "total_requests": 1234,
  "requests_by_method": {
    "GET": 800,
    "POST": 434,
    "PUT": 0,
    "DELETE": 0,
    "PATCH": 0,
    "OPTIONS": 0
  },
  "total_errors": 12,
  "errors_by_type": {
    "RateLimitExceeded": 5,
    "ConnectionError": 7
  },
  "avg_response_time": 125.4,
  "active_connections": 15,
  "uptime": 3600.5
}
```

**Status Codes:**

- `200 OK` - Metrics retrieved successfully

### HAProxy-style Statistics

**GET** `/stats`

Returns load balancer statistics in HAProxy-compatible format.

**Response:**

```json
{
  "frontend": {
    "name": "frontend",
    "status": "OPEN",
    "requests": 1234,
    "bytes_in": 0,
    "bytes_out": 0,
    "session_rate": 0
  },
  "backend": [
    {
      "name": "backend1.example.com:8080",
      "status": "UP",
      "current_connections": 5,
      "max_connections": 100,
      "response_time": 45.2,
      "consecutive_failures": 0,
      "consecutive_successes": 150,
      "weight": 1,
      "is_healthy": true
    },
    {
      "name": "backend2.example.com:8080",
      "status": "UP",
      "current_connections": 3,
      "max_connections": 100,
      "response_time": 32.1,
      "consecutive_failures": 0,
      "consecutive_successes": 120,
      "weight": 2,
      "is_healthy": true
    }
  ]
}
```

**Status Codes:**

- `200 OK` - Statistics retrieved successfully

## Proxy Endpoints

### GET Proxy

**GET** `/proxy`

Proxy GET requests with optional method parameter.

**Query Parameters:**

- `url` (required): Target URL to proxy
- `method` (optional): HTTP method (default: "GET", valid: "GET", "HEAD", "OPTIONS")

**Example:**

```
GET /proxy?url=https://api.example.com/data&method=GET
```

**Response:**

- Proxied response from target server
- All headers preserved (except security-filtered ones)
- Content-Type and Content-Length updated appropriately

**Status Codes:**

- `200 OK` - Request proxied successfully
- `400 Bad Request` - Invalid URL or method
- `403 Forbidden` - Blocked domain or IP
- `413 Payload Too Large` - Request body too large
- `415 Unsupported Media Type` - Invalid content type
- `429 Too Many Requests` - Rate limit exceeded
- `502 Bad Gateway` - Backend server error
- `503 Service Unavailable` - No healthy backend servers

### POST Proxy

**POST** `/proxy`

Proxy requests with custom method, headers, and body.

**Request Body:**

```json
{
  "url": "https://api.example.com/data",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json",
    "Authorization": "Bearer token"
  },
  "body": "{\"key\": \"value\"}"
}
```

**Fields:**

- `url` (required): Target URL to proxy
- `method` (required): HTTP method (enum: "GET", "POST", "PUT", "DELETE", "PATCH")
- `headers` (optional): Custom headers to send
- `body` (optional): Request body content

**Response:**

- Proxied response from target server
- All headers preserved (except security-filtered ones)
- Content-Type and Content-Length updated appropriately

**Status Codes:**

- `200 OK` - Request proxied successfully
- `400 Bad Request` - Invalid request format
- `403 Forbidden` - Blocked domain or IP
- `413 Payload Too Large` - Request body too large
- `415 Unsupported Media Type` - Invalid content type
- `429 Too Many Requests` - Rate limit exceeded
- `502 Bad Gateway` - Backend server error
- `503 Service Unavailable` - No healthy backend servers

### Other HTTP Methods

**PUT** `/proxy`
**DELETE** `/proxy`
**PATCH** `/proxy`

Same interface as POST proxy, but method is inferred from HTTP verb.

**Request Body:**

```json
{
  "url": "https://api.example.com/data",
  "headers": {
    "Content-Type": "application/json",
    "Authorization": "Bearer token"
  },
  "body": "{\"key\": \"value\"}"
}
```

**OPTIONS** `/proxy`

CORS preflight request handler.

**Response:**

```json
{
  "message": "OK"
}
```

## Request/Response Models

### ProxyRequest Model

```python
class ProxyRequest(BaseModel):
    url: str
    method: HTTPMethod
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
```

**Fields:**

- `url`: Target URL (must be valid HTTP/HTTPS)
- `method`: HTTP method (GET, POST, PUT, DELETE, PATCH)
- `headers`: Optional custom headers
- `body`: Optional request body (string format)

### HTTPMethod Enum

```python
class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
```

### HealthResponse Model

```python
class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
```

## Error Handling

### Standard Error Response

All error responses follow this format:

```json
{
  "error": "Error description"
}
```

### Error Types

#### 400 Bad Request

- **Invalid URL**: Malformed or missing URL
- **Invalid Method**: Unsupported HTTP method
- **Invalid Request Body**: Malformed JSON or invalid fields

#### 403 Forbidden

- **Blocked Domain**: Target domain is in blacklist
- **Private IP Access**: Attempting to access private IP range
- **Suspicious Content**: URL contains suspicious patterns

#### 413 Payload Too Large

- **Request Body Too Large**: Exceeds `max_content_length` configuration
- **Response Too Large**: Target response exceeds size limits

#### 415 Unsupported Media Type

- **Invalid Content Type**: Target server returns unsupported content type
- **Security Violation**: Content type violates security policies

#### 429 Too Many Requests

- **Rate Limit Exceeded**: Client exceeded rate limits
- **Burst Limit Exceeded**: Too many requests in burst period

#### 502 Bad Gateway

- **Backend Error**: Target server returned error
- **Connection Failed**: Unable to connect to target server
- **Timeout**: Request timed out

#### 503 Service Unavailable

- **No Healthy Servers**: All backend servers are unhealthy
- **Circuit Breaker Open**: Circuit breaker is open
- **Service Overloaded**: Server is temporarily unavailable

### Security Headers

All responses include security headers:

```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
```

## Authentication

### Basic Authentication

**Configuration:**

```yaml
middleware:
  authentication:
    enabled: true
    basic_auth:
      "admin": "password123"
      "user": "userpass"
```

**Usage:**

```bash
curl -u admin:password123 http://localhost:6969/proxy?url=https://api.example.com/data
```

### JWT Authentication (Framework Ready)

**Configuration:**

```yaml
middleware:
  authentication:
    enabled: true
    jwt_secret: "your-jwt-secret"
    jwt_algorithm: "HS256"
    required_scopes: ["proxy:read", "proxy:write"]
```

**Usage:**

```bash
curl -H "Authorization: Bearer your-jwt-token" http://localhost:6969/proxy?url=https://api.example.com/data
```

## Rate Limiting

### Rate Limit Headers

All responses include rate limiting information:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 58
X-RateLimit-Reset: 1697823456
X-RateLimit-Burst-Remaining: 8
```

### Rate Limit Configuration

**Configuration:**

```yaml
rate_limiting:
  enabled: true
  rate_limit_per_minute: 60
  rate_limit_per_hour: 1000
  rate_limit_burst: 10
```

### Rate Limit Response

When rate limit is exceeded:

**Status:** `429 Too Many Requests`

**Headers:**

```
Retry-After: 55
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1697823456
```

**Body:**

```json
{
  "error": "Rate limit exceeded. Try again in 55 seconds."
}
```

## Load Balancer Integration

### Automatic Load Balancing

When load balancer is enabled, all proxy requests are automatically distributed across backend servers using the configured algorithm.

### Session Persistence

**Cookie-based:**

```
Set-Cookie: PROXIPY_SESSION=server1; Path=/; Max-Age=3600
```

**IP-based:**

- Automatic based on client IP hash
- No additional configuration required

### Health Check Integration

Backend servers are automatically monitored and removed from rotation when unhealthy.

## Performance Considerations

### Streaming vs Buffering

- **Files < 1MB**: Buffered in memory for faster response
- **Files ≥ 1MB**: Streamed directly to client
- **Binary Content**: Always streamed regardless of size

### Connection Pooling

- **Max Connections**: Configurable connection pool size
- **Connection Reuse**: HTTP connections are reused when possible
- **Timeout Handling**: Configurable timeouts for all operations

### Caching (Future)

- **Response Caching**: Planned for future versions
- **DNS Caching**: Automatic DNS resolution caching
- **Health Check Caching**: Health check results cached for performance

## Monitoring Integration

### Prometheus Metrics (Future)

Planned metrics for Prometheus integration:

- Request rate
- Error rate
- Response time percentiles
- Backend server health
- Circuit breaker state

### Custom Metrics

Current metrics available via `/metrics` endpoint:

- Total requests by method
- Error counts by type
- Average response time
- Active connections
- Uptime

## Security Best Practices

### Input Validation

- URL validation and sanitization
- Content type validation
- Request size limits
- Suspicious pattern detection

### Output Security

- Security headers on all responses
- Content type sanitization
- Header filtering
- XSS protection

### Network Security

- Private IP range blocking
- Domain blacklisting
- TLS enforcement options
- CORS policy configuration

## Troubleshooting

### Common Issues

#### 502 Bad Gateway

- Check target server availability
- Verify URL format
- Check network connectivity

#### 403 Forbidden

- Verify target domain is not blocked
- Check private IP access restrictions
- Review suspicious pattern detection

#### 429 Too Many Requests

- Check rate limit configuration
- Verify client IP is not blocked
- Review burst limit settings

#### 503 Service Unavailable

- Check load balancer configuration
- Verify backend server health
- Review circuit breaker state

### Debug Mode

Enable debug mode for detailed logging:

```yaml
server:
  debug: true
```

### Log Analysis

Check proxy.log for detailed request/response information:

- Request timestamps
- Response times
- Error details
- Security violations

## Client Libraries

### JavaScript/TypeScript

```typescript
class ProxipyClient {
  constructor(private baseUrl: string) {}

  async get<T>(url: string): Promise<T> {
    const response = await fetch(`${this.baseUrl}/proxy?url=${encodeURIComponent(url)}`);
    return response.json();
  }

  async post<T>(url: string, data: any): Promise<T> {
    const response = await fetch(`${this.baseUrl}/proxy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url,
        method: 'POST',
        body: JSON.stringify(data)
      })
    });
    return response.json();
  }
}
```

### Python

```python
import requests
import json

class ProxipyClient:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def get(self, url: str):
        response = requests.get(f"{self.base_url}/proxy", params={"url": url})
        response.raise_for_status()
        return response.json()

    def post(self, url: str, data: dict):
        payload = {
            "url": url,
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(data)
        }
        response = requests.post(f"{self.base_url}/proxy", json=payload)
        response.raise_for_status()
        return response.json()
```

## Version Compatibility

### API Stability

- **v2.x.x**: Current major version with full feature set
- **v1.x.x**: Legacy version with basic proxy functionality
- **Backward Compatibility**: v2 maintains compatibility with v1 API

### Breaking Changes

- **v2.0.0**: Added load balancing and middleware (non-breaking)
- **v1.0.0**: Initial release

## Support

For API-related questions:

- Check this documentation
- Review the test suite for examples
- Create an issue on GitHub
- Check the implementation summary for technical details

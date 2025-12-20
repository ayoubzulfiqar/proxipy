# Proxipy

A **production-ready, high-performance, secure CORS proxy server** built with FastAPI to bypass same-origin policy and prevent mixed content issues. Features intelligent streaming, comprehensive security, advanced load balancing, and robust concurrency handling.

## 🚀 Features

### Core Features

- **✅ CORS Proxy**: Bypass same-origin policy for AJAX requests
- **✅ HTTP/2 Support**: Full HTTP/2 support when using TLS
- **✅ Mixed Content Fix**: Proxy resources to serve them under HTTPS
- **✅ High Performance**: Optimized for high throughput and low latency
- **✅ Universal Content-Type Support**: Handles all content types including images, videos, audio, documents, and binary files
- **✅ Intelligent Streaming**: Automatically streams large files and binary content for better performance
- **✅ Content-Type Detection**: Smart detection of binary vs text content for optimal handling

### 🏗️ Advanced Architecture

- **✅ Load Balancing**: Multiple algorithms (Round Robin, Weighted, Least Connections, etc.)
- **✅ Health Checks**: Automated backend server health monitoring
- **✅ Circuit Breaker**: Prevents cascading failures
- **✅ Session Stickiness**: Cookie and IP-based session persistence
- **✅ Multi-Protocol Support**: HTTP, HTTPS, WebSocket, TCP, UDP
- **✅ Advanced Middleware**: Authentication, Rate Limiting, Compression, Buffering, IP Filtering

### 🔒 Security Features

- **✅ Rate Limiting**: Configurable rate limiting per client IP with Redis/memory fallback
- **✅ Request Validation**: Comprehensive URL and request validation
- **✅ Security Headers**: Automatic security headers (CSP, HSTS, XSS protection, etc.)
- **✅ Cross-Origin Policies**: Configurable CORP, COEP, and COOP headers for enhanced security
- **✅ Blocked Hosts**: Configurable list of blocked hosts/IPs
- **✅ Private IP Protection**: Prevents access to private IP ranges
- **✅ HTTPS Enforcement**: Optional HTTPS-only mode
- **✅ Suspicious Pattern Detection**: Blocks directory traversal and injection attempts

### 📊 Monitoring & Analytics

- **✅ Structured Logging**: JSON or text format logging with configurable levels
- **✅ Request Tracking**: Detailed request/response logging with metrics
- **✅ Health Checks**: Built-in health check endpoint
- **✅ HAProxy-style Stats**: Comprehensive load balancer statistics
- **✅ Performance Metrics**: Real-time performance monitoring
- **✅ Circuit Breaker Metrics**: Failure and recovery tracking

### ⚙️ Configuration

- **✅ YAML Configuration**: Easy-to-use YAML configuration with hot reload support
- **✅ Environment Variables**: Support for environment-based configuration
- **✅ Flexible Settings**: Highly configurable for different use cases
- **✅ Middleware Pipeline**: Configurable middleware stack with priority ordering

## 📁 Project Structure

```html
proxipy/
├── app/
│   ├── __init__.py
│   ├── main.py              # Main FastAPI application with enhanced proxy logic
│   ├── config.py            # Enhanced configuration with YAML support
│   ├── security.py          # Comprehensive security middleware
│   ├── rate_limiter.py      # Advanced rate limiting with Redis support
│   ├── load_balancer.py     # Advanced load balancing with health checks
│   ├── middleware.py        # Modular middleware system
│   ├── protocols.py         # Multi-protocol proxy support
│   ├── model.py             # Pydantic models for requests/responses
│   └── utils.py             # Enhanced proxy utilities with streaming
├── tests/
│   ├── __init__.py
│   ├── proxipy_test.py      # Comprehensive test suite
│   └── test_enhanced_features.py  # Enhanced features testing
├── config.yaml              # YAML configuration file
├── requirements.txt         # Python dependencies
├── Dockerfile              # Docker configuration
├── docker-compose.yml      # Docker Compose setup
├── nginx.conf              # Nginx reverse proxy configuration
├── ARCHITECTURE_ANALYSIS.md    # Detailed architecture documentation
├── IMPLEMENTATION_SUMMARY.md   # Implementation details
└── README.md               # This file
```

## 🛠️ Installation

### Prerequisites

- Python 3.8+
- Redis (optional, for enhanced rate limiting)

### Local Development

```bash
# Clone the repository
git clone https://github.com/ayoubzulfiqar/proxipy.git
cd proxipy

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python -m app.main
```

### Using Docker Compose (Recommended)

```bash
# Start with Docker Compose
docker-compose up -d

# Or build and run manually
docker build -t proxipy .
docker run -p 6969:6969 proxipy
```

### Using Docker

```bash
# Build the image
docker build -t proxipy .

# Run the container
docker run -d \
  --name proxipy \
  -p 6969:6969 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  proxipy
```

## ⚙️ Configuration

The proxy server supports both environment variables and YAML configuration files.

### Quick Start Configuration

Create a `config.yaml` file:

```yaml
# Server Configuration
server:
  name: "CORS Proxy Server"
  version: "2.0.0"
  debug: false
  host: "0.0.0.0"
  port: 6969

# Load Balancer Configuration
load_balancer:
  enabled: true
  algorithm: "round_robin"
  backend_servers:
    - host: "backend1.example.com"
      port: 8080
      weight: 1
    - host: "backend2.example.com"
      port: 8080
      weight: 2

# Security
security:
  allowed_hosts: ["*"]
  max_content_length: 52428800  # 50MB

# Rate Limiting
rate_limiting:
  enabled: true
  rate_limit_per_minute: 60
  rate_limit_per_hour: 1000

# Middleware
middleware:
  rate_limit:
    enabled: true
    requests_per_minute: 60
  compression:
    enabled: true
    min_size: 1024
```

### Environment Variables

```bash
export DEBUG=true
export PORT=6969
export RATE_LIMIT_PER_MINUTE=100
export REDIS_URL=redis://localhost:6379
export ENABLE_HTTP2=true
```

## 📖 Usage

### Basic Proxy Usage

```javascript
// Simple GET request
const response = await fetch('http://localhost:6969/proxy?url=https://api.example.com/data');
const data = await response.json();
```

### Advanced Proxy with Load Balancing

```javascript
// The proxy automatically load balances across backend servers
const response = await fetch('http://localhost:6969/proxy?url=https://api.example.com/data');
```

### POST Request with Custom Headers

```javascript
const response = await fetch('http://localhost:6969/proxy', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        url: 'https://api.example.com/data',
        method: 'POST',
        body: JSON.stringify({key: 'value'}),
        headers: {
            'Authorization': 'Bearer token'
        }
    })
});
```

### Python Client

```python
import requests

def proxy_get(target_url):
    proxy_url = "http://localhost:6969/proxy"
    params = {"url": target_url}
    response = requests.get(proxy_url, params=params)
    return response.json()

def proxy_post(target_url, data):
    proxy_url = "http://localhost:6969/proxy"
    payload = {
        "url": target_url,
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(data)
    }
    response = requests.post(proxy_url, json=payload)
    return response.json()
```

## 🔧 API Endpoints

### Health & Monitoring

- `GET /` - Root endpoint with server information
- `GET /health` - Health check endpoint with load balancer status
- `GET /metrics` - Performance metrics and statistics
- `GET /stats` - HAProxy-style load balancer statistics
- `GET /docs` - Interactive API documentation (Swagger UI)
- `GET /redoc` - Alternative API documentation (ReDoc)

### Proxy Endpoints

- `GET /proxy?url=<target_url>` - Proxy GET requests with load balancing
- `POST /proxy` - Proxy requests with body and custom headers
- `PUT /proxy` - Proxy PUT requests
- `DELETE /proxy` - Proxy DELETE requests
- `PATCH /proxy` - Proxy PATCH requests
- `OPTIONS /proxy` - CORS preflight requests

## 🏗️ Load Balancer Features

### Supported Algorithms

- **Round Robin**: Distribute requests evenly across servers
- **Weighted Round Robin**: Distribute based on server weights
- **Least Connections**: Send to server with fewest active connections
- **Weighted Least Connections**: Weighted version of least connections
- **Least Response Time**: Send to server with fastest response time
- **Source IP Hash**: Distribute based on client IP hash
- **URI Hash**: Distribute based on request URI hash
- **Header Hash**: Distribute based on custom header hash
- **Random**: Randomly select servers

### Health Checks

- **TCP Health Checks**: Basic connectivity testing
- **HTTP/HTTPS Health Checks**: HTTP status code validation
- **Configurable Intervals**: Custom health check timing
- **Failure Thresholds**: Configurable failure counts
- **Automatic Recovery**: Servers automatically recover when healthy

### Session Persistence

- **Cookie-based**: Session stickiness via cookies
- **IP-based**: Session affinity based on client IP
- **Configurable Timeout**: Custom session timeout settings

## 🔒 Security Features

### Rate Limiting

- **Per-minute and per-hour limits**
- **Redis-backed storage with memory fallback**
- **IP-based rate limiting**
- **Burst allowance support**

### Content Security

- **Comprehensive content-type validation**
- **Binary content streaming for large files**
- **Text content buffering for small responses**
- **Suspicious pattern detection and blocking**

### Network Security

- **Private IP range protection**
- **Domain/IP blacklisting**
- **URL sanitization and validation**
- **Header sanitization**

### Authentication

- **Basic HTTP Authentication**
- **JWT Token Support** (framework ready)
- **Client Certificate Support** (framework ready)

## 📊 Monitoring & Analytics

### Health Check Endpoint

```bash
curl http://localhost:6969/health
```

Response:

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
    "requests_by_method": {"GET": 800, "POST": 434},
    "total_errors": 12,
    "errors_by_type": {"RateLimitExceeded": 5, "ConnectionError": 7},
    "avg_response_time": 125.4,
    "active_connections": 15,
    "uptime": 3600.5
  }
}
```

### HAProxy-style Statistics

```bash
curl http://localhost:6969/stats
```

Response:

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

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=app

# Run specific test
pytest tests/proxipy_test.py::test_proxy_get_json -v

# Run enhanced features tests
pytest tests/test_enhanced_features.py -v
```

## 🚀 Deployment

### Production Deployment

1. Set `DEBUG=false` in configuration
2. Use a reverse proxy (nginx) for SSL termination
3. Configure Redis for rate limiting
4. Set up monitoring and logging
5. Use environment variables for sensitive settings

### Docker Production

```bash
# Build for production
docker build -t proxipy:latest .

# Run with environment variables
docker run -d \
  --name proxipy \
  -p 6969:6969 \
  -e REDIS_URL=redis://redis:6379 \
  -e DEBUG=false \
  --restart unless-stopped \
  proxipy
```

### Nginx Configuration

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:6969;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 📈 Performance Optimization

### Connection Pooling

```yaml
performance:
  max_connections: 100
  connection_timeout: 30.0
  read_timeout: 60.0
  write_timeout: 30.0
```

### Streaming Configuration

```yaml
proxy:
  stream_threshold: 1048576  # 1MB
  enable_compression: true
```

### Load Balancer Tuning

```yaml
load_balancer:
  algorithm: "least_response_time"
  health_check:
    interval: 10.0
    timeout: 3.0
    healthy_threshold: 2
    unhealthy_threshold: 3
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Development Setup

```bash
# Clone and setup
git clone https://github.com/ayoubzulfiqar/proxipy.git
cd proxipy
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run with linting
pylint app/
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:

- Create an issue on GitHub
- Check the documentation
- Review the test suite for examples

## 📚 Additional Documentation

- **[Architecture Analysis](ARCHITECTURE_ANALYSIS.md)** - Detailed system architecture
- **[Implementation Summary](IMPLEMENTATION_SUMMARY.md)** - Complete implementation details
- **[Configuration Guide](config.yaml)** - Comprehensive configuration examples

## 🔄 Changelog

### v2.0.0 (Current)

- **🏗️ Advanced Load Balancing**: Multiple algorithms with health checks
- **🔧 Modular Middleware**: Authentication, Rate Limiting, Compression, Buffering, IP Filtering
- **🌐 Multi-Protocol Support**: HTTP, HTTPS, WebSocket, TCP, UDP
- **📊 Enhanced Monitoring**: HAProxy-style stats, performance metrics
- **🔒 Advanced Security**: Circuit breaker, enhanced validation
- **⚙️ YAML Configuration**: Comprehensive configuration system
- **🧪 Comprehensive Testing**: Full test coverage for all features

### v1.0.0

- Initial release with basic proxy functionality
- Rate limiting and security features
- Docker support

## 🎯 Use Cases

### Enterprise Applications

- **Microservices Communication**: Load balance between multiple service instances
- **API Gateway**: Centralized proxy with security and monitoring
- **Content Delivery**: Efficient streaming of large files and media

### Development & Testing

- **CORS Bypass**: Development proxy for cross-origin requests
- **API Testing**: Mock and proxy external APIs
- **Load Testing**: Simulate traffic across multiple backends

### Production Deployments

- **High Availability**: Automatic failover with health checks
- **Performance Optimization**: Connection pooling and intelligent streaming
- **Security Enhancement**: Comprehensive security headers and validation

---

**Proxipy**: Your production-ready solution for secure, high-performance CORS proxying with advanced load balancing and monitoring capabilities. 🚀

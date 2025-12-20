# Proxipy

A **production-ready, high-performance, secure CORS proxy server** built with FastAPI to bypass same-origin policy and prevent mixed content issues. Features intelligent streaming, comprehensive security, and robust concurrency handling.

## 🚀 Features

### Core Features

- **✅ CORS Proxy**: Bypass same-origin policy for AJAX requests
- **✅ HTTP/2 Support**: Full HTTP/2 support when using TLS
- **✅ Mixed Content Fix**: Proxy resources to serve them under HTTPS
- **✅ High Performance**: Optimized for high throughput and low latency
- **✅ Universal Content-Type Support**: Handles all content types including images, videos, audio, documents, and binary files
- **✅ Intelligent Streaming**: Automatically streams large files and binary content for better performance
- **✅ Content-Type Detection**: Smart detection of binary vs text content for optimal handling

### 🔒 Security Features

- **✅ Rate Limiting**: Configurable rate limiting per client IP with Redis/memory fallback
- **✅ Request Validation**: Comprehensive URL and request validation
- **✅ Security Headers**: Automatic security headers (CSP, HSTS, XSS protection, etc.)
- **✅ Cross-Origin Policies**: Configurable CORP, COEP, and COOP headers for enhanced security
- **✅ Blocked Hosts**: Configurable list of blocked hosts/IPs
- **✅ Private IP Protection**: Prevents access to private IP ranges
- **✅ HTTPS Enforcement**: Optional HTTPS-only mode
- **✅ Suspicious Pattern Detection**: Blocks directory traversal and injection attempts

### 📊 Monitoring & Logging

- **✅ Structured Logging**: JSON or text format logging with configurable levels
- **✅ Request Tracking**: Detailed request/response logging with metrics
- **✅ Health Checks**: Built-in health check endpoint
- **✅ Metrics**: Comprehensive rate limiting metrics and performance statistics

### ⚙️ Configuration

- **✅ YAML Configuration**: Easy-to-use YAML configuration with hot reload support
- **✅ Environment Variables**: Support for environment-based configuration
- **✅ Flexible Settings**: Highly configurable for different use cases

## 📁 Project Structure

```html
proxypy/
├── app/
│   ├── __init__.py
│   ├── main.py          # Main FastAPI application with enhanced proxy logic
│   ├── config.py        # Enhanced configuration with YAML support
│   ├── security.py      # Comprehensive security middleware
│   ├── rate_limiter.py  # Advanced rate limiting with Redis support
│   ├── model.py         # Pydantic models for requests/responses
│   └── utils.py         # Enhanced proxy utilities with streaming
├── tests/
│   ├── __init__.py
│   └── proxipy_test.py  # Comprehensive test suite
├── config.yaml          # YAML configuration file
├── requirements.txt     # Python dependencies
├── Dockerfile          # Docker configuration
├── docker-compose.yml  # Docker Compose setup
├── nginx.conf          # Nginx reverse proxy configuration
└── README.md           # This file
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

### Environment Variables

```bash
export DEBUG=true
export PORT=6969
export RATE_LIMIT_PER_MINUTE=100
export REDIS_URL=redis://localhost:6379
export ENABLE_HTTP2=true
```

### YAML Configuration

Create a `config.yaml` file:

```yaml
# Server Configuration
app_name: "CORS Proxy Server"
debug: false
host: "0.0.0.0"
port: 6969

# Performance & Concurrency
max_connections: 100
max_workers: 4
stream_threshold: 1048576  # 1MB

# Security
enable_csp: true
enable_hsts: true
enable_cors: true
enable_corp: true
enable_coep: true
enable_coop: true

# Rate Limiting
rate_limit_enabled: true
rate_limit_per_minute: 60
rate_limit_per_hour: 1000

# Content Types (automatically configured)
allowed_content_types:
  - "application/json"
  - "text/html"
  - "image/jpeg"
  - "video/mp4"
  # ... and many more
```

## 📖 Usage

### GET Request

```javascript
// Simple GET request
const response = await fetch('http://localhost:6969/proxy?url=https://api.example.com/data');
const data = await response.json();
```

### POST Request

```javascript
// POST request with body
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

### Health & Metrics

- `GET /` - Root endpoint with server information
- `GET /health` - Health check endpoint
- `GET /metrics` - Performance metrics and statistics
- `GET /docs` - Interactive API documentation (Swagger UI)
- `GET /redoc` - Alternative API documentation (ReDoc)

### Proxy Endpoints

- `GET /proxy?url=<target_url>` - Proxy GET requests
- `POST /proxy` - Proxy requests with body and custom headers
- `PUT /proxy` - Proxy PUT requests
- `DELETE /proxy` - Proxy DELETE requests
- `PATCH /proxy` - Proxy PATCH requests
- `OPTIONS /proxy` - CORS preflight requests

## 🔒 Security Features

### Rate Limiting

- Per-minute and per-hour limits
- Redis-backed storage with memory fallback
- Different limits for different endpoints
- IP-based rate limiting

### Content Security

- Comprehensive content-type validation
- Binary content streaming for large files
- Text content buffering for small responses
- Suspicious pattern detection and blocking

### Network Security

- Private IP range protection
- Domain/IP blacklisting
- URL sanitization and validation
- Header sanitization

## 📊 Performance Features

### Intelligent Streaming

- Automatic detection of binary vs text content
- Streaming for files larger than 1MB
- Connection pooling for optimal performance
- HTTP/2 support for better throughput

### Concurrency

- Async/await architecture
- Connection pooling with semaphore limits
- Thread-safe metrics collection
- Background task processing

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=app

# Run specific test
pytest tests/proxipy_test.py::test_proxy_get_json -v
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

## 📈 Monitoring

The proxy server provides comprehensive monitoring:

```bash
# Health check
curl http://localhost:6969/health

# Metrics
curl http://localhost:6969/metrics

# Check logs
tail -f proxy.log
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:

- Create an issue on GitHub
- Check the documentation
- Review the test suite for examples

## 🔄 Changelog

### v1.0.0

- Initial release with basic proxy functionality
- Rate limiting and security features
- Docker support

### v2.0.0 (Current)

- **Intelligent streaming** for large files
- **Enhanced security** with comprehensive validation
- **HTTP/2 support** and connection pooling
- **YAML configuration** with hot reload
- **Advanced metrics** and monitoring
- **Comprehensive test suite**
- **Cross-origin policies** (CORP, COEP, COOP)
- **Universal content-type support**

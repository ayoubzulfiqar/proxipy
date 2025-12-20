# Proxipy Configuration Guide

This guide provides comprehensive information on configuring the Proxipy CORS proxy server for various use cases and environments.

## Table of Contents

- [Configuration Overview](#configuration-overview)
- [Configuration Methods](#configuration-methods)
- [Server Configuration](#server-configuration)
- [Load Balancer Configuration](#load-balancer-configuration)
- [Security Configuration](#security-configuration)
- [Middleware Configuration](#middleware-configuration)
- [Performance Tuning](#performance-tuning)
- [Monitoring & Logging](#monitoring--logging)
- [Environment-Specific Configs](#environment-specific-configs)
- [Advanced Configuration](#advanced-configuration)

## Configuration Overview

Proxipy supports multiple configuration methods:

1. **YAML Configuration File** (`config.yaml`) - Primary method
2. **Environment Variables** - For deployment and secrets
3. **Python Configuration** - Programmatic configuration

The configuration system is hierarchical with environment variables taking precedence over YAML values.

## Configuration Methods

### 1. YAML Configuration File

Create a `config.yaml` file in your project root:

```yaml
# Basic configuration
server:
  name: "My CORS Proxy"
  version: "2.0.0"
  debug: false
  host: "0.0.0.0"
  port: 6969

# Security settings
security:
  allowed_hosts: ["*"]
  max_content_length: 52428800  # 50MB

# Rate limiting
rate_limiting:
  enabled: true
  rate_limit_per_minute: 100
```

### 2. Environment Variables

Environment variables override YAML configuration:

```bash
export DEBUG=true
export PORT=8080
export REDIS_URL=redis://localhost:6379
export RATE_LIMIT_PER_MINUTE=200
```

### 3. Python Configuration

For programmatic configuration:

```python
from app.config import settings

# Override specific settings
settings.server.debug = True
settings.rate_limiting.rate_limit_per_minute = 500
```

## Server Configuration

### Basic Server Settings

```yaml
server:
  name: "CORS Proxy Server"
  version: "2.0.0"
  debug: false
  host: "0.0.0.0"
  port: 6969
```

**Environment Variables:**

- `DEBUG` - Enable debug mode
- `HOST` - Server host
- `PORT` - Server port

### Performance Settings

```yaml
performance:
  max_connections: 100
  max_workers: 4
  connection_timeout: 30.0
  read_timeout: 60.0
  write_timeout: 30.0
  stream_chunk_size: 8192
  max_response_size: 104857600  # 100MB
```

**Environment Variables:**

- `MAX_CONNECTIONS` - Maximum concurrent connections
- `MAX_WORKERS` - Number of worker processes
- `CONNECTION_TIMEOUT` - Connection timeout in seconds
- `READ_TIMEOUT` - Read timeout in seconds
- `WRITE_TIMEOUT` - Write timeout in seconds

## Load Balancer Configuration

### Basic Load Balancer Setup

```yaml
load_balancer:
  enabled: true
  algorithm: "round_robin"
  session_stickiness: false
  session_timeout: 3600
```

### Load Balancer Algorithms

Choose from these algorithms:

```yaml
load_balancer:
  algorithm: "round_robin"           # Distribute evenly
  # algorithm: "weighted_round_robin"    # Weighted distribution
  # algorithm: "least_connections"       # Fewest active connections
  # algorithm: "least_response_time"     # Fastest response time
  # algorithm: "source_ip_hash"          # IP-based distribution
  # algorithm: "uri_hash"                # URI-based distribution
  # algorithm: "header_hash"             # Custom header hash
  # algorithm: "random"                  # Random selection
  # algorithm: "weighted_least_connections"  # Weighted least connections
```

### Backend Server Configuration

```yaml
load_balancer:
  backend_servers:
    - host: "backend1.example.com"
      port: 8080
      protocol: "http"
      weight: 1
      max_connections: 100
    - host: "backend2.example.com"
      port: 8080
      protocol: "https"
      weight: 2  # Higher weight = more traffic
      max_connections: 100
```

### Health Check Configuration

```yaml
load_balancer:
  health_check:
    protocol: "http"
    path: "/health"
    port: null  # Uses server port if null
    interval: 30.0
    timeout: 5.0
    healthy_threshold: 2
    unhealthy_threshold: 3
    expected_status: 200
```

### Circuit Breaker Configuration

```yaml
load_balancer:
  enable_circuit_breaker: true
  circuit_breaker_failure_threshold: 5
  circuit_breaker_recovery_timeout: 60.0
```

## Security Configuration

### Basic Security Settings

```yaml
security:
  secret_key: "your-secret-key-change-in-production"
  allowed_hosts: ["*"]
  allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]
  allowed_headers: ["*"]
  max_content_length: 52428800  # 50MB
```

### Security Headers

```yaml
security:
  enable_csp: true
  enable_hsts: true
  enable_https_only: false
  enable_cors: true
  enable_corp: true
  enable_coep: true
  enable_coop: true
```

### Content Type Security

```yaml
content_types:
  stream_threshold: 1048576  # 1MB
  binary_content_types:
    - "application/octet-stream"
    - "application/pdf"
    - "image/jpeg"
    - "video/mp4"
    - "audio/mpeg"
  text_content_types:
    - "application/json"
    - "text/html"
    - "application/javascript"
```

### Blocked Domains

```yaml
blocked_domains:
  - "localhost"
  - "127.0.0.1"
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "172.16.0.0/12"
```

## Middleware Configuration

### Middleware Pipeline

```yaml
middleware:
  enabled: true
  
  # Rate Limiting Middleware
  rate_limit:
    enabled: true
    requests_per_minute: 60
    requests_per_hour: 1000
    burst_size: 10
    block_duration: 300.0

  # Circuit Breaker Middleware
  circuit_breaker:
    enabled: true
    failure_threshold: 5
    recovery_timeout: 60.0
    half_open_max_requests: 3
    timeout: 30.0

  # Compression Middleware
  compression:
    enabled: true
    min_size: 1024
    compression_level: 6
    supported_encodings: ["gzip", "deflate"]

  # Buffering Middleware
  buffering:
    enabled: true
    max_buffer_size: 1048576  # 1MB
    buffer_timeout: 5.0
    enable_streaming: true

  # Header Manipulation Middleware
  header_manipulation:
    enabled: true
    add_headers:
      "X-Proxy-Version": "2.0.0"
      "X-Frame-Options": "DENY"
    remove_headers:
      - "Server"
      - "X-Powered-By"
    modify_headers:
      "X-Content-Type-Options": "nosniff"

  # IP Filter Middleware
  ip_filter:
    enabled: true
    whitelist: []
    blacklist:
      - "192.168.1.100"
    block_private_ips: true
    block_loopback: true

  # Authentication Middleware
  authentication:
    enabled: false
    basic_auth:
      "admin": "password123"
      "user": "userpass"
    jwt_secret: null
    jwt_algorithm: "HS256"
    required_scopes: []
```

## Performance Tuning

### Connection Pool Optimization

```yaml
performance:
  max_connections: 200  # Increase for high traffic
  connection_timeout: 10.0  # Reduce for faster timeouts
  read_timeout: 30.0  # Adjust based on backend response times
  write_timeout: 30.0
```

### Streaming Configuration

```yaml
proxy:
  stream_threshold: 2097152  # 2MB threshold
  enable_compression: true
  enable_http2: true
```

### Load Balancer Tuning

```yaml
load_balancer:
  algorithm: "least_response_time"
  health_check:
    interval: 10.0  # More frequent checks
    timeout: 3.0    # Faster timeouts
    healthy_threshold: 1
    unhealthy_threshold: 2
```

### Rate Limiting Optimization

```yaml
rate_limiting:
  rate_limit_per_minute: 200  # Adjust based on needs
  rate_limit_per_hour: 2000
  rate_limit_burst: 20
```

## Monitoring & Logging

### Logging Configuration

```yaml
logging:
  log_level: "INFO"
  log_format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  log_file: "proxy.log"
  structured_logging: true
```

**Environment Variables:**

- `LOG_LEVEL` - Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `LOG_FILE` - Log file path
- `STRUCTURED_LOGGING` - Enable JSON logging

### Metrics Configuration

```yaml
metrics:
  enabled: true
  prometheus_enabled: false  # Enable for Prometheus integration
  haproxy_style_enabled: true
```

## Environment-Specific Configs

### Development Configuration

```yaml
# config.development.yaml
server:
  debug: true
  host: "127.0.0.1"
  port: 6969

security:
  allowed_hosts: ["localhost", "127.0.0.1"]
  max_content_length: 104857600  # 100MB for development

rate_limiting:
  enabled: false  # Disable for development

logging:
  log_level: "DEBUG"
  structured_logging: false
```

### Staging Configuration

```yaml
# config.staging.yaml
server:
  debug: false
  host: "0.0.0.0"
  port: 6969

security:
  allowed_hosts: ["staging.example.com"]
  max_content_length: 52428800  # 50MB

rate_limiting:
  enabled: true
  rate_limit_per_minute: 100

load_balancer:
  enabled: true
  algorithm: "round_robin"
  backend_servers:
    - host: "staging-backend1.example.com"
      port: 8080
      weight: 1
    - host: "staging-backend2.example.com"
      port: 8080
      weight: 1

logging:
  log_level: "INFO"
  structured_logging: true
```

### Production Configuration

```yaml
# config.production.yaml
server:
  debug: false
  host: "0.0.0.0"
  port: 6969

security:
  allowed_hosts: ["api.example.com", "app.example.com"]
  max_content_length: 26214400  # 25MB for production
  enable_https_only: true

rate_limiting:
  enabled: true
  rate_limit_per_minute: 60
  rate_limit_per_hour: 1000
  redis_url: "redis://redis:6379"

load_balancer:
  enabled: true
  algorithm: "least_response_time"
  session_stickiness: true
  session_timeout: 1800  # 30 minutes
  backend_servers:
    - host: "backend1.prod.example.com"
      port: 443
      protocol: "https"
      weight: 2
      max_connections: 200
    - host: "backend2.prod.example.com"
      port: 443
      protocol: "https"
      weight: 2
      max_connections: 200
    - host: "backend3.prod.example.com"
      port: 443
      protocol: "https"
      weight: 1
      max_connections: 100

performance:
  max_connections: 500
  max_workers: 8
  connection_timeout: 5.0
  read_timeout: 30.0

logging:
  log_level: "WARNING"
  log_file: "/var/log/proxipy/proxy.log"
  structured_logging: true

metrics:
  enabled: true
  prometheus_enabled: true
```

## Advanced Configuration

### Multi-Environment Setup

Use environment variables to switch configurations:

```bash
# Development
export CONFIG_FILE=config.development.yaml
export DEBUG=true

# Staging
export CONFIG_FILE=config.staging.yaml
export REDIS_URL=redis://staging-redis:6379

# Production
export CONFIG_FILE=config.production.yaml
export REDIS_URL=redis://prod-redis:6379
export SECRET_KEY=your-production-secret-key
```

### Docker Configuration

```yaml
# docker-compose.override.yml for development
version: '3.8'
services:
  proxipy:
    environment:
      - DEBUG=true
      - LOG_LEVEL=DEBUG
      - REDIS_URL=redis://redis:6379
    volumes:
      - ./config.development.yaml:/app/config.yaml
      - ./proxy.log:/app/proxy.log

  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
```

### Kubernetes Configuration

```yaml
# k8s-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: proxipy-config
data:
  config.yaml: |
    server:
      debug: false
      host: "0.0.0.0"
      port: 6969
    security:
      allowed_hosts: ["*.example.com"]
    rate_limiting:
      enabled: true
      redis_url: "redis://redis-service:6379"
---
apiVersion: v1
kind: Secret
metadata:
  name: proxipy-secrets
type: Opaque
data:
  secret_key: <base64-encoded-secret-key>
```

### Environment Variable Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `DEBUG` | Enable debug mode | `false` |
| `HOST` | Server host | `"0.0.0.0"` |
| `PORT` | Server port | `6969` |
| `SECRET_KEY` | Secret key for security | Random |
| `REDIS_URL` | Redis connection URL | None |
| `LOG_LEVEL` | Logging level | `"INFO"` |
| `MAX_CONNECTIONS` | Max concurrent connections | `100` |
| `MAX_WORKERS` | Number of worker processes | `4` |
| `CONNECTION_TIMEOUT` | Connection timeout (seconds) | `30.0` |
| `READ_TIMEOUT` | Read timeout (seconds) | `60.0` |
| `WRITE_TIMEOUT` | Write timeout (seconds) | `30.0` |
| `RATE_LIMIT_PER_MINUTE` | Rate limit per minute | `60` |
| `RATE_LIMIT_PER_HOUR` | Rate limit per hour | `1000` |
| `MAX_CONTENT_LENGTH` | Max content length (bytes) | `52428800` |

## Configuration Validation

### YAML Validation

Use a YAML validator to check your configuration:

```bash
# Install yamllint
pip install yamllint

# Validate configuration
yamllint config.yaml
```

### Configuration Testing

Test your configuration with the server:

```python
from app.config import settings

# Print current configuration
print(settings.dict())

# Validate specific settings
assert settings.server.port > 0
assert settings.rate_limiting.rate_limit_per_minute > 0
```

### Environment Variable Testing

Test environment variable overrides:

```bash
# Set environment variable
export DEBUG=true

# Start server and check if debug is enabled
python -m app.main
```

## Troubleshooting

### Common Configuration Issues

#### 1. Port Already in Use

```yaml
server:
  port: 6970  # Change to different port
```

#### 2. Redis Connection Issues

```yaml
rate_limiting:
  redis_url: "redis://localhost:6379/1"  # Specify database
```

#### 3. CORS Issues

```yaml
security:
  allowed_hosts: ["*"]  # Allow all hosts for testing
```

#### 4. Performance Issues

```yaml
performance:
  max_connections: 200  # Increase connections
  max_workers: 8        # Increase workers
```

### Debug Configuration

Enable debug mode to see configuration loading:

```yaml
server:
  debug: true
logging:
  log_level: "DEBUG"
```

### Configuration Hot Reload

For development, enable configuration hot reload:

```yaml
server:
  debug: true
```

The server will automatically reload when `config.yaml` changes.

## Best Practices

### 1. Security

- Never commit secrets to version control
- Use environment variables for sensitive data
- Restrict allowed hosts in production
- Enable HTTPS in production

### 2. Performance

- Tune connection pool size based on traffic
- Use appropriate timeouts
- Enable compression for text content
- Configure health checks for load balancer

### 3. Monitoring

- Enable structured logging
- Set up metrics collection
- Monitor error rates and response times
- Use health checks for uptime monitoring

### 4. Configuration Management

- Use different configs for different environments
- Validate configuration before deployment
- Document configuration changes
- Use version control for configuration files

## Migration Guide

### From v1.x to v2.x

1. **Update Configuration Structure:**

   ```yaml
   # v1.x
   rate_limit_per_minute: 60
   
   # v2.x
   rate_limiting:
     rate_limit_per_minute: 60
   ```

2. **Add Load Balancer Configuration:**

   ```yaml
   load_balancer:
     enabled: false  # Disable if not needed
   ```

3. **Update Middleware Settings:**

   ```yaml
   middleware:
     enabled: true
   ```

### Configuration Backup

Always backup your configuration before making changes:

```bash
# Backup current configuration
cp config.yaml config.yaml.backup

# Test new configuration
cp config.new.yaml config.yaml

# If issues occur, restore backup
cp config.yaml.backup config.yaml
```

This comprehensive configuration guide should help you set up Proxipy for any environment or use case. Always test your configuration thoroughly before deploying to production.

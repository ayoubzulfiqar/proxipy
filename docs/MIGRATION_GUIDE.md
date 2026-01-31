# Proxipy Migration Guide

This guide helps you migrate from Proxipy v1.x to v2.x, which includes significant enhancements and architectural changes.

## Table of Contents

- [Overview of Changes](#overview-of-changes)
- [Breaking Changes](#breaking-changes)
- [Configuration Migration](#configuration-migration)
- [API Changes](#api-changes)
- [New Features](#new-features)
- [Performance Improvements](#performance-improvements)
- [Security Enhancements](#security-enhancements)
- [Migration Steps](#migration-steps)
- [Testing Migration](#testing-migration)
- [Rollback Plan](#rollback-plan)

## Overview of Changes

### Major Version Changes

**Proxipy v2.x** introduces:

- **Load Balancing**: Multiple backend server support with health checks
- **Advanced Middleware**: Modular middleware system with authentication, compression, buffering
- **Multi-Protocol Support**: HTTP, HTTPS, WebSocket, TCP, UDP proxying
- **Enhanced Configuration**: YAML-based configuration with environment variable support
- **Improved Security**: Enhanced security headers, IP filtering, content validation
- **Better Monitoring**: HAProxy-style statistics, enhanced metrics
- **Performance Optimizations**: Connection pooling, intelligent streaming

### Backward Compatibility

- **API Compatibility**: v2.x maintains backward compatibility with v1.x API
- **Configuration**: v2.x configuration is different but migration tools are provided
- **Dependencies**: Some dependencies have been updated for security and performance

## Breaking Changes

### Configuration Structure

#### v1.x Configuration

```yaml
# v1.x config.yaml
rate_limit_per_minute: 60
rate_limit_per_hour: 1000
redis_url: "redis://localhost:6379"
debug: false
port: 6969
```

#### v2.x Configuration

```yaml
# v2.x config.yaml
rate_limiting:
  enabled: true
  rate_limit_per_minute: 60
  rate_limit_per_hour: 1000
  redis_url: "redis://localhost:6379"

server:
  debug: false
  port: 6969
```

### Environment Variables

#### v1.x Environment Variables

```bash
export RATE_LIMIT_PER_MINUTE=60
export REDIS_URL=redis://localhost:6379
```

#### v2.x Environment Variables

```bash
export RATE_LIMITING_RATE_LIMIT_PER_MINUTE=60
export RATE_LIMITING_REDIS_URL=redis://localhost:6379
```

### Middleware System

#### v1.x Middleware

```python
# v1.x - Built-in middleware only
from app.main import app
```

#### v2.x Middleware

```python
# v2.x - Configurable middleware pipeline
from app.middleware import get_middleware_pipeline
from app.config import settings

pipeline = get_middleware_pipeline()
# Configure middleware based on settings
```

## Configuration Migration

### Automated Migration Script

Use the provided migration script to automatically convert v1.x configuration to v2.x:

```bash
# Run migration script
python migrate_config.py config_v1.yaml config_v2.yaml

# Or migrate environment variables
python migrate_env.py .env_v1 .env_v2
```

### Manual Configuration Migration

#### Step 1: Server Configuration

```yaml
# v1.x
debug: false
port: 6969

# v2.x
server:
  debug: false
  port: 6969
  host: "0.0.0.0"
```

#### Step 2: Rate Limiting

```yaml
# v1.x
rate_limit_per_minute: 60
rate_limit_per_hour: 1000
redis_url: "redis://localhost:6379"

# v2.x
rate_limiting:
  enabled: true
  rate_limit_per_minute: 60
  rate_limit_per_hour: 1000
  redis_url: "redis://localhost:6379"
```

#### Step 3: Security Configuration

```yaml
# v1.x
allowed_hosts: ["*"]
max_content_length: 52428800

# v2.x
security:
  allowed_hosts: ["*"]
  max_content_length: 52428800
  enable_csp: true
  enable_hsts: true
  enable_cors: true
```

#### Step 4: Load Balancer (New in v2.x)

```yaml
# v2.x - New load balancer configuration
load_balancer:
  enabled: false  # Disable if not needed
  algorithm: "round_robin"
  backend_servers:
    - host: "backend1.example.com"
      port: 8080
      weight: 1
```

#### Step 5: Middleware (New in v2.x)

```yaml
# v2.x - New middleware configuration
middleware:
  enabled: true
  
  rate_limit:
    enabled: true
    requests_per_minute: 60
  
  compression:
    enabled: true
    min_size: 1024
```

### Environment Variable Migration

#### Create Migration Script

```python
# migrate_env.py
import os

def migrate_environment_variables():
    """Migrate environment variables from v1.x to v2.x"""
    
    # Mapping of v1.x to v2.x environment variables
    env_mapping = {
        'RATE_LIMIT_PER_MINUTE': 'RATE_LIMITING_RATE_LIMIT_PER_MINUTE',
        'RATE_LIMIT_PER_HOUR': 'RATE_LIMITING_RATE_LIMIT_PER_HOUR',
        'REDIS_URL': 'RATE_LIMITING_REDIS_URL',
        'DEBUG': 'SERVER_DEBUG',
        'PORT': 'SERVER_PORT',
        'HOST': 'SERVER_HOST'
    }
    
    # Read current environment
    current_env = {}
    for old_var, new_var in env_mapping.items():
        if old_var in os.environ:
            current_env[new_var] = os.environ[old_var]
    
    # Write new environment file
    with open('.env', 'w') as f:
        for var, value in current_env.items():
            f.write(f"{var}={value}\n")
    
    print("Environment variables migrated successfully!")

if __name__ == "__main__":
    migrate_environment_variables()
```

## API Changes

### Endpoint Changes

#### v1.x Endpoints

- `GET /proxy?url=<url>`
- `POST /proxy` (with body)
- `GET /health`
- `GET /metrics`

#### v2.x Endpoints (Enhanced)

- `GET /proxy?url=<url>` (enhanced with load balancing)
- `POST /proxy` (enhanced with middleware)
- `GET /health` (enhanced with load balancer status)
- `GET /metrics` (enhanced metrics)
- `GET /stats` (new HAProxy-style statistics)

### Request/Response Changes

#### v1.x Request Format

```json
{
  "url": "https://api.example.com/data",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": "{\"key\": \"value\"}"
}
```

#### v2.x Request Format (Same, Enhanced Processing)

```json
{
  "url": "https://api.example.com/data",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": "{\"key\": \"value\"}"
}
```

### Response Changes

#### v1.x Health Response

```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

#### v2.x Health Response (Enhanced)

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

## New Features

### Load Balancer

#### Configuration

```yaml
load_balancer:
  enabled: true
  algorithm: "least_response_time"
  session_stickiness: true
  session_timeout: 1800
  backend_servers:
    - host: "backend1.example.com"
      port: 8080
      weight: 2
    - host: "backend2.example.com"
      port: 8080
      weight: 1
```

#### Usage

```bash
# Load balancer automatically distributes requests
curl "http://localhost:6969/proxy?url=https://api.example.com/data"
```

### Advanced Middleware

#### Authentication Middleware

```yaml
middleware:
  authentication:
    enabled: true
    basic_auth:
      "admin": "password123"
      "user": "userpass"
```

#### Compression Middleware

```yaml
middleware:
  compression:
    enabled: true
    min_size: 1024
    compression_level: 6
```

#### Circuit Breaker Middleware

```yaml
middleware:
  circuit_breaker:
    enabled: true
    failure_threshold: 5
    recovery_timeout: 60.0
```

### Enhanced Monitoring

#### HAProxy-style Statistics

```bash
# New endpoint for load balancer statistics
curl http://localhost:6969/stats
```

#### Enhanced Metrics

```bash
# More detailed metrics
curl http://localhost:6969/metrics
```

## Performance Improvements

### Connection Pooling

- **v1.x**: New connection for each request
- **v2.x**: Reusable connection pools with configurable limits

### Intelligent Streaming

- **v1.x**: Buffer all responses
- **v2.x**: Stream large files, buffer small responses

### Middleware Optimization

- **v1.x**: Fixed middleware pipeline
- **v2.x**: Configurable middleware with priority ordering

### Load Balancer Optimization

- **v1.x**: Single backend only
- **v2.x**: Multiple backends with intelligent routing

## Security Enhancements

### Enhanced Security Headers

```yaml
security:
  enable_csp: true
  enable_hsts: true
  enable_cors: true
  enable_corp: true
  enable_coep: true
  enable_coop: true
```

### IP Filtering

```yaml
middleware:
  ip_filter:
    enabled: true
    whitelist: []
    blacklist: ["192.168.1.100"]
    block_private_ips: true
    block_loopback: true
```

### Content Validation

```yaml
security:
  validate_content_types: true
  allowed_content_types: ["application/json", "text/html"]
  max_content_length: 52428800
```

## Migration Steps

### Step 1: Backup Current Configuration

```bash
# Backup current configuration
cp config.yaml config.yaml.backup
cp .env .env.backup
```

### Step 2: Update Dependencies

```bash
# Update requirements
pip install --upgrade -r requirements.txt
```

### Step 3: Migrate Configuration

```bash
# Use automated migration script
python migrate_config.py config.yaml config_v2.yaml

# Or manually update configuration
# See configuration migration section above
```

### Step 4: Update Environment Variables

```bash
# Use automated migration script
python migrate_env.py .env .env_v2

# Or manually update environment variables
# See environment variable migration section above
```

### Step 5: Test Migration

```bash
# Start with v2.x configuration
python -m app.main

# Test basic functionality
curl http://localhost:6969/health
curl "http://localhost:6969/proxy?url=https://httpbin.org/get"

# Test new features
curl http://localhost:6969/stats
```

### Step 6: Update Deployment Scripts

```bash
# Update Docker Compose
# Update Kubernetes manifests
# Update systemd service files
```

### Step 7: Deploy to Staging

```bash
# Deploy to staging environment
# Run comprehensive tests
# Validate performance
```

### Step 8: Deploy to Production

```bash
# Deploy to production with monitoring
# Monitor for issues
# Be ready to rollback if needed
```

## Testing Migration

### Automated Tests

```bash
# Run existing tests
pytest tests/

# Run migration-specific tests
pytest tests/test_migration.py

# Run integration tests
pytest tests/test_integration.py
```

### Manual Testing Checklist

#### Basic Functionality

- [ ] Proxy requests work correctly
- [ ] Health check endpoint responds
- [ ] Metrics endpoint provides data
- [ ] Rate limiting functions properly

#### New Features

- [ ] Load balancer distributes traffic
- [ ] Middleware processes requests
- [ ] Security headers are present
- [ ] Enhanced monitoring works

#### Performance

- [ ] Response times are acceptable
- [ ] Memory usage is reasonable
- [ ] CPU usage is within limits
- [ ] Connection pooling works

#### Security

- [ ] Rate limiting blocks excess requests
- [ ] IP filtering blocks malicious IPs
- [ ] Content validation works
- [ ] Security headers are set

### Load Testing

```bash
# Test with load
ab -n 1000 -c 100 http://localhost:6969/proxy?url=https://httpbin.org/get

# Monitor performance
curl http://localhost:6969/metrics
```

## Rollback Plan

### Rollback Triggers

- Performance degradation
- Security issues
- Critical functionality broken
- High error rates

### Rollback Steps

#### Step 1: Stop v2.x

```bash
# Stop current instance
pkill -f "python.*app.main"
```

#### Step 2: Restore v1.x Configuration

```bash
# Restore backup configuration
cp config.yaml.backup config.yaml
cp .env.backup .env
```

#### Step 3: Downgrade Dependencies

```bash
# Downgrade to v1.x dependencies
pip install -r requirements_v1.txt
```

#### Step 4: Restart v1.x

```bash
# Start v1.x
python -m app.main
```

#### Step 5: Verify Rollback

```bash
# Test basic functionality
curl http://localhost:6969/health
curl "http://localhost:6969/proxy?url=https://httpbin.org/get"
```

### Rollback Validation

#### Functional Tests

- [ ] All endpoints respond correctly
- [ ] Proxy functionality works
- [ ] Rate limiting functions
- [ ] No security issues

#### Performance Tests

- [ ] Response times acceptable
- [ ] Memory usage normal
- [ ] CPU usage normal
- [ ] No connection issues

## Post-Migration Tasks

### Configuration Optimization

```yaml
# Optimize configuration for your use case
performance:
  max_connections: 200
  max_workers: 4

load_balancer:
  algorithm: "least_response_time"
  health_check:
    interval: 10.0
    timeout: 3.0
```

### Monitoring Setup

```yaml
# Set up monitoring for new features
metrics:
  enabled: true
  prometheus_enabled: true

logging:
  log_level: "INFO"
  structured_logging: true
```

### Security Review

```yaml
# Review and harden security configuration
security:
  allowed_hosts: ["yourdomain.com"]
  enable_https_only: true
  max_content_length: 26214400  # 25MB
```

### Performance Tuning

```yaml
# Tune performance based on monitoring
performance:
  max_connections: 500
  connection_timeout: 10.0
  read_timeout: 30.0
```

## Support and Resources

### Documentation

- [API Reference](API_REFERENCE.md)
- [Configuration Guide](CONFIGURATION_GUIDE.md)
- [Deployment Guide](DEPLOYMENT_GUIDE.md)
- [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md)

### Community Support

- GitHub Issues
- Documentation
- Examples and tutorials

### Professional Support

- Enterprise support available
- Consulting services
- Custom development

## Migration Timeline

### Recommended Timeline

- **Week 1**: Preparation and testing
- **Week 2**: Staging deployment and validation
- **Week 3**: Production deployment
- **Week 4**: Post-migration optimization

### Risk Mitigation

- Thorough testing in staging
- Rollback plan ready
- Monitoring in place
- Support team available

This migration guide provides comprehensive steps to upgrade from Proxipy v1.x to v2.x safely and successfully. Always test thoroughly before deploying to production.

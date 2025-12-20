# Proxipy Troubleshooting Guide

This guide provides comprehensive troubleshooting information for common issues with Proxipy CORS proxy server.

## Table of Contents

- [Common Issues](#common-issues)
- [Error Codes & Messages](#error-codes--messages)
- [Performance Issues](#performance-issues)
- [Configuration Problems](#configuration-problems)
- [Load Balancer Issues](#load-balancer-issues)
- [Security Issues](#security-issues)
- [Network & Connectivity](#network--connectivity)
- [Debugging Tools](#debugging-tools)
- [Log Analysis](#log-analysis)
- [FAQ](#faq)

## Common Issues

### 1. Server Won't Start

**Symptoms:**

- Application fails to start
- Port binding errors
- Import errors

**Solutions:**

#### Port Already in Use

```bash
# Check if port is in use
sudo netstat -tlnp | grep :6969

# Kill process using port
sudo fuser -k 6969/tcp

# Or change port in config
server:
  port: 6970
```

#### Missing Dependencies

```bash
# Reinstall dependencies
pip uninstall -r requirements.txt -y
pip install -r requirements.txt

# Check Python version
python --version  # Should be 3.8+
```

#### Import Errors

```bash
# Check if all modules are installed
python -c "import fastapi; import uvicorn; import httpx"

# Reinstall specific module
pip install --force-reinstall fastapi
```

### 2. 502 Bad Gateway

**Symptoms:**

- Target server returns 502
- Connection timeouts
- Backend server unreachable

**Solutions:**

#### Check Target Server

```bash
# Test target server directly
curl -I https://api.example.com

# Check if server is running
telnet api.example.com 443
```

#### Increase Timeouts

```yaml
performance:
  connection_timeout: 60.0
  read_timeout: 120.0
  write_timeout: 60.0
```

#### Check Load Balancer

```bash
# Check health status
curl http://localhost:6969/health

# Check backend servers
curl http://localhost:6969/stats
```

### 3. 403 Forbidden

**Symptoms:**

- Requests blocked by security
- Domain/IP filtering
- Suspicious content detection

**Solutions:**

#### Check Blocked Domains

```yaml
# Review blocked domains list
blocked_domains:
  - "localhost"
  - "127.0.0.1"
  - "192.168.0.0/16"
```

#### Check Allowed Hosts

```yaml
security:
  allowed_hosts: ["*"]  # Allow all for testing
```

#### Disable Security Temporarily

```yaml
security:
  enable_cors: false
  enable_csp: false
```

### 4. 429 Too Many Requests

**Symptoms:**

- Rate limiting blocking requests
- High traffic scenarios
- Burst traffic issues

**Solutions:**

#### Increase Rate Limits

```yaml
rate_limiting:
  rate_limit_per_minute: 200
  rate_limit_per_hour: 2000
  burst_size: 50
```

#### Check Redis Connection

```bash
# Test Redis connection
redis-cli ping

# Check Redis memory usage
redis-cli info memory
```

#### Monitor Rate Limit Headers

```bash
curl -I http://localhost:6969/proxy?url=https://api.example.com
# Check headers:
# X-RateLimit-Remaining
# X-RateLimit-Reset
```

## Error Codes & Messages

### HTTP Status Codes

| Status | Error | Common Causes | Solutions |
|--------|-------|---------------|-----------|
| 400 | Bad Request | Invalid URL, malformed request | Validate input, check URL format |
| 403 | Forbidden | Blocked domain, security violation | Check security config, whitelist domains |
| 413 | Payload Too Large | Request body too big | Increase `max_content_length` |
| 415 | Unsupported Media Type | Invalid content type | Check content type validation |
| 429 | Too Many Requests | Rate limit exceeded | Increase limits, check Redis |
| 502 | Bad Gateway | Backend server error | Check backend health, timeouts |
| 503 | Service Unavailable | No healthy servers | Check load balancer, circuit breaker |

### Common Error Messages

#### "Connection refused"

```bash
# Check if target server is running
telnet target-server.com 80

# Check firewall rules
sudo ufw status
```

#### "Timeout"

```yaml
# Increase timeout values
performance:
  connection_timeout: 60.0
  read_timeout: 120.0
```

#### "Redis connection failed"

```bash
# Check Redis service
sudo systemctl status redis

# Test connection
redis-cli -h localhost -p 6379 ping
```

#### "SSL certificate verify failed"

```yaml
# Disable SSL verification (development only)
security:
  enable_https_only: false
```

## Performance Issues

### High Response Times

**Symptoms:**

- Slow proxy responses
- High latency
- Timeout errors

**Solutions:**

#### Connection Pool Tuning

```yaml
performance:
  max_connections: 200
  connection_timeout: 10.0
  read_timeout: 30.0
```

#### Enable Compression

```yaml
middleware:
  compression:
    enabled: true
    min_size: 1024
```

#### Streaming Configuration

```yaml
proxy:
  stream_threshold: 2097152  # 2MB
  enable_streaming: true
```

### High Memory Usage

**Symptoms:**

- Memory consumption growing
- Out of memory errors
- Slow garbage collection

**Solutions:**

#### Buffer Size Optimization

```yaml
middleware:
  buffering:
    max_buffer_size: 524288  # 512KB
    buffer_timeout: 3.0
```

#### Connection Limits

```yaml
performance:
  max_connections: 100
  max_workers: 4
```

#### Monitor Memory Usage

```bash
# Check memory usage
top -p $(pgrep -f proxipy)

# Monitor with htop
htop
```

### High CPU Usage

**Symptoms:**

- High CPU utilization
- Slow response times
- System overload

**Solutions:**

#### Worker Configuration

```yaml
performance:
  max_workers: 2  # Reduce workers
```

#### Disable Heavy Middleware

```yaml
middleware:
  compression:
    enabled: false  # Disable if CPU intensive
  buffering:
    enabled: false  # Disable if memory intensive
```

#### Load Testing

```bash
# Test with ab (Apache Bench)
ab -n 1000 -c 10 http://localhost:6969/proxy?url=https://api.example.com

# Test with wrk
wrk -t12 -c400 -d30s http://localhost:6969/proxy?url=https://api.example.com
```

## Configuration Problems

### YAML Configuration Issues

**Symptoms:**

- Configuration not loading
- Invalid YAML syntax
- Environment variables not working

**Solutions:**

#### Validate YAML

```bash
# Install yamllint
pip install yamllint

# Validate configuration
yamllint config.yaml
```

#### Check Environment Variables

```bash
# Set environment variable
export DEBUG=true

# Verify it's set
echo $DEBUG

# Check if Proxipy sees it
python -c "from app.config import settings; print(settings.server.debug)"
```

#### Configuration Precedence

```yaml
# Environment variables override YAML
# Example: DEBUG=true overrides debug: false in YAML
```

### Middleware Configuration Issues

**Symptoms:**

- Middleware not working
- Wrong execution order
- Configuration conflicts

**Solutions:**

#### Check Middleware Order

```yaml
middleware:
  # Order matters - first to last execution
  rate_limit:
    priority: 10
  authentication:
    priority: 20
  compression:
    priority: 30
```

#### Debug Middleware

```yaml
server:
  debug: true
logging:
  log_level: "DEBUG"
```

#### Test Individual Middleware

```yaml
# Disable all except one
middleware:
  enabled: true
  rate_limit:
    enabled: true
  authentication:
    enabled: false
  compression:
    enabled: false
```

## Load Balancer Issues

### Backend Server Health

**Symptoms:**

- Servers marked as unhealthy
- Health checks failing
- Uneven traffic distribution

**Solutions:**

#### Check Health Check Configuration

```yaml
load_balancer:
  health_check:
    protocol: "http"
    path: "/health"
    interval: 30.0
    timeout: 5.0
    healthy_threshold: 2
    unhealthy_threshold: 3
```

#### Manual Health Check

```bash
# Test health endpoint manually
curl http://backend-server:8080/health

# Check response time
time curl -o /dev/null -s -w '%{time_total}\n' http://backend-server:8080/health
```

#### Adjust Health Check Thresholds

```yaml
load_balancer:
  health_check:
    healthy_threshold: 1
    unhealthy_threshold: 2
```

### Load Balancer Algorithm Issues

**Symptoms:**

- Uneven traffic distribution
- Wrong server selection
- Session stickiness not working

**Solutions:**

#### Test Different Algorithms

```yaml
load_balancer:
  algorithm: "round_robin"  # Try different algorithms
  # algorithm: "least_connections"
  # algorithm: "least_response_time"
```

#### Check Session Stickiness

```yaml
load_balancer:
  session_stickiness: true
  session_timeout: 3600
```

#### Monitor Distribution

```bash
# Check stats endpoint
curl http://localhost:6969/stats | jq '.backend[] | {name, current_connections}'
```

### Circuit Breaker Issues

**Symptoms:**

- Circuit breaker opening too quickly
- Not recovering from failures
- False positives

**Solutions:**

#### Adjust Circuit Breaker Settings

```yaml
load_balancer:
  circuit_breaker_failure_threshold: 10  # Increase threshold
  circuit_breaker_recovery_timeout: 120.0  # Increase recovery time
```

#### Monitor Circuit Breaker State

```bash
# Check circuit breaker status
curl http://localhost:6969/health | jq '.load_balancer'
```

## Security Issues

### CORS Issues

**Symptoms:**

- CORS errors in browser
- Cross-origin requests blocked
- Preflight requests failing

**Solutions:**

#### Configure CORS Headers

```yaml
security:
  enable_cors: true
  allowed_hosts: ["*"]
  allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  allowed_headers: ["*"]
```

#### Debug CORS

```bash
# Check CORS headers
curl -I -X OPTIONS http://localhost:6969/proxy

# Test with specific origin
curl -H "Origin: https://example.com" http://localhost:6969/proxy
```

### Rate Limiting Issues

**Symptoms:**

- Legitimate requests blocked
- Rate limits too aggressive
- Redis connection issues

**Solutions:**

#### Check Rate Limit Configuration

```yaml
rate_limiting:
  rate_limit_per_minute: 100
  rate_limit_per_hour: 1000
  burst_size: 10
```

#### Monitor Rate Limit Headers

```bash
curl -I http://localhost:6969/proxy?url=https://api.example.com
# Look for:
# X-RateLimit-Limit
# X-RateLimit-Remaining
# X-RateLimit-Reset
```

#### Debug Redis Rate Limiting

```bash
# Check Redis keys
redis-cli KEYS "*rate_limit*"

# Check rate limit values
redis-cli GET "rate_limit:client_ip:minute"
```

## Network & Connectivity

### DNS Resolution Issues

**Symptoms:**

- DNS lookup failures
- Slow DNS resolution
- Connection timeouts

**Solutions:**

#### Check DNS Configuration

```bash
# Test DNS resolution
nslookup api.example.com

# Check DNS servers
cat /etc/resolv.conf
```

#### Use IP Addresses

```yaml
load_balancer:
  backend_servers:
    - host: "192.168.1.100"  # Use IP instead of hostname
      port: 8080
```

#### DNS Caching

```yaml
performance:
  # Enable DNS caching in HTTP client
  dns_cache: true
```

### Firewall Issues

**Symptoms:**

- Connection blocked
- Port access denied
- Network timeouts

**Solutions:**

#### Check Firewall Rules

```bash
# UFW status
sudo ufw status

# iptables rules
sudo iptables -L

# Check specific port
sudo netstat -tlnp | grep :6969
```

#### Open Required Ports

```bash
# UFW
sudo ufw allow 6969
sudo ufw allow 6379  # Redis

# iptables
sudo iptables -A INPUT -p tcp --dport 6969 -j ACCEPT
```

### Proxy Chain Issues

**Symptoms:**

- Multiple proxy layers
- Request forwarding loops
- Header corruption

**Solutions:**

#### Check Proxy Headers

```bash
# Check forwarded headers
curl -I http://localhost:6969/proxy?url=https://api.example.com
# Look for:
# X-Forwarded-For
# X-Real-IP
# X-Forwarded-Proto
```

#### Configure Proxy Chain

```yaml
security:
  # Handle proxy headers correctly
  trusted_proxies: ["127.0.0.1", "10.0.0.0/8"]
```

## Debugging Tools

### Built-in Debug Features

#### Enable Debug Mode

```yaml
server:
  debug: true
logging:
  log_level: "DEBUG"
```

#### Health Check Endpoints

```bash
# Basic health
curl http://localhost:6969/health

# Detailed metrics
curl http://localhost:6969/metrics

# Load balancer stats
curl http://localhost:6969/stats
```

### External Debugging Tools

#### Network Analysis

```bash
# Monitor network traffic
sudo tcpdump -i any -n port 6969

# HTTP traffic analysis
sudo ngrep -d any -t 'GET|POST' port 6969
```

#### Performance Profiling

```bash
# Python profiling
python -m cProfile -o profile.stats app/main.py

# Memory profiling
pip install memory-profiler
python -m memory_profiler app/main.py
```

#### Request/Response Analysis

```bash
# Detailed curl output
curl -v -I http://localhost:6969/proxy?url=https://api.example.com

# HTTPie for better formatting
pip install httpie
http GET http://localhost:6969/proxy url=https://api.example.com
```

## Log Analysis

### Log Levels and Formats

#### Configure Logging

```yaml
logging:
  log_level: "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  log_format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  log_file: "proxy.log"
  structured_logging: true
```

#### Common Log Patterns

**Request Logs:**

```
2024-10-20 15:30:45,123 - app.main - INFO - Request: GET /proxy?url=https://api.example.com
```

**Error Logs:**

```
2024-10-20 15:30:45,123 - app.main - ERROR - Request failed: Connection timeout
```

**Security Logs:**

```
2024-10-20 15:30:45,123 - app.security - WARNING - Blocked request from 192.168.1.100
```

### Log Analysis Commands

#### Filter by Level

```bash
# Show only errors
grep "ERROR" proxy.log

# Show warnings and errors
grep -E "(WARNING|ERROR)" proxy.log
```

#### Filter by Time

```bash
# Show last hour
grep "$(date '+%Y-%m-%d %H')" proxy.log

# Show specific time range
sed -n '/2024-10-20 15:00/,/2024-10-20 16:00/p' proxy.log
```

#### Analyze Request Patterns

```bash
# Top requested URLs
grep "Request:" proxy.log | awk '{print $8}' | sort | uniq -c | sort -nr

# Response time analysis
grep "X-Process-Time" proxy.log | awk -F': ' '{print $2}' | sort -n

# Error rate by hour
grep "ERROR" proxy.log | awk '{print $1 " " $2}' | cut -d: -f1 | sort | uniq -c
```

### Structured Logging Analysis

#### JSON Log Analysis

```bash
# Parse JSON logs
jq '. | select(.level == "ERROR")' proxy.log

# Extract specific fields
jq -r '.timestamp, .message' proxy.log
```

#### Log Aggregation

```bash
# Combine multiple log files
cat proxy.log.* > combined.log

# Sort by timestamp
sort -t' ' -k1,2 combined.log > sorted.log
```

## FAQ

### Q: How do I reset rate limiting?

**A:** Clear Redis keys or restart Redis:

```bash
redis-cli FLUSHDB
```

### Q: Why are my requests timing out?

**A:** Increase timeout values in configuration:

```yaml
performance:
  connection_timeout: 60.0
  read_timeout: 120.0
```

### Q: How do I enable HTTPS?

**A:** Use a reverse proxy like Nginx with SSL certificates, or configure your load balancer.

### Q: Why is load balancing not working?

**A:** Check health check configuration and ensure backend servers are responding properly.

### Q: How do I debug middleware issues?

**A:** Enable debug mode and check the order of middleware execution in configuration.

### Q: What should I monitor in production?

**A:** Monitor response times, error rates, rate limiting metrics, and backend server health.

### Q: How do I scale Proxipy horizontally?

**A:** Use a load balancer in front of multiple Proxipy instances with shared Redis for rate limiting.

### Q: Why are CORS requests failing?

**A:** Check CORS configuration and ensure proper headers are being set.

### Q: How do I handle large file uploads?

**A:** Increase `max_content_length` and enable streaming for large files.

### Q: What are the minimum system requirements?

**A:** 512MB RAM, 1 CPU core, 100MB disk space for basic usage.

This troubleshooting guide covers the most common issues with Proxipy. If you encounter problems not covered here, check the logs and consider creating an issue on the GitHub repository with detailed information about your setup and the problem.

# Proxipy Performance Optimization Guide

This guide provides comprehensive strategies for optimizing Proxipy's performance in various deployment scenarios.

## Table of Contents

- [Performance Overview](#performance-overview)
- [Configuration Optimization](#configuration-optimization)
- [Load Balancer Tuning](#load-balancer-tuning)
- [Middleware Optimization](#middleware-optimization)
- [Network Optimization](#network-optimization)
- [Memory Management](#memory-management)
- [CPU Optimization](#cpu-optimization)
- [Monitoring & Benchmarking](#monitoring--benchmarking)
- [Production Optimization](#production-optimization)
- [Scaling Strategies](#scaling-strategies)

## Performance Overview

### Key Performance Metrics

- **Request Throughput**: Requests per second (RPS)
- **Response Time**: 95th percentile response time
- **Memory Usage**: RAM consumption under load
- **CPU Utilization**: CPU usage percentage
- **Error Rate**: Percentage of failed requests
- **Connection Pool Efficiency**: Connection reuse rate

### Performance Targets

| Environment | Target RPS | 95th %ile RT | Memory | CPU |
|-------------|------------|--------------|---------|-----|
| Development | 100 RPS | < 100ms | < 512MB | < 50% |
| Staging | 1000 RPS | < 200ms | < 2GB | < 70% |
| Production | 5000+ RPS | < 500ms | < 4GB | < 80% |

## Configuration Optimization

### Basic Performance Settings

```yaml
# High-performance configuration
performance:
  max_connections: 1000
  max_workers: 8
  connection_timeout: 10.0
  read_timeout: 30.0
  write_timeout: 30.0
  stream_chunk_size: 16384  # 16KB chunks
  max_response_size: 209715200  # 200MB

server:
  host: "0.0.0.0"
  port: 6969
```

### Connection Pool Optimization

```yaml
# Connection pool settings for high throughput
performance:
  max_connections: 2000  # Increase for high traffic
  connection_timeout: 5.0  # Reduce for faster timeouts
  read_timeout: 15.0  # Reduce for faster responses
  write_timeout: 15.0
```

### Streaming Configuration

```yaml
# Optimize for large file streaming
proxy:
  stream_threshold: 1048576  # 1MB threshold
  enable_compression: true
  enable_http2: true
  stream_chunk_size: 32768  # 32KB chunks for better throughput
```

## Load Balancer Tuning

### Algorithm Selection

#### High Throughput Scenarios

```yaml
load_balancer:
  algorithm: "least_response_time"  # Best for performance
  health_check:
    interval: 10.0  # More frequent checks
    timeout: 3.0    # Faster timeouts
    healthy_threshold: 1
    unhealthy_threshold: 2
```

#### High Availability Scenarios

```yaml
load_balancer:
  algorithm: "weighted_least_connections"
  session_stickiness: true
  session_timeout: 1800  # 30 minutes
```

### Backend Server Optimization

```yaml
load_balancer:
  backend_servers:
    - host: "backend1.example.com"
      port: 443
      protocol: "https"
      weight: 3  # Higher weight for more powerful servers
      max_connections: 500
      response_timeout: 10.0
    - host: "backend2.example.com"
      port: 443
      protocol: "https"
      weight: 2
      max_connections: 300
      response_timeout: 10.0
```

### Circuit Breaker Tuning

```yaml
load_balancer:
  enable_circuit_breaker: true
  circuit_breaker_failure_threshold: 10  # Higher threshold
  circuit_breaker_recovery_timeout: 30.0  # Faster recovery
  circuit_breaker_half_open_max_requests: 5
```

## Middleware Optimization

### Essential Middleware Only

```yaml
# Minimal middleware for maximum performance
middleware:
  enabled: true
  
  # Keep rate limiting for protection
  rate_limit:
    enabled: true
    requests_per_minute: 1000
    requests_per_hour: 10000
    burst_size: 100
  
  # Disable heavy middleware in high-performance scenarios
  compression:
    enabled: false  # CPU intensive
  buffering:
    enabled: false  # Memory intensive
  authentication:
    enabled: false  # Only if not needed
```

### Selective Middleware

```yaml
# Enable only necessary middleware
middleware:
  rate_limit:
    enabled: true
    priority: 10
  header_manipulation:
    enabled: true
    priority: 20
    add_headers:
      "X-Proxy-Version": "2.0.0"
  compression:
    enabled: true
    min_size: 4096  # Only compress larger responses
    compression_level: 1  # Lower compression for speed
```

## Network Optimization

### TCP Optimization

```yaml
# Network-level optimizations
performance:
  # Enable TCP keepalive
  tcp_keepalive: true
  tcp_keepalive_time: 60
  tcp_keepalive_intvl: 10
  tcp_keepalive_probes: 9
  
  # Connection reuse
  connection_reuse: true
  connection_pool_size: 100
```

### DNS Optimization

```yaml
# DNS caching and optimization
performance:
  dns_cache: true
  dns_cache_ttl: 300  # 5 minutes
  dns_timeout: 5.0
```

### HTTP/2 Configuration

```yaml
# HTTP/2 optimization
proxy:
  enable_http2: true
  http2_max_concurrent_streams: 100
  http2_initial_connection_window_size: 1048576  # 1MB
  http2_initial_stream_window_size: 65536  # 64KB
```

## Memory Management

### Buffer Size Optimization

```yaml
# Memory-efficient buffering
middleware:
  buffering:
    max_buffer_size: 1048576  # 1MB
    buffer_timeout: 3.0
    enable_streaming: true
```

### Connection Limits

```yaml
# Memory-conscious connection limits
performance:
  max_connections: 500  # Balance between performance and memory
  max_workers: 4        # Reduce workers to save memory
```

### Garbage Collection

```yaml
# Python garbage collection tuning
performance:
  gc_threshold: [700, 10, 10]  # Tune garbage collection
  gc_debug: false
```

### Memory Monitoring

```python
# Add memory monitoring to your application
import psutil
import gc

def monitor_memory():
    process = psutil.Process()
    memory_info = process.memory_info()
    gc.collect()  # Force garbage collection
    return {
        'rss': memory_info.rss / 1024 / 1024,  # MB
        'vms': memory_info.vms / 1024 / 1024,  # MB
        'gc_collections': gc.get_count()
    }
```

## CPU Optimization

### Worker Configuration

```yaml
# CPU-optimized worker settings
performance:
  max_workers: $(nproc)  # Number of CPU cores
  worker_class: "uvicorn.workers.UvicornWorker"
  worker_connections: 1000
```

### Async Optimization

```python
# Optimize async operations
import asyncio
from asyncio import Semaphore

# Use semaphores for controlled concurrency
semaphore = Semaphore(100)  # Limit concurrent operations

async def optimized_request(url):
    async with semaphore:
        # Your request logic here
        pass
```

### CPU Monitoring

```python
# CPU usage monitoring
import psutil
import time

def monitor_cpu():
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count()
    load_avg = psutil.getloadavg()
    return {
        'cpu_percent': cpu_percent,
        'cpu_count': cpu_count,
        'load_1min': load_avg[0],
        'load_5min': load_avg[1],
        'load_15min': load_avg[2]
    }
```

## Monitoring & Benchmarking

### Performance Metrics Collection

```python
# Custom performance metrics
import time
from collections import deque

class PerformanceMetrics:
    def __init__(self):
        self.response_times = deque(maxlen=1000)
        self.request_count = 0
        self.error_count = 0
    
    def record_request(self, response_time, success=True):
        self.response_times.append(response_time)
        self.request_count += 1
        if not success:
            self.error_count += 1
    
    def get_stats(self):
        if not self.response_times:
            return {"avg_response_time": 0, "rps": 0, "error_rate": 0}
        
        avg_time = sum(self.response_times) / len(self.response_times)
        # Calculate 95th percentile
        sorted_times = sorted(self.response_times)
        p95_index = int(0.95 * len(sorted_times))
        p95_time = sorted_times[p95_index] if p95_index < len(sorted_times) else sorted_times[-1]
        
        return {
            "avg_response_time": avg_time,
            "p95_response_time": p95_time,
            "total_requests": self.request_count,
            "error_rate": (self.error_count / self.request_count) * 100 if self.request_count > 0 else 0
        }
```

### Benchmarking Tools

#### Apache Bench (ab)

```bash
# Basic load test
ab -n 1000 -c 100 http://localhost:6969/proxy?url=https://api.example.com

# With POST requests
ab -n 1000 -c 50 -p post_data.txt -T application/json http://localhost:6969/proxy

# Keep-alive test
ab -n 1000 -c 100 -k http://localhost:6969/proxy?url=https://api.example.com
```

#### wrk

```bash
# High-performance HTTP benchmarking
wrk -t12 -c400 -d30s http://localhost:6969/proxy?url=https://api.example.com

# With custom script
wrk -t12 -c400 -d30s -s script.lua http://localhost:6969/proxy
```

#### Custom Benchmark Script

```python
# Custom Python benchmark
import asyncio
import aiohttp
import time
from concurrent.futures import ThreadPoolExecutor

async def benchmark_request(session, url, num_requests):
    start_time = time.time()
    tasks = []
    
    for _ in range(num_requests):
        task = session.get(url)
        tasks.append(task)
    
    responses = await asyncio.gather(*tasks)
    end_time = time.time()
    
    return {
        'total_time': end_time - start_time,
        'requests': len(responses),
        'success_rate': sum(1 for r in responses if r.status == 200) / len(responses)
    }

async def run_benchmark():
    url = "http://localhost:6969/proxy?url=https://api.example.com"
    
    async with aiohttp.ClientSession() as session:
        # Test with different concurrency levels
        for concurrency in [10, 50, 100, 200]:
            result = await benchmark_request(session, url, concurrency)
            print(f"Concurrency: {concurrency}")
            print(f"  Total time: {result['total_time']:.2f}s")
            print(f"  Requests/sec: {result['requests'] / result['total_time']:.2f}")
            print(f"  Success rate: {result['success_rate']:.2%}")
            print()

if __name__ == "__main__":
    asyncio.run(run_benchmark())
```

## Production Optimization

### Production Configuration Template

```yaml
# Production-optimized configuration
server:
  debug: false
  host: "0.0.0.0"
  port: 6969

performance:
  max_connections: 2000
  max_workers: 8
  connection_timeout: 5.0
  read_timeout: 15.0
  write_timeout: 15.0
  stream_chunk_size: 32768

security:
  allowed_hosts: ["*.yourdomain.com"]
  max_content_length: 52428800  # 50MB
  enable_https_only: true

rate_limiting:
  enabled: true
  rate_limit_per_minute: 1000
  rate_limit_per_hour: 10000
  redis_url: "redis://prod-redis:6379"

load_balancer:
  enabled: true
  algorithm: "least_response_time"
  session_stickiness: true
  session_timeout: 1800
  backend_servers:
    - host: "backend1.prod.example.com"
      port: 443
      protocol: "https"
      weight: 2
      max_connections: 500
    - host: "backend2.prod.example.com"
      port: 443
      protocol: "https"
      weight: 2
      max_connections: 500

middleware:
  enabled: true
  rate_limit:
    enabled: true
    requests_per_minute: 1000
  compression:
    enabled: true
    min_size: 4096
    compression_level: 1
  header_manipulation:
    enabled: true
    add_headers:
      "X-Proxy-Version": "2.0.0"

logging:
  log_level: "WARNING"
  log_file: "/var/log/proxipy/proxy.log"
  structured_logging: true

metrics:
  enabled: true
  prometheus_enabled: true
  haproxy_style_enabled: true
```

### System-Level Optimization

#### Linux Kernel Tuning

```bash
# Network buffer optimization
echo 'net.core.somaxconn = 65535' >> /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 5000'
echo 'net.ipv4.tcp_max_syn_backlog = 65535'
echo 'net.ipv4.tcp_fin_timeout = 30'
echo 'net.ipv4.tcp_keepalive_time = 1200'
echo 'net.ipv4.tcp_max_tw_buckets = 2000000'
echo 'net.ipv4.ip_local_port_range = 10000 65000'

# Apply changes
sysctl -p
```

#### File Descriptor Limits

```bash
# Increase file descriptor limits
echo '* soft nofile 65535' >> /etc/security/limits.conf
echo '* hard nofile 65535' >> /etc/security/limits.conf
echo 'root soft nofile 65535' >> /etc/security/limits.conf
echo 'root hard nofile 65535' >> /etc/security/limits.conf
```

#### Process Limits

```bash
# Increase process limits
echo 'vm.max_map_count = 262144' >> /etc/sysctl.conf
echo 'fs.file-max = 65535' >> /etc/sysctl.conf
```

### Container Optimization

#### Docker Performance Settings

```yaml
# docker-compose.yml performance settings
version: '3.8'
services:
  proxipy:
    image: proxipy:latest
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 4G
        reservations:
          cpus: '2.0'
          memory: 2G
    environment:
      - PYTHONUNBUFFERED=1
      - PYTHONOPTIMIZE=1
      - MAX_WORKERS=4
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
```

#### Kubernetes Performance Settings

```yaml
# Pod resource limits and requests
resources:
  requests:
    memory: "2Gi"
    cpu: "1000m"
  limits:
    memory: "4Gi"
    cpu: "4000m"

# Pod anti-affinity for distribution
affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
        - key: app
          operator: In
          values:
          - proxipy
      topologyKey: kubernetes.io/hostname
```

## Scaling Strategies

### Horizontal Scaling

#### Load Balancer Configuration

```haproxy
# HAProxy configuration for horizontal scaling
frontend proxipy_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/proxipy.pem
    default_backend proxipy_backend

backend proxipy_backend
    balance leastconn
    option httpchk GET /health
    server proxipy1 10.0.1.10:6969 check maxconn 1000
    server proxipy2 10.0.1.11:6969 check maxconn 1000
    server proxipy3 10.0.1.12:6969 check maxconn 1000
    server proxipy4 10.0.1.13:6969 check maxconn 1000
```

#### Auto Scaling Configuration

```yaml
# Kubernetes Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: proxipy-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: proxipy
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Vertical Scaling

#### CPU Scaling

```yaml
# Increase CPU allocation
performance:
  max_workers: 16  # For 16-core systems
  worker_class: "uvicorn.workers.UvicornWorker"
```

#### Memory Scaling

```yaml
# Increase memory allocation
performance:
  max_connections: 4000  # For high-memory systems
  max_buffer_size: 4194304  # 4MB buffers
```

### Database Scaling

#### Redis Optimization

```yaml
# Redis configuration for high performance
rate_limiting:
  redis_url: "redis://redis-cluster:6379"
  redis_pool_size: 100
  redis_timeout: 5.0
```

#### Redis Cluster Configuration

```bash
# Redis cluster setup for distributed rate limiting
redis-cli --cluster create 10.0.1.10:6379 10.0.1.11:6379 10.0.1.12:6379 \
  --cluster-replicas 1
```

## Performance Best Practices

### 1. Monitor Continuously

- Set up monitoring for key metrics
- Use alerting for performance degradation
- Regular performance testing

### 2. Optimize Gradually

- Start with basic optimization
- Measure impact of each change
- Roll back changes that hurt performance

### 3. Test Under Load

- Use realistic load testing
- Test with production-like data
- Monitor resource usage during tests

### 4. Use Caching Strategically

- Cache expensive computations
- Use Redis for distributed caching
- Implement proper cache invalidation

### 5. Optimize Network

- Use HTTP/2 for better performance
- Enable compression for text content
- Minimize round trips

### 6. Scale Appropriately

- Scale horizontally for availability
- Scale vertically for performance
- Use auto-scaling for dynamic workloads

This performance optimization guide provides comprehensive strategies for maximizing Proxipy's performance in any deployment scenario. Always test changes in a staging environment before applying them to production.

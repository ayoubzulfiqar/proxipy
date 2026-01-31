# Proxipy Deployment Guide

This guide provides comprehensive instructions for deploying Proxipy in various environments, from development to production.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Deployment](#development-deployment)
- [Staging Deployment](#staging-deployment)
- [Production Deployment](#production-deployment)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Cloud Platform Deployment](#cloud-platform-deployment)
- [Monitoring & Maintenance](#monitoring--maintenance)
- [Security Hardening](#security-hardening)
- [Scaling Strategies](#scaling-strategies)

## Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, Windows
- **Python**: 3.8 or higher
- **Memory**: Minimum 512MB, Recommended 2GB+
- **Storage**: 100MB for application + logs
- **Network**: Internet access for dependencies

### Dependencies

```bash
# Core dependencies
python>=3.8
fastapi
uvicorn[standard]
httpx
redis  # Optional, for enhanced rate limiting

# Development dependencies
pytest
pytest-asyncio
pytest-cov
pylint
black
mypy
```

### Optional Services

- **Redis**: For distributed rate limiting
- **Prometheus**: For metrics collection
- **Grafana**: For monitoring dashboards
- **Nginx**: For reverse proxy and SSL termination

## Development Deployment

### Local Development Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/ayoubzulfiqar/proxipy.git
   cd proxipy
   ```

2. **Create virtual environment:**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure for development:**

   ```bash
   cp config.yaml config.development.yaml
   # Edit config.development.yaml for development settings
   ```

5. **Run the server:**

   ```bash
   python -m app.main
   ```

6. **Verify deployment:**

   ```bash
   curl http://localhost:6969/health
   ```

### Development Configuration

Create `config.development.yaml`:

```yaml
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

load_balancer:
  enabled: false  # Disable for development
```

### Development Tools

#### Hot Reload

Enable automatic restart on code changes:

```bash
# Install watchgod for file watching
pip install watchgod

# Run with hot reload
watchgod app.main:app
```

#### Debug Mode

Enable detailed logging and error messages:

```yaml
server:
  debug: true
logging:
  log_level: "DEBUG"
```

#### Development Proxy

Use Proxipy as a development proxy:

```javascript
// In your frontend application
const proxyUrl = 'http://localhost:6969/proxy';
const apiUrl = 'https://api.example.com/data';

fetch(`${proxyUrl}?url=${encodeURIComponent(apiUrl)}`)
  .then(response => response.json())
  .then(data => console.log(data));
```

## Staging Deployment

### Staging Environment Setup

1. **Provision staging server:**

   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install python3 python3-pip python3-venv nginx
   
   # CentOS/RHEL
   sudo yum install python3 python3-pip python3-venv nginx
   ```

2. **Create application user:**

   ```bash
   sudo useradd -m -s /bin/bash proxipy
   sudo usermod -aG sudo proxipy
   ```

3. **Deploy application:**

   ```bash
   sudo -u proxipy mkdir /home/proxipy/app
   sudo -u proxipy git clone https://github.com/ayoubzulfiqar/proxipy.git /home/proxipy/app
   ```

4. **Setup environment:**

   ```bash
   sudo -u proxipy python3 -m venv /home/proxipy/app/.venv
   source /home/proxipy/app/.venv/bin/activate
   pip install -r /home/proxipy/app/requirements.txt
   ```

### Staging Configuration

Create `/home/proxipy/app/config.staging.yaml`:

```yaml
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
  redis_url: "redis://staging-redis:6379"

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
  log_file: "/var/log/proxipy/proxy.log"
  structured_logging: true

metrics:
  enabled: true
  haproxy_style_enabled: true
```

### Staging Services

#### Systemd Service

Create `/etc/systemd/system/proxipy.service`:

```ini
[Unit]
Description=Proxipy CORS Proxy Server
After=network.target

[Service]
Type=simple
User=proxipy
Group=proxipy
WorkingDirectory=/home/proxipy/app
Environment=PATH=/home/proxipy/app/.venv/bin
Environment=CONFIG_FILE=config.staging.yaml
ExecStart=/home/proxipy/app/.venv/bin/python -m app.main
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

#### Nginx Configuration

Create `/etc/nginx/sites-available/proxipy-staging`:

```nginx
server {
    listen 80;
    server_name staging-proxy.example.com;

    location / {
        proxy_pass http://127.0.0.1:6969;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeout settings
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:6969/health;
        access_log off;
    }
}
```

#### SSL Configuration (Let's Encrypt)

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d staging-proxy.example.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## Production Deployment

### Production Environment Setup

#### High Availability Architecture

```
Internet
    ↓
Load Balancer (HAProxy/Nginx)
    ↓
┌─────────────────┐
│   Proxipy 1   │
│   (Instance)  │
└─────────────────┘
    ↓
┌─────────────────┐
│   Proxipy 2   │
│   (Instance)  │
└─────────────────┘
    ↓
Backend Services
```

#### Production Server Requirements

- **Minimum**: 2 CPU cores, 4GB RAM, 20GB SSD
- **Recommended**: 4 CPU cores, 8GB RAM, 50GB SSD
- **High Traffic**: 8+ CPU cores, 16GB+ RAM, 100GB+ SSD

### Production Configuration

Create `config.production.yaml`:

```yaml
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
  redis_url: "redis://prod-redis-cluster:6379"

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
  haproxy_style_enabled: true
```

### Production Services

#### Multiple Instance Deployment

**Instance 1** (`config.instance1.yaml`):

```yaml
server:
  port: 6969
load_balancer:
  backend_servers:
    - host: "backend1.prod.example.com"
      port: 443
      weight: 1
    - host: "backend2.prod.example.com"
      port: 443
      weight: 1
```

**Instance 2** (`config.instance2.yaml`):

```yaml
server:
  port: 6970
load_balancer:
  backend_servers:
    - host: "backend2.prod.example.com"
      port: 443
      weight: 1
    - host: "backend3.prod.example.com"
      port: 443
      weight: 1
```

#### Load Balancer Configuration (HAProxy)

Create `/etc/haproxy/haproxy.cfg`:

```haproxy
global
    daemon
    maxconn 4096
    log stdout local0

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog

frontend proxipy_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/proxipy.pem
    redirect scheme https if !{ ssl_fc }
    
    acl health_check path_beg /health
    use_backend health_backend if health_check
    
    default_backend proxipy_backend

backend health_backend
    server health_check 127.0.0.1:6969 check

backend proxipy_backend
    balance leastconn
    option httpchk GET /health
    server proxipy1 127.0.0.1:6969 check
    server proxipy2 127.0.0.1:6970 check
```

#### Monitoring Setup

**Prometheus Configuration** (`prometheus.yml`):

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'proxipy'
    static_configs:
      - targets: ['localhost:6969']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

**Grafana Dashboard**: Import dashboard for Proxipy metrics

## Docker Deployment

### Docker Compose Setup

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  proxipy:
    build: .
    ports:
      - "6969:6969"
    environment:
      - DEBUG=false
      - REDIS_URL=redis://redis:6379
      - LOG_LEVEL=INFO
    volumes:
      - ./config.production.yaml:/app/config.yaml
      - ./proxy.log:/app/proxy.log
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - proxipy
    restart: unless-stopped

volumes:
  redis_data:
```

### Docker Production Setup

**Multi-stage Dockerfile** (`Dockerfile.prod`):

```dockerfile
# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Create non-root user
RUN useradd --create-home --shell /bin/bash app

# Copy Python dependencies from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=app:app . .

# Switch to non-root user
USER app

# Expose port
EXPOSE 6969

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:6969/health || exit 1

# Start command
CMD ["python", "-m", "app.main"]
```

### Docker Swarm Deployment

Create `docker-stack.yml`:

```yaml
version: '3.8'

services:
  proxipy:
    image: proxipy:latest
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
    environment:
      - REDIS_URL=redis://redis:6379
      - LOG_LEVEL=INFO
    volumes:
      - ./config.yaml:/app/config.yaml
    networks:
      - proxipy-net

  redis:
    image: redis:alpine
    deploy:
      replicas: 1
      resources:
        limits:
          memory: 256M
    volumes:
      - redis_data:/data
    networks:
      - proxipy-net

networks:
  proxipy-net:

volumes:
  redis_data:
```

## Kubernetes Deployment

### Kubernetes Manifests

**ConfigMap** (`k8s-configmap.yaml`):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: proxipy-config
  namespace: proxipy
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
```

**Secret** (`k8s-secret.yaml`):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: proxipy-secrets
  namespace: proxipy
type: Opaque
data:
  secret_key: <base64-encoded-secret-key>
```

**Deployment** (`k8s-deployment.yaml`):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: proxipy
  namespace: proxipy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: proxipy
  template:
    metadata:
      labels:
        app: proxipy
    spec:
      containers:
      - name: proxipy
        image: proxipy:latest
        ports:
        - containerPort: 6969
        env:
        - name: CONFIG_FILE
          value: "/app/config.yaml"
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: proxipy-secrets
              key: secret_key
        volumeMounts:
        - name: config-volume
          mountPath: /app/config.yaml
          subPath: config.yaml
        - name: logs-volume
          mountPath: /app/proxy.log
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 6969
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 6969
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config-volume
        configMap:
          name: proxipy-config
      - name: logs-volume
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: proxipy-service
  namespace: proxipy
spec:
  selector:
    app: proxipy
  ports:
  - protocol: TCP
    port: 80
    targetPort: 6969
  type: ClusterIP
```

**Ingress** (`k8s-ingress.yaml`):

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: proxipy-ingress
  namespace: proxipy
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
  - hosts:
    - proxy.example.com
    secretName: proxipy-tls
  rules:
  - host: proxy.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: proxipy-service
            port:
              number: 80
```

## Cloud Platform Deployment

### AWS Deployment

#### EC2 Deployment

1. **Launch EC2 Instance:**
   - AMI: Ubuntu 22.04 LTS
   - Instance Type: t3.medium or larger
   - Security Group: Allow ports 22, 80, 443

2. **Install and Configure:**

   ```bash
   # SSH into instance
   ssh -i your-key.pem ubuntu@your-instance-ip
   
   # Install dependencies
   sudo apt update
   sudo apt install python3 python3-pip python3-venv nginx
   
   # Deploy application (same as staging deployment)
   ```

3. **Elastic Load Balancer:**
   - Create Application Load Balancer
   - Configure target groups for EC2 instances
   - Set up SSL certificates via ACM

#### ECS Deployment

**Task Definition** (`task-definition.json`):

```json
{
  "family": "proxipy-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "proxipy",
      "image": "your-account.dkr.ecr.region.amazonaws.com/proxipy:latest",
      "portMappings": [
        {
          "containerPort": 6969,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "REDIS_URL",
          "value": "redis://your-elasticache-endpoint:6379"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/proxipy",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Google Cloud Platform Deployment

#### Compute Engine

Similar to AWS EC2 deployment, but using Google Cloud SDK:

```bash
# Create instance
gcloud compute instances create proxipy-server \
  --machine-type=e2-medium \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud

# SSH and deploy (same as other deployments)
```

#### Cloud Run

**Dockerfile for Cloud Run:**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["python", "-m", "app.main"]
```

**Deploy to Cloud Run:**

```bash
# Build and push to Container Registry
gcloud builds submit --tag gcr.io/your-project/proxipy

# Deploy to Cloud Run
gcloud run deploy proxipy \
  --image gcr.io/your-project/proxipy \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

### Azure Deployment

#### Azure Container Instances

**Deployment Template** (`aci-template.json`):

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.ContainerInstance/containerGroups",
      "apiVersion": "2021-09-01",
      "name": "proxipy-container",
      "location": "[resourceGroup().location]",
      "properties": {
        "containers": [
          {
            "name": "proxipy",
            "properties": {
              "image": "your-registry.azurecr.io/proxipy:latest",
              "ports": [
                {
                  "protocol": "TCP",
                  "port": 6969
                }
              ],
              "environmentVariables": [
                {
                  "name": "REDIS_URL",
                  "value": "redis://your-redis:6379"
                }
              ],
              "resources": {
                "requests": {
                  "cpu": 1,
                  "memoryInGB": 2
                }
              }
            }
          }
        ],
        "osType": "Linux",
        "ipAddress": {
          "type": "Public",
          "ports": [
            {
              "protocol": "TCP",
              "port": 6969
            }
          ]
        }
      }
    }
  ]
}
```

## Monitoring & Maintenance

### Health Monitoring

#### Application Health Checks

```bash
# Basic health check
curl -f http://localhost:6969/health

# Detailed health check with load balancer status
curl -f http://localhost:6969/health | jq '.load_balancer.healthy_servers'

# Metrics endpoint
curl http://localhost:6969/metrics
```

#### System Monitoring

**Prometheus Alert Rules** (`alerts.yml`):

```yaml
groups:
- name: proxipy
  rules:
  - alert: ProxipyDown
    expr: up{job="proxipy"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Proxipy instance is down"
      description: "Proxipy instance {{ $labels.instance }} has been down for more than 1 minute"

  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value }} errors per second"
```

### Log Management

#### Centralized Logging

**Fluentd Configuration** (`fluentd.conf`):

```xml
<source>
  @type tail
  path /var/log/proxipy/proxy.log
  pos_file /var/log/fluentd/proxipy.log.pos
  tag proxipy
  format json
</source>

<match proxipy>
  @type forward
  <server>
    name log-server
    host log.example.com
    port 24224
  </server>
</match>
```

#### Log Analysis

**Common Log Queries:**

```bash
# Top error responses
grep "ERROR" proxy.log | awk '{print $8}' | sort | uniq -c | sort -nr

# Response time analysis
grep "X-Process-Time" proxy.log | awk -F': ' '{print $2}' | sort -n

# Rate limiting violations
grep "429" proxy.log | wc -l
```

### Backup and Recovery

#### Configuration Backup

```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/backup/proxipy/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup configuration
cp config.yaml "$BACKUP_DIR/"
cp config.*.yaml "$BACKUP_DIR/" 2>/dev/null

# Backup logs (last 24 hours)
find /var/log/proxipy -name "*.log" -mtime -1 -exec cp {} "$BACKUP_DIR/" \;

# Compress backup
tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname $BACKUP_DIR)" "$(basename $BACKUP_DIR)"
rm -rf "$BACKUP_DIR"

# Upload to cloud storage (example: AWS S3)
aws s3 cp "$BACKUP_DIR.tar.gz" s3://your-backup-bucket/proxipy/
```

#### Database Backup (Redis)

```bash
# Redis backup script
#!/bin/bash

REDIS_HOST="localhost"
REDIS_PORT="6379"
BACKUP_DIR="/backup/redis/$(date +%Y%m%d_%H%M%S)"

mkdir -p "$BACKUP_DIR"
redis-cli -h $REDIS_HOST -p $REDIS_PORT BGSAVE
sleep 5
cp /var/lib/redis/dump.rdb "$BACKUP_DIR/redis_backup.rdb"
```

## Security Hardening

### Network Security

#### Firewall Configuration

**UFW (Ubuntu):**

```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow Proxipy port (if direct access needed)
sudo ufw allow 6969/tcp

# Enable firewall
sudo ufw enable
```

**iptables:**

```bash
# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Drop everything else
iptables -A INPUT -j DROP
```

### Application Security

#### Security Headers

Ensure all security headers are properly configured:

```yaml
security:
  enable_csp: true
  enable_hsts: true
  enable_cors: true
  enable_corp: true
  enable_coep: true
  enable_coop: true
```

#### Rate Limiting

Configure aggressive rate limiting for production:

```yaml
rate_limiting:
  rate_limit_per_minute: 30  # More restrictive
  rate_limit_per_hour: 500
  burst_size: 5
  block_duration: 600  # 10 minutes
```

#### SSL/TLS Configuration

**Nginx SSL Configuration:**

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;

# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# CSP
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';";

# Other security headers
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
```

### Secrets Management

#### Environment Variables

Use environment variables for sensitive configuration:

```bash
# Use a secrets manager or environment file
export SECRET_KEY=$(cat /run/secrets/secret_key)
export REDIS_PASSWORD=$(cat /run/secrets/redis_password)
```

#### Docker Secrets

**Docker Compose with Secrets:**

```yaml
version: '3.8'

services:
  proxipy:
    image: proxipy:latest
    secrets:
      - secret_key
      - redis_password
    environment:
      - SECRET_KEY_FILE=/run/secrets/secret_key
      - REDIS_PASSWORD_FILE=/run/secrets/redis_password

secrets:
  secret_key:
    file: ./secrets/secret_key.txt
  redis_password:
    file: ./secrets/redis_password.txt
```

## Scaling Strategies

### Horizontal Scaling

#### Load Balancer Configuration

**HAProxy for Horizontal Scaling:**

```haproxy
backend proxipy_backend
    balance leastconn
    option httpchk GET /health
    server proxipy1 10.0.1.10:6969 check
    server proxipy2 10.0.1.11:6969 check
    server proxipy3 10.0.1.12:6969 check
    server proxipy4 10.0.1.13:6969 check
```

#### Auto Scaling (AWS)

**Auto Scaling Group Configuration:**

```json
{
  "AutoScalingGroupName": "proxipy-asg",
  "LaunchConfigurationName": "proxipy-lc",
  "MinSize": 2,
  "MaxSize": 10,
  "DesiredCapacity": 3,
  "VPCZoneIdentifier": "subnet-12345,subnet-67890",
  "TargetGroupARNs": ["arn:aws:elasticloadbalancing:...:targetgroup/..."],
  "HealthCheckType": "ELB",
  "HealthCheckGracePeriod": 300,
  "Tags": [
    {
      "Key": "Environment",
      "Value": "Production",
      "PropagateAtLaunch": true
    }
  ]
}
```

### Vertical Scaling

#### Resource Optimization

**Memory Optimization:**

```yaml
performance:
  max_connections: 1000  # Increase based on available memory
  max_workers: 16        # Increase based on CPU cores
  connection_timeout: 10.0
  read_timeout: 30.0
```

**CPU Optimization:**

```yaml
# Use multiple workers for CPU-bound tasks
performance:
  max_workers: $(nproc)  # Number of CPU cores
```

### Database Scaling

#### Redis Clustering

**Redis Cluster Configuration:**

```yaml
rate_limiting:
  redis_url: "redis://redis-cluster:6379"
  # Use Redis Cluster for distributed rate limiting
```

#### Read Replicas

**Redis Read Replicas:**

```yaml
rate_limiting:
  redis_url: "redis://redis-master:6379"
  # Use read replicas for metrics and monitoring
```

This comprehensive deployment guide covers all major deployment scenarios for Proxipy. Choose the appropriate section based on your environment and requirements.

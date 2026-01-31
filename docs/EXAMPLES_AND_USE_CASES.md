# Proxipy Examples and Use Cases

This guide provides comprehensive examples and real-world use cases for Proxipy CORS proxy server.

## Table of Contents

- [Basic Examples](#basic-examples)
- [Advanced Use Cases](#advanced-use-cases)
- [Enterprise Examples](#enterprise-examples)
- [Development Examples](#development-examples)
- [Integration Examples](#integration-examples)
- [Performance Examples](#performance-examples)
- [Security Examples](#security-examples)
- [Load Balancer Examples](#load-balancer-examples)
- [Multi-Protocol Examples](#multi-protocol-examples)
- [Monitoring Examples](#monitoring-examples)

## Basic Examples

### 1. Simple CORS Proxy

**Use Case**: Bypass CORS restrictions for API calls

```javascript
// Frontend JavaScript
async function fetchUserData() {
  try {
    const response = await fetch('http://localhost:6969/proxy?url=https://api.example.com/users');
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching data:', error);
  }
}

// Usage
fetchUserData().then(users => {
  console.log('Users:', users);
});
```

### 2. POST Request with Custom Headers

**Use Case**: Send POST requests with custom authentication

```javascript
async function createUser(userData) {
  const response = await fetch('http://localhost:6969/proxy', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer your-token-here'
    },
    body: JSON.stringify({
      url: 'https://api.example.com/users',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer your-token-here'
      },
      body: JSON.stringify(userData)
    })
  });
  
  return response.json();
}

// Usage
const newUser = { name: 'John Doe', email: 'john@example.com' };
createUser(newUser).then(result => {
  console.log('User created:', result);
});
```

### 3. File Upload Proxy

**Use Case**: Proxy file uploads to external services

```javascript
async function uploadFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await fetch('http://localhost:6969/proxy', {
    method: 'POST',
    body: JSON.stringify({
      url: 'https://api.example.com/upload',
      method: 'POST',
      headers: {
        'Authorization': 'Bearer your-token-here'
      },
      body: formData
    })
  });
  
  return response.json();
}

// Usage with HTML file input
document.getElementById('fileInput').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  const result = await uploadFile(file);
  console.log('Upload result:', result);
});
```

## Advanced Use Cases

### 1. Microservices Gateway

**Use Case**: API gateway for microservices architecture

```yaml
# config.yaml for microservices gateway
server:
  port: 8080

load_balancer:
  enabled: true
  algorithm: "least_response_time"
  backend_servers:
    - host: "user-service.internal"
      port: 3001
      weight: 2
    - host: "product-service.internal"
      port: 3002
      weight: 2
    - host: "order-service.internal"
      port: 3003
      weight: 1

middleware:
  authentication:
    enabled: true
    jwt_secret: "${JWT_SECRET}"
    required_scopes: ["api:read", "api:write"]
  
  rate_limit:
    enabled: true
    requests_per_minute: 1000
    requests_per_hour: 10000
  
  compression:
    enabled: true
    min_size: 1024
```

```javascript
// Frontend microservices client
class MicroservicesClient {
  constructor(baseURL = 'http://localhost:8080') {
    this.baseURL = baseURL;
    this.token = localStorage.getItem('auth_token');
  }

  async request(service, endpoint, method = 'GET', data = null) {
    const url = `${this.baseURL}/proxy`;
    const targetUrl = `https://${service}.internal${endpoint}`;
    
    const options = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`
      },
      body: JSON.stringify({
        url: targetUrl,
        method: method,
        headers: {
          'Authorization': `Bearer ${this.token}`
        },
        body: data ? JSON.stringify(data) : null
      })
    };

    const response = await fetch(url, options);
    return response.json();
  }

  // Service-specific methods
  async getUser(userId) {
    return this.request('user-service', `/users/${userId}`, 'GET');
  }

  async createUser(userData) {
    return this.request('user-service', '/users', 'POST', userData);
  }

  async getProducts() {
    return this.request('product-service', '/products', 'GET');
  }

  async createOrder(orderData) {
    return this.request('order-service', '/orders', 'POST', orderData);
  }
}

// Usage
const client = new MicroservicesClient();
const user = await client.getUser('123');
const products = await client.getProducts();
```

### 2. Content Aggregation Service

**Use Case**: Aggregate content from multiple APIs

```yaml
# config.yaml for content aggregation
server:
  port: 3000

load_balancer:
  enabled: true
  algorithm: "round_robin"
  backend_servers:
    - host: "news-api.example.com"
      port: 443
      protocol: "https"
      weight: 1
    - host: "weather-api.example.com"
      port: 443
      protocol: "https"
      weight: 1
    - host: "stock-api.example.com"
      port: 443
      protocol: "https"
      weight: 1

middleware:
  compression:
    enabled: true
    min_size: 1024
  buffering:
    enabled: true
    max_buffer_size: 2097152  # 2MB
```

```javascript
// Content aggregation frontend
class ContentAggregator {
  constructor(proxyURL = 'http://localhost:3000') {
    this.proxyURL = proxyURL;
  }

  async aggregateContent() {
    const sources = [
      { name: 'news', url: 'https://news-api.example.com/top-headlines' },
      { name: 'weather', url: 'https://weather-api.example.com/current' },
      { name: 'stocks', url: 'https://stock-api.example.com/prices' }
    ];

    const results = {};

    for (const source of sources) {
      try {
        const response = await fetch(`${this.proxyURL}/proxy?url=${encodeURIComponent(source.url)}`);
        results[source.name] = await response.json();
      } catch (error) {
        console.error(`Error fetching ${source.name}:`, error);
        results[source.name] = { error: error.message };
      }
    }

    return results;
  }

  async getDashboardData() {
    const data = await this.aggregateContent();
    
    return {
      timestamp: new Date().toISOString(),
      news: data.news,
      weather: data.weather,
      stocks: data.stocks
    };
  }
}

// Usage
const aggregator = new ContentAggregator();
const dashboardData = await aggregator.getDashboardData();
console.log('Dashboard data:', dashboardData);
```

### 3. Development Proxy for Local Development

**Use Case**: Proxy API calls during local development

```yaml
# config.development.yaml
server:
  debug: true
  port: 3000

security:
  allowed_hosts: ["localhost", "127.0.0.1", "*.local"]

rate_limiting:
  enabled: false  # Disable for development

load_balancer:
  enabled: false  # Single backend for development

middleware:
  compression:
    enabled: false  # Disable for faster development
  buffering:
    enabled: true
    max_buffer_size: 1048576  # 1MB for development
```

```javascript
// Development proxy client
class DevProxyClient {
  constructor(proxyURL = 'http://localhost:3000') {
    this.proxyURL = proxyURL;
  }

  // Proxy API calls to staging environment
  async proxyToStaging(endpoint, method = 'GET', data = null) {
    const stagingURL = `https://staging-api.example.com${endpoint}`;
    
    const options = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url: stagingURL,
        method: method,
        headers: {
          'Authorization': 'Bearer your-staging-token'
        },
        body: data ? JSON.stringify(data) : null
      })
    };

    const response = await fetch(`${this.proxyURL}/proxy`, options);
    return response.json();
  }

  // Mock responses for development
  async mockResponse(endpoint, mockData) {
    // Store mock data in localStorage for offline development
    localStorage.setItem(`mock_${endpoint}`, JSON.stringify(mockData));
    return mockData;
  }
}

// Usage in development
const devClient = new DevProxyClient();

// Try to fetch real data, fallback to mock
async function getData(endpoint) {
  try {
    return await devClient.proxyToStaging(endpoint);
  } catch (error) {
    console.log('Using mock data:', error.message);
    const mockData = { message: 'Mock data for development' };
    return devClient.mockResponse(endpoint, mockData);
  }
}
```

## Enterprise Examples

### 1. Enterprise API Gateway

**Use Case**: Enterprise-grade API gateway with authentication and monitoring

```yaml
# config.enterprise.yaml
server:
  port: 443
  host: "0.0.0.0"

security:
  allowed_hosts: ["*.company.com", "*.internal"]
  enable_https_only: true
  max_content_length: 104857600  # 100MB

rate_limiting:
  enabled: true
  rate_limit_per_minute: 1000
  rate_limit_per_hour: 50000
  redis_url: "redis://enterprise-redis:6379"

load_balancer:
  enabled: true
  algorithm: "weighted_least_connections"
  session_stickiness: true
  session_timeout: 3600
  backend_servers:
    - host: "api-prod-1.company.com"
      port: 443
      protocol: "https"
      weight: 3
      max_connections: 1000
    - host: "api-prod-2.company.com"
      port: 443
      protocol: "https"
      weight: 3
      max_connections: 1000
    - host: "api-prod-3.company.com"
      port: 443
      protocol: "https"
      weight: 2
      max_connections: 800

middleware:
  authentication:
    enabled: true
    jwt_secret: "${JWT_SECRET}"
    jwt_algorithm: "RS256"
    required_scopes: ["api:read", "api:write", "admin:access"]
  
  rate_limit:
    enabled: true
    requests_per_minute: 1000
    requests_per_hour: 50000
  
  ip_filter:
    enabled: true
    whitelist: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    block_private_ips: false  # Allow internal IPs
  
  compression:
    enabled: true
    min_size: 2048
    compression_level: 6
  
  header_manipulation:
    enabled: true
    add_headers:
      "X-Company-API": "Enterprise Gateway"
      "X-Request-ID": "${REQUEST_ID}"
    remove_headers:
      - "Server"
      - "X-Powered-By"

logging:
  log_level: "INFO"
  log_file: "/var/log/proxipy/enterprise.log"
  structured_logging: true

metrics:
  enabled: true
  prometheus_enabled: true
  haproxy_style_enabled: true
```

```javascript
// Enterprise API client
class EnterpriseAPIClient {
  constructor(baseURL = 'https://api.company.com') {
    this.baseURL = baseURL;
    this.token = null;
  }

  async authenticate(credentials) {
    const response = await fetch(`${this.baseURL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    });
    
    const data = await response.json();
    this.token = data.token;
    return data;
  }

  async makeRequest(endpoint, method = 'GET', data = null) {
    if (!this.token) {
      throw new Error('Authentication required');
    }

    const response = await fetch(`${this.baseURL}/proxy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`
      },
      body: JSON.stringify({
        url: `https://internal-api.company.com${endpoint}`,
        method: method,
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'X-Company-API': 'Enterprise Gateway'
        },
        body: data ? JSON.stringify(data) : null
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return response.json();
  }

  // Department-specific clients
  async getUserManagementClient() {
    return new DepartmentClient(this, '/user-management');
  }

  async getFinanceClient() {
    return new DepartmentClient(this, '/finance');
  }

  async getHRClient() {
    return new DepartmentClient(this, '/hr');
  }
}

class DepartmentClient {
  constructor(apiClient, departmentPath) {
    this.apiClient = apiClient;
    this.departmentPath = departmentPath;
  }

  async getUsers() {
    return this.apiClient.makeRequest(`${this.departmentPath}/users`);
  }

  async createUser(userData) {
    return this.apiClient.makeRequest(`${this.departmentPath}/users`, 'POST', userData);
  }
}
```

### 2. Multi-Region Load Balancer

**Use Case**: Global load balancing across multiple regions

```yaml
# config.global.yaml
server:
  port: 443

load_balancer:
  enabled: true
  algorithm: "least_response_time"
  session_stickiness: true
  session_timeout: 1800
  
  backend_servers:
    # North America
    - host: "api-na1.company.com"
      port: 443
      protocol: "https"
      weight: 3
      region: "us-east-1"
    - host: "api-na2.company.com"
      port: 443
      protocol: "https"
      weight: 3
      region: "us-west-2"
    
    # Europe
    - host: "api-eu1.company.com"
      port: 443
      protocol: "https"
      weight: 2
      region: "eu-west-1"
    - host: "api-eu2.company.com"
      port: 443
      protocol: "https"
      weight: 2
      region: "eu-central-1"
    
    # Asia Pacific
    - host: "api-ap1.company.com"
      port: 443
      protocol: "https"
      weight: 1
      region: "ap-southeast-1"
    - host: "api-ap2.company.com"
      port: 443
      protocol: "https"
      weight: 1
      region: "ap-northeast-1"

middleware:
  rate_limit:
    enabled: true
    requests_per_minute: 500
    requests_per_hour: 25000
  
  compression:
    enabled: true
    min_size: 1024
```

```javascript
// Global load balancer client
class GlobalAPIClient {
  constructor(baseURL = 'https://api.company.com') {
    this.baseURL = baseURL;
    this.regionPreference = this.detectRegion();
  }

  detectRegion() {
    // Simple region detection based on latency
    const regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'];
    
    // Could use more sophisticated detection (IP geolocation, latency measurement)
    return regions[Math.floor(Math.random() * regions.length)];
  }

  async makeGlobalRequest(endpoint, method = 'GET', data = null) {
    const startTime = Date.now();
    
    try {
      const response = await fetch(`${this.baseURL}/proxy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: `https://api.${this.regionPreference}.company.com${endpoint}`,
          method: method,
          body: data ? JSON.stringify(data) : null
        })
      });

      const latency = Date.now() - startTime;
      console.log(`Request to ${this.regionPreference}: ${latency}ms`);

      return response.json();
    } catch (error) {
      console.error(`Request failed for ${this.regionPreference}:`, error);
      // Fallback to another region
      return this.fallbackRequest(endpoint, method, data);
    }
  }

  async fallbackRequest(endpoint, method, data) {
    // Try different region
    const fallbackRegion = this.getFallbackRegion();
    console.log(`Falling back to ${fallbackRegion}`);
    
    return fetch(`${this.baseURL}/proxy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: `https://api.${fallbackRegion}.company.com${endpoint}`,
        method: method,
        body: data ? JSON.stringify(data) : null
      })
    }).then(response => response.json());
  }

  getFallbackRegion() {
    const regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'];
    const currentIndex = regions.indexOf(this.regionPreference);
    const fallbackIndex = (currentIndex + 1) % regions.length;
    return regions[fallbackIndex];
  }
}
```

## Development Examples

### 1. Local Development with Hot Reload

**Use Case**: Development setup with automatic configuration reloading

```yaml
# config.development.yaml
server:
  debug: true
  port: 3000

security:
  allowed_hosts: ["localhost", "127.0.0.1", "*.local"]

rate_limiting:
  enabled: false

load_balancer:
  enabled: false

middleware:
  compression:
    enabled: false
  buffering:
    enabled: true
    max_buffer_size: 1048576
```

```javascript
// Development proxy with hot reload
class DevProxyManager {
  constructor() {
    this.config = null;
    this.proxyURL = 'http://localhost:3000';
  }

  async loadConfig() {
    try {
      const response = await fetch(`${this.proxyURL}/config`);
      this.config = await response.json();
      console.log('Configuration loaded:', this.config);
    } catch (error) {
      console.error('Failed to load configuration:', error);
    }
  }

  async watchConfigChanges() {
    // Poll for configuration changes
    setInterval(async () => {
      await this.loadConfig();
    }, 5000); // Check every 5 seconds
  }

  async proxyRequest(targetURL, options = {}) {
    const proxyOptions = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      body: JSON.stringify({
        url: targetURL,
        method: options.method || 'GET',
        headers: options.headers,
        body: options.body
      })
    };

    const response = await fetch(`${this.proxyURL}/proxy`, proxyOptions);
    return response;
  }
}

// Usage
const devProxy = new DevProxyManager();
await devProxy.loadConfig();
devProxy.watchConfigChanges();

// Use the proxy
const response = await devProxy.proxyRequest('https://api.example.com/data', {
  method: 'GET',
  headers: { 'Authorization': 'Bearer token' }
});
```

### 2. Mock API Development

**Use Case**: Development with mock APIs and response simulation

```yaml
# config.mock.yaml
server:
  debug: true
  port: 3001

middleware:
  header_manipulation:
    enabled: true
    add_headers:
      "X-Mock-API": "true"
      "X-Response-Delay": "1000"  # Simulate network delay
```

```javascript
// Mock API client for development
class MockAPIClient {
  constructor(proxyURL = 'http://localhost:3001') {
    this.proxyURL = proxyURL;
  }

  async mockRequest(endpoint, mockData, delay = 1000) {
    // Store mock data
    localStorage.setItem(`mock_${endpoint}`, JSON.stringify(mockData));
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, delay));
    
    return mockData;
  }

  async proxyWithMock(targetURL, mockEndpoint, mockData) {
    try {
      // Try real API first
      const response = await fetch(`${this.proxyURL}/proxy?url=${encodeURIComponent(targetURL)}`);
      return response.json();
    } catch (error) {
      console.log('Using mock data for:', targetURL);
      return this.mockRequest(mockEndpoint, mockData);
    }
  }
}

// Usage
const mockClient = new MockAPIClient();

// Mock user data
const mockUsers = [
  { id: 1, name: 'John Doe', email: 'john@example.com' },
  { id: 2, name: 'Jane Smith', email: 'jane@example.com' }
];

// Use mock or real API
const users = await mockClient.proxyWithMock(
  'https://api.example.com/users',
  '/users',
  mockUsers
);
```

## Integration Examples

### 1. React Integration

**Use Case**: React application with Proxipy integration

```jsx
// React hook for Proxipy integration
import { useState, useEffect } from 'react';

const useProxipy = (proxyURL = 'http://localhost:6969') => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchData = async (targetURL, options = {}) => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${proxyURL}/proxy`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        },
        body: JSON.stringify({
          url: targetURL,
          method: options.method || 'GET',
          headers: options.headers,
          body: options.body
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      setData(result);
      return result;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  return { data, loading, error, fetchData };
};

// React component using Proxipy
const UserProfile = ({ userId }) => {
  const { data: user, loading, error, fetchData } = useProxipy();

  useEffect(() => {
    if (userId) {
      fetchData(`https://api.example.com/users/${userId}`);
    }
  }, [userId, fetchData]);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!user) return <div>No user data</div>;

  return (
    <div>
      <h2>{user.name}</h2>
      <p>Email: {user.email}</p>
      <p>ID: {user.id}</p>
    </div>
  );
};
```

### 2. Vue.js Integration

**Use Case**: Vue.js application with Proxipy integration

```javascript
// Vue plugin for Proxipy
const ProxipyPlugin = {
  install(app, options) {
    const proxyURL = options.proxyURL || 'http://localhost:6969';

    const proxipy = {
      async get(url, headers = {}) {
        const response = await fetch(`${proxyURL}/proxy?url=${encodeURIComponent(url)}`, {
          headers
        });
        return response.json();
      },

      async post(url, data, headers = {}) {
        const response = await fetch(`${proxyURL}/proxy`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...headers
          },
          body: JSON.stringify({
            url,
            method: 'POST',
            headers,
            body: JSON.stringify(data)
          })
        });
        return response.json();
      }
    };

    app.config.globalProperties.$proxipy = proxipy;
    app.provide('proxipy', proxipy);
  }
};

// Vue component using Proxipy
export default {
  name: 'UserList',
  data() {
    return {
      users: [],
      loading: false,
      error: null
    };
  },
  async mounted() {
    await this.loadUsers();
  },
  methods: {
    async loadUsers() {
      this.loading = true;
      this.error = null;

      try {
        this.users = await this.$proxipy.get('https://api.example.com/users');
      } catch (error) {
        this.error = error.message;
      } finally {
        this.loading = false;
      }
    }
  }
};
```

### 3. Angular Integration

**Use Case**: Angular service for Proxipy integration

```typescript
// Angular service for Proxipy
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class ProxipyService {
  private proxyURL = 'http://localhost:6969';

  constructor(private http: HttpClient) {}

  private createProxyBody(targetURL: string, method: string, headers?: any, body?: any) {
    return {
      url: targetURL,
      method: method,
      headers: headers,
      body: body ? JSON.stringify(body) : null
    };
  }

  get<T>(targetURL: string, headers?: any): Observable<T> {
    const body = this.createProxyBody(targetURL, 'GET', headers);
    
    return this.http.post<T>(`${this.proxyURL}/proxy`, body, {
      headers: { 'Content-Type': 'application/json' }
    }).pipe(
      catchError(error => {
        console.error('Proxipy request failed:', error);
        return throwError(error);
      })
    );
  }

  post<T>(targetURL: string, data: any, headers?: any): Observable<T> {
    const body = this.createProxyBody(targetURL, 'POST', headers, data);
    
    return this.http.post<T>(`${this.proxyURL}/proxy`, body, {
      headers: { 'Content-Type': 'application/json' }
    }).pipe(
      catchError(error => {
        console.error('Proxipy request failed:', error);
        return throwError(error);
      })
    );
  }
}

// Angular component using Proxipy
@Component({
  selector: 'app-user-list',
  template: `
    <div *ngIf="loading">Loading...</div>
    <div *ngIf="error">Error: {{ error }}</div>
    <div *ngFor="let user of users">
      <h3>{{ user.name }}</h3>
      <p>{{ user.email }}</p>
    </div>
  `
})
export class UserListComponent implements OnInit {
  users: any[] = [];
  loading = false;
  error: string | null = null;

  constructor(private proxipyService: ProxipyService) {}

  ngOnInit() {
    this.loadUsers();
  }

  async loadUsers() {
    this.loading = true;
    this.error = null;

    try {
      const users = await this.proxipyService.get<any[]>('https://api.example.com/users').toPromise();
      this.users = users;
    } catch (error) {
      this.error = error.message;
    } finally {
      this.loading = false;
    }
  }
}
```

## Performance Examples

### 1. High-Performance Configuration

**Use Case**: Optimized configuration for high-traffic scenarios

```yaml
# config.performance.yaml
server:
  port: 6969
  host: "0.0.0.0"

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

rate_limiting:
  enabled: true
  rate_limit_per_minute: 2000
  rate_limit_per_hour: 20000
  redis_url: "redis://high-performance-redis:6379"

load_balancer:
  enabled: true
  algorithm: "least_response_time"
  session_stickiness: true
  session_timeout: 1800
  backend_servers:
    - host: "backend1.highperf.com"
      port: 443
      protocol: "https"
      weight: 3
      max_connections: 1000
    - host: "backend2.highperf.com"
      port: 443
      protocol: "https"
      weight: 3
      max_connections: 1000
    - host: "backend3.highperf.com"
      port: 443
      protocol: "https"
      weight: 2
      max_connections: 800

middleware:
  enabled: true
  
  rate_limit:
    enabled: true
    requests_per_minute: 2000
    requests_per_hour: 20000
  
  compression:
    enabled: true
    min_size: 4096
    compression_level: 1  # Lower compression for speed
  
  header_manipulation:
    enabled: true
    add_headers:
      "X-Performance": "High-Performance Mode"

logging:
  log_level: "WARNING"
  structured_logging: true

metrics:
  enabled: true
  prometheus_enabled: true
```

### 2. CDN Integration

**Use Case**: Integration with Content Delivery Network

```yaml
# config.cdn.yaml
server:
  port: 443

load_balancer:
  enabled: true
  algorithm: "least_response_time"
  backend_servers:
    # CDN edge servers
    - host: "cdn-edge-1.example.com"
      port: 443
      protocol: "https"
      weight: 2
    - host: "cdn-edge-2.example.com"
      port: 443
      protocol: "https"
      weight: 2
    - host: "cdn-edge-3.example.com"
      port: 443
      protocol: "https"
      weight: 1
    
    # Origin servers
    - host: "origin-1.example.com"
      port: 443
      protocol: "https"
      weight: 1

middleware:
  compression:
    enabled: true
    min_size: 1024
  buffering:
    enabled: true
    max_buffer_size: 4194304  # 4MB for large files
```

```javascript
// CDN-aware client
class CDNClient {
  constructor(proxyURL = 'https://cdn-proxy.example.com') {
    this.proxyURL = proxyURL;
    this.region = this.detectRegion();
  }

  detectRegion() {
    // Detect user region for optimal CDN selection
    const regions = ['us', 'eu', 'ap', 'sa'];
    // Implementation would use IP geolocation
    return regions[0];
  }

  async fetchContent(contentURL, options = {}) {
    const cdnURL = this.getCdnURL(contentURL);
    
    return fetch(`${this.proxyURL}/proxy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Region': this.region,
        ...options.headers
      },
      body: JSON.stringify({
        url: cdnURL,
        method: options.method || 'GET',
        headers: options.headers,
        body: options.body
      })
    });
  }

  getCdnURL(contentURL) {
    // Transform content URL to CDN URL
    return contentURL.replace('https://origin.example.com', `https://cdn-${this.region}.example.com`);
  }
}
```

## Security Examples

### 1. OAuth2 Integration

**Use Case**: OAuth2 authentication with external providers

```yaml
# config.oauth.yaml
server:
  port: 443

middleware:
  authentication:
    enabled: true
    oauth2:
      provider: "auth0"
      client_id: "${OAUTH_CLIENT_ID}"
      client_secret: "${OAUTH_CLIENT_SECRET}"
      redirect_uri: "https://yourapp.com/auth/callback"
      scopes: ["openid", "profile", "email", "api:read", "api:write"]

security:
  allowed_hosts: ["*.yourdomain.com"]
  enable_https_only: true

rate_limiting:
  enabled: true
  rate_limit_per_minute: 100
  rate_limit_per_hour: 1000
```

```javascript
// OAuth2 client
class OAuth2Client {
  constructor(proxyURL = 'https://api.yourdomain.com') {
    this.proxyURL = proxyURL;
    this.authConfig = {
      provider: 'auth0',
      clientId: process.env.OAUTH_CLIENT_ID,
      redirectUri: 'https://yourapp.com/auth/callback',
      scopes: ['openid', 'profile', 'email', 'api:read', 'api:write']
    };
  }

  async initiateOAuth2() {
    const authURL = `https://${this.authConfig.provider}.com/authorize?` + new URLSearchParams({
      client_id: this.authConfig.clientId,
      redirect_uri: this.authConfig.redirectUri,
      scope: this.authConfig.scopes.join(' '),
      response_type: 'code'
    });

    window.location.href = authURL;
  }

  async handleOAuth2Callback(code) {
    const tokenResponse = await fetch(`${this.proxyURL}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: this.authConfig.clientId,
        client_secret: process.env.OAUTH_CLIENT_SECRET,
        code: code,
        redirect_uri: this.authConfig.redirectUri
      })
    });

    const tokens = await tokenResponse.json();
    localStorage.setItem('access_token', tokens.access_token);
    localStorage.setItem('refresh_token', tokens.refresh_token);
    
    return tokens;
  }

  async makeAuthenticatedRequest(endpoint, method = 'GET', data = null) {
    const token = localStorage.getItem('access_token');
    
    if (!token) {
      throw new Error('Authentication required');
    }

    return fetch(`${this.proxyURL}/proxy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        url: `https://api.internal.com${endpoint}`,
        method: method,
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: data ? JSON.stringify(data) : null
      })
    });
  }
}
```

### 2. IP Whitelisting for Internal APIs

**Use Case**: Restrict access to internal APIs based on IP addresses

```yaml
# config.ip-filter.yaml
server:
  port: 8080

middleware:
  ip_filter:
    enabled: true
    whitelist: 
      - "10.0.0.0/8"      # Internal network
      - "172.16.0.0/12"   # VPN range
      - "192.168.0.0/16"  # Local networks
      - "203.0.113.0/24"  # Partner network
    blacklist:
      - "198.51.100.0/24" # Known malicious range
    block_private_ips: false  # Allow internal access
    block_loopback: false     # Allow localhost

security:
  allowed_hosts: ["*.internal.company.com"]
  max_content_length: 26214400  # 25MB
```

```javascript
// IP-filtered API client
class IPFilteredClient {
  constructor(proxyURL = 'https://internal-proxy.company.com') {
    this.proxyURL = proxyURL;
  }

  async makeInternalRequest(endpoint, method = 'GET', data = null) {
    // Check if client is in allowed network (this would be done server-side)
    const clientIP = await this.getClientIP();
    
    return fetch(`${this.proxyURL}/proxy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-IP': clientIP
      },
      body: JSON.stringify({
        url: `https://internal-api.company.com${endpoint}`,
        method: method,
        headers: {
          'X-Client-IP': clientIP
        },
        body: data ? JSON.stringify(data) : null
      })
    });
  }

  async getClientIP() {
    // Get client IP from a service
    const response = await fetch('https://api.ipify.org?format=json');
    const data = await response.json();
    return data.ip;
  }
}
```

## Load Balancer Examples

### 1. Health Check Monitoring

**Use Case**: Monitor backend server health and automatically handle failures

```yaml
# config.health-monitor.yaml
load_balancer:
  enabled: true
  algorithm: "least_response_time"
  health_check:
    protocol: "http"
    path: "/health"
    port: null
    interval: 30.0
    timeout: 5.0
    healthy_threshold: 2
    unhealthy_threshold: 3
    expected_status: 200

middleware:
  circuit_breaker:
    enabled: true
    failure_threshold: 5
    recovery_timeout: 60.0
    half_open_max_requests: 3
    timeout: 30.0
```

```javascript
// Health monitoring client
class HealthMonitoringClient {
  constructor(proxyURL = 'http://localhost:6969') {
    this.proxyURL = proxyURL;
    this.healthStatus = new Map();
  }

  async getHealthStatus() {
    const response = await fetch(`${this.proxyURL}/health`);
    const healthData = await response.json();
    
    this.healthStatus.set('proxy', healthData);
    
    if (healthData.load_balancer) {
      this.healthStatus.set('load_balancer', healthData.load_balancer);
    }
    
    return healthData;
  }

  async getBackendStats() {
    const response = await fetch(`${this.proxyURL}/stats`);
    const stats = await response.json();
    
    this.healthStatus.set('backend_stats', stats);
    return stats;
  }

  async monitorHealth() {
    setInterval(async () => {
      try {
        await this.getHealthStatus();
        await this.getBackendStats();
        
        // Log health status
        console.log('Health Status:', this.healthStatus);
        
        // Alert on issues
        this.checkForIssues();
      } catch (error) {
        console.error('Health monitoring failed:', error);
      }
    }, 30000); // Check every 30 seconds
  }

  checkForIssues() {
    const lbStatus = this.healthStatus.get('load_balancer');
    const backendStats = this.healthStatus.get('backend_stats');
    
    if (lbStatus && lbStatus.unhealthy_servers > 0) {
      console.warn(`Warning: ${lbStatus.unhealthy_servers} unhealthy servers`);
    }
    
    if (backendStats && backendStats.backend) {
      backendStats.backend.forEach(server => {
        if (server.consecutive_failures > 3) {
          console.error(`Server ${server.name} has ${server.consecutive_failures} consecutive failures`);
        }
      });
    }
  }
}
```

### 2. Session Affinity

**Use Case**: Maintain user sessions across multiple backend servers

```yaml
# config.session-affinity.yaml
load_balancer:
  enabled: true
  algorithm: "source_ip_hash"
  session_stickiness: true
  session_timeout: 1800  # 30 minutes
  backend_servers:
    - host: "session-backend-1.example.com"
      port: 8080
      weight: 1
    - host: "session-backend-2.example.com"
      port: 8080
      weight: 1
    - host: "session-backend-3.example.com"
      port: 8080
      weight: 1

middleware:
  header_manipulation:
    enabled: true
    add_headers:
      "X-Session-ID": "${SESSION_ID}"
      "X-Backend-Server": "${BACKEND_SERVER}"
```

```javascript
// Session-affinity client
class SessionAffinityClient {
  constructor(proxyURL = 'http://localhost:6969') {
    this.proxyURL = proxyURL;
    this.sessionId = this.getSessionId();
  }

  getSessionId() {
    let sessionId = localStorage.getItem('session_id');
    if (!sessionId) {
      sessionId = this.generateSessionId();
      localStorage.setItem('session_id', sessionId);
    }
    return sessionId;
  }

  generateSessionId() {
    return 'session_' + Math.random().toString(36).substr(2, 9);
  }

  async makeSessionRequest(endpoint, method = 'GET', data = null) {
    return fetch(`${this.proxyURL}/proxy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Session-ID': this.sessionId
      },
      body: JSON.stringify({
        url: `https://session-api.example.com${endpoint}`,
        method: method,
        headers: {
          'X-Session-ID': this.sessionId
        },
        body: data ? JSON.stringify(data) : null
      })
    });
  }

  async getSessionInfo() {
    const response = await fetch(`${this.proxyURL}/proxy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: 'https://session-api.example.com/session/info',
        method: 'GET',
        headers: {
          'X-Session-ID': this.sessionId
        }
      })
    });

    return response.json();
  }
}
```

## Multi-Protocol Examples

### 1. WebSocket Proxy

**Use Case**: Proxy WebSocket connections for real-time applications

```yaml
# config.websocket.yaml
protocols:
  http: true
  https: true
  websocket: true
  websockets: true

middleware:
  compression:
    enabled: true
    min_size: 1024
```

```javascript
// WebSocket proxy client
class WebSocketProxyClient {
  constructor(proxyURL = 'ws://localhost:6969') {
    this.proxyURL = proxyURL;
    this.ws = null;
  }

  connect(targetWebSocketURL) {
    // Connect to proxy WebSocket
    this.ws = new WebSocket(`${this.proxyURL}/proxy/websocket`);
    
    this.ws.onopen = () => {
      // Send target WebSocket URL to proxy
      this.ws.send(JSON.stringify({
        type: 'connect',
        url: targetWebSocketURL
      }));
    };

    this.ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      
      if (message.type === 'message') {
        // Handle WebSocket message from target server
        this.handleMessage(message.data);
      } else if (message.type === 'error') {
        // Handle WebSocket error
        this.handleError(message.error);
      }
    };

    this.ws.onclose = () => {
      console.log('WebSocket connection closed');
    };
  }

  send(data) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'send',
        data: data
      }));
    }
  }

  handleMessage(data) {
    console.log('Received message:', data);
    // Handle message in your application
  }

  handleError(error) {
    console.error('WebSocket error:', error);
  }
}

// Usage
const wsClient = new WebSocketProxyClient();
wsClient.connect('wss://api.example.com/realtime');

// Send messages
wsClient.send({ type: 'subscribe', channel: 'updates' });
```

### 2. TCP Proxy

**Use Case**: Proxy TCP connections for custom protocols

```yaml
# config.tcp.yaml
protocols:
  tcp: true
  udp: false

middleware:
  buffering:
    enabled: true
    max_buffer_size: 1048576  # 1MB
    buffer_timeout: 5.0
```

```javascript
// TCP proxy client (Node.js example)
const net = require('net');

class TCPPRoxyClient {
  constructor(proxyHost = 'localhost', proxyPort = 6969) {
    this.proxyHost = proxyHost;
    this.proxyPort = proxyPort;
    this.socket = null;
  }

  connect(targetHost, targetPort) {
    return new Promise((resolve, reject) => {
      this.socket = net.createConnection(this.proxyPort, this.proxyHost);
      
      this.socket.on('connect', () => {
        // Send target server information
        const targetInfo = JSON.stringify({
          type: 'tcp_connect',
          host: targetHost,
          port: targetPort
        });
        
        this.socket.write(targetInfo + '\n');
      });

      this.socket.on('data', (data) => {
        const message = data.toString();
        console.log('Received:', message);
      });

      this.socket.on('error', (error) => {
        reject(error);
      });

      this.socket.on('close', () => {
        console.log('Connection closed');
      });
    });
  }

  send(data) {
    if (this.socket) {
      this.socket.write(JSON.stringify({
        type: 'tcp_data',
        data: data
      }) + '\n');
    }
  }

  close() {
    if (this.socket) {
      this.socket.end();
    }
  }
}

// Usage
const tcpClient = new TCPPRoxyClient();
tcpClient.connect('tcp-server.example.com', 8080)
  .then(() => {
    console.log('Connected to TCP server');
    tcpClient.send('Hello TCP Server!');
  })
  .catch(error => {
    console.error('Connection failed:', error);
  });
```

## Monitoring Examples

### 1. Prometheus Integration

**Use Case**: Monitor Proxipy with Prometheus and Grafana

```yaml
# config.monitoring.yaml
metrics:
  enabled: true
  prometheus_enabled: true
  haproxy_style_enabled: true

logging:
  log_level: "INFO"
  structured_logging: true
  log_file: "/var/log/proxipy/monitoring.log"
```

```python
# Prometheus metrics exporter
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time
import requests

# Metrics
requests_total = Counter('proxipy_requests_total', 'Total requests', ['method', 'status'])
response_time = Histogram('proxipy_response_time_seconds', 'Response time')
active_connections = Gauge('proxipy_active_connections', 'Active connections')
backend_health = Gauge('proxipy_backend_health', 'Backend server health', ['server'])

class ProxipyMonitor:
    def __init__(self, proxipy_url='http://localhost:6969'):
        self.proxipy_url = proxipy_url
        self.start_time = time.time()

    def collect_metrics(self):
        try:
            # Get health status
            health_response = requests.get(f"{self.proxipy_url}/health")
            health_data = health_response.json()
            
            # Update metrics
            active_connections.set(health_data.get('metrics', {}).get('active_connections', 0))
            
            # Get backend stats
            stats_response = requests.get(f"{self.proxipy_url}/stats")
            stats_data = stats_response.json()
            
            if 'backend' in stats_data:
                for server in stats_data['backend']:
                    backend_health.labels(server=server['name']).set(1 if server['is_healthy'] else 0)
            
        except Exception as e:
            print(f"Error collecting metrics: {e}")

    def start_monitoring(self, interval=30):
        # Start Prometheus metrics server
        start_http_server(8000)
        
        # Collect metrics periodically
        while True:
            self.collect_metrics()
            time.sleep(interval)

if __name__ == "__main__":
    monitor = ProxipyMonitor()
    monitor.start_monitoring()
```

### 2. Custom Dashboard

**Use Case**: Create custom monitoring dashboard

```html
<!DOCTYPE html>
<html>
<head>
    <title>Proxipy Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .dashboard {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            padding: 20px;
        }
        .card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric {
            font-size: 24px;
            font-weight: bold;
            color: #333;
        }
        .status {
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .healthy { background-color: #d4edda; color: #155724; }
        .unhealthy { background-color: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="card">
            <h3>System Health</h3>
            <div id="health-status" class="status healthy">Healthy</div>
            <div class="metric">Active Connections: <span id="active-connections">0</span></div>
            <div class="metric">Uptime: <span id="uptime">0</span> seconds</div>
        </div>
        
        <div class="card">
            <h3>Backend Servers</h3>
            <div id="backend-status"></div>
        </div>
        
        <div class="card">
            <h3>Request Rate</h3>
            <canvas id="request-chart"></canvas>
        </div>
        
        <div class="card">
            <h3>Response Time</h3>
            <canvas id="response-chart"></canvas>
        </div>
    </div>

    <script>
        class ProxipyDashboard {
            constructor(proxyURL = 'http://localhost:6969') {
                this.proxyURL = proxyURL;
                this.requestChart = null;
                this.responseChart = null;
                this.requestData = [];
                this.responseData = [];
            }

            async updateDashboard() {
                try {
                    // Get health data
                    const healthResponse = await fetch(`${this.proxyURL}/health`);
                    const healthData = await healthResponse.json();
                    
                    // Update health status
                    const healthStatus = document.getElementById('health-status');
                    if (healthData.status === 'healthy') {
                        healthStatus.className = 'status healthy';
                        healthStatus.textContent = 'Healthy';
                    } else {
                        healthStatus.className = 'status unhealthy';
                        healthStatus.textContent = 'Unhealthy';
                    }
                    
                    // Update metrics
                    document.getElementById('active-connections').textContent = 
                        healthData.metrics?.active_connections || 0;
                    document.getElementById('uptime').textContent = 
                        Math.floor(healthData.metrics?.uptime || 0);
                    
                    // Update backend status
                    this.updateBackendStatus(healthData.load_balancer);
                    
                    // Update charts
                    this.updateCharts(healthData.metrics);
                    
                } catch (error) {
                    console.error('Error updating dashboard:', error);
                }
            }

            updateBackendStatus(lbData) {
                const container = document.getElementById('backend-status');
                container.innerHTML = '';
                
                if (lbData && lbData.backend_servers) {
                    lbData.backend_servers.forEach(server => {
                        const div = document.createElement('div');
                        div.className = 'status ' + (server.is_healthy ? 'healthy' : 'unhealthy');
                        div.textContent = `${server.host}:${server.port} - ${server.is_healthy ? 'Healthy' : 'Unhealthy'}`;
                        container.appendChild(div);
                    });
                }
            }

            updateCharts(metrics) {
                // Update request chart
                if (this.requestChart) {
                    this.requestData.push(metrics?.total_requests || 0);
                    if (this.requestData.length > 20) this.requestData.shift();
                    
                    this.requestChart.data.datasets[0].data = this.requestData;
                    this.requestChart.update();
                }
                
                // Update response time chart
                if (this.responseChart) {
                    this.responseData.push(metrics?.avg_response_time || 0);
                    if (this.responseData.length > 20) this.responseData.shift();
                    
                    this.responseChart.data.datasets[0].data = this.responseData;
                    this.responseChart.update();
                }
            }

            initCharts() {
                // Request chart
                const requestCtx = document.getElementById('request-chart').getContext('2d');
                this.requestChart = new Chart(requestCtx, {
                    type: 'line',
                    data: {
                        labels: Array(20).fill(''),
                        datasets: [{
                            label: 'Total Requests',
                            data: [],
                            borderColor: 'rgb(75, 192, 192)',
                            tension: 0.1
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });

                // Response time chart
                const responseCtx = document.getElementById('response-chart').getContext('2d');
                this.responseChart = new Chart(responseCtx, {
                    type: 'line',
                    data: {
                        labels: Array(20).fill(''),
                        datasets: [{
                            label: 'Avg Response Time (ms)',
                            data: [],
                            borderColor: 'rgb(255, 99, 132)',
                            tension: 0.1
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });
            }

            start() {
                this.initCharts();
                setInterval(() => this.updateDashboard(), 5000);
                this.updateDashboard(); // Initial update
            }
        }

        // Start dashboard
        const dashboard = new ProxipyDashboard();
        dashboard.start();
    </script>
</body>
</html>
```

This comprehensive examples and use cases guide demonstrates the versatility and power of Proxipy in various scenarios, from simple CORS bypassing to complex enterprise-grade deployments with load balancing, monitoring, and security features.

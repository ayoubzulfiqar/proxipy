# Proxipy

A production-ready, secure CORS proxy server built with FastAPI to bypass same-origin policy and prevent mixed content issues.
To Setup on Reverse Proxy Sever you need to buy this own domain and change localhost with this ip bascially this domain ip and build a docker file and run

## Project Structure

```html
proxypy/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── security.py
│   ├── rate_limiter.py
│   ├── models.py
│   └── utils.py
├── tests/
│   ├── __init__.py
│   └── test_proxy.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
└── README.md

```

## Features

- ✅ CORS headers for cross-origin requests
- ✅ Rate limiting with Redis (falls back to memory)
- ✅ Security headers (CSP, HSTS, XSS Protection)
- ✅ Domain blocking for internal networks
- ✅ Content type validation
- ✅ Request size limits
- ✅ HTTP/2 support with Hypercorn
- ✅ Docker containerization
- ✅ Health checks
- ✅ Metrics endpoint
- ✅ Comprehensive error handling

## Quick Start

### Using Docker Compose (Recommended)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

python main.py

OR

docker-compose up -d

```

## Usage

### GET Request

```jsx
const response = await fetch('http://this-proxy/proxy?url=https://api.example.com/data');
const data = await response.json();
```

### POST Request

```jsx
const response = await fetch('http://this-proxy/proxy', {
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

## Py Client Usage

```py
import requests

def proxy_get(target_url):
    proxy_url = "https://this-proxy-server.com/proxy"
    params = {"url": target_url}
    response = requests.get(proxy_url, params=params)
    return response.json()

def proxy_post(target_url, data):
    proxy_url = "https://this-proxy-server.com/proxy"
    payload = {
        "url": target_url,
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(data)
    }
    response = requests.post(proxy_url, json=payload)
    return response.json()

```

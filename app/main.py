import asyncio
import logging
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from slowapi.errors import RateLimitExceeded

try:
    from .config import settings
    from .model import HealthResponse, ProxyRequest
    from .rate_limiter import get_rate_limiter, rate_limit_exceeded_handler
    from .security import security
    from .utils import proxy_utils
except ImportError:
    # Handle direct execution
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app.config import settings
    from app.model import HealthResponse, ProxyRequest
    from app.rate_limiter import get_rate_limiter, rate_limit_exceeded_handler
    from app.security import security
    from app.utils import proxy_utils

# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("proxy.log")],
)
logger = logging.getLogger(__name__)


# Enhanced metrics storage with thread safety
class MetricsStorage:
    def __init__(self):
        self._lock = threading.Lock()
        self.request_metrics = defaultdict(int)
        self.error_metrics = defaultdict(int)
        self.response_times = deque(maxlen=1000)
        self.active_connections = 0
        self.total_requests = 0
        self.start_time = time.time()

    def increment_request(self, method: str):
        with self._lock:
            self.request_metrics[method] += 1
            self.total_requests += 1

    def increment_error(self, error_type: str):
        with self._lock:
            self.error_metrics[error_type] += 1

    def add_response_time(self, response_time: float):
        with self._lock:
            self.response_times.append(response_time)

    def get_connection_count(self):
        with self._lock:
            return self.active_connections

    def increment_connection(self):
        with self._lock:
            self.active_connections += 1

    def decrement_connection(self):
        with self._lock:
            self.active_connections = max(0, self.active_connections - 1)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            avg_response_time = (
                sum(self.response_times) / len(self.response_times)
                if self.response_times
                else 0
            )
            return {
                "total_requests": self.total_requests,
                "requests_by_method": dict(self.request_metrics),
                "total_errors": sum(self.error_metrics.values()),
                "errors_by_type": dict(self.error_metrics),
                "avg_response_time": avg_response_time,
                "active_connections": self.active_connections,
                "uptime": time.time() - self.start_time,
            }


metrics = MetricsStorage()


# Connection pool for better performance
class ConnectionPool:
    def __init__(self, max_connections: int = 100):
        self.max_connections = max_connections
        self._semaphore = asyncio.Semaphore(max_connections)
        self._active_count = 0
        self._lock = asyncio.Lock()

    async def acquire(self):
        await self._semaphore.acquire()
        async with self._lock:
            self._active_count += 1
            metrics.increment_connection()

    async def release(self):
        self._semaphore.release()
        async with self._lock:
            self._active_count = max(0, self._active_count - 1)
            metrics.decrement_connection()

    def get_active_count(self):
        return self._active_count


connection_pool = ConnectionPool(settings.MAX_CONNECTIONS)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Application lifespan events"""
    # Startup
    print(f"Starting {settings.APP_NAME} v{settings.VERSION}")
    from .rate_limiter import initialize_redis

    await initialize_redis()
    yield
    # Shutdown
    await proxy_utils.close_client()


# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="A secure CORS proxy server to bypass same-origin policy",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Rate limiter
limiter = get_rate_limiter()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)  # type: ignore

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=settings.ALLOWED_HEADERS,
)


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()

    # Track request metrics
    metrics.increment_request(request.method)

    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        metrics.add_response_time(process_time)
        response.headers["X-Process-Time"] = str(process_time)

        # Add enhanced security headers
        return security.add_security_headers(response)

    except Exception as exc:
        # Track error metrics
        metrics.increment_error(type(exc).__name__)
        logger.error(f"Request error: {request.method} {request.url} - {str(exc)}")
        raise


@app.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint with health information"""
    return HealthResponse(
        status="healthy",
        version=settings.VERSION,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
    )


@app.get("/health")
async def health_check(request: Request):
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": time.time()}


@app.get("/metrics")
async def get_metrics():
    """Enhanced metrics endpoint"""
    return metrics.get_stats()


@app.get("/proxy")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def proxy_get(request: Request, url: str, method: str = "GET"):
    """
    Enhanced proxy GET requests with intelligent streaming
    """
    # Validate method parameter
    if method.upper() not in ["GET", "HEAD", "OPTIONS"]:
        raise HTTPException(status_code=400, detail="Invalid method for GET endpoint")

    await security.validate_request(request, url)
    sanitized_url = proxy_utils.sanitize_url(url)

    # Fetch the target URL
    response = await proxy_utils.fetch_url(sanitized_url, method.upper())

    # Validate content type
    content_type = response.headers.get("content-type", "")
    if not security.validate_content_type(content_type):
        raise HTTPException(
            status_code=415, detail=f"Content type {content_type} is not allowed"
        )

    # Check if we should stream the response
    if proxy_utils.should_stream_response(response):
        logger.info(f"Streaming response for: {url}")
        return await proxy_utils.create_streaming_response(
            sanitized_url, method.upper()
        )

    # Return buffered response for smaller files
    logger.info(f"Buffering response for: {url}")
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=security.sanitize_headers(dict(response.headers)),
        media_type=content_type,
    )


@app.api_route("/proxy", methods=["POST", "PUT", "DELETE", "PATCH"])
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def proxy_with_body(request: Request, proxy_request: ProxyRequest):
    """
    Enhanced proxy requests with request body and intelligent streaming
    """
    # Validate request body size
    if proxy_request.body and len(proxy_request.body) > settings.MAX_CONTENT_LENGTH:
        raise HTTPException(
            status_code=413,
            detail=f"Request body too large. Maximum size: {settings.MAX_CONTENT_LENGTH} bytes",
        )

    await security.validate_request(request, proxy_request.url)
    sanitized_url = proxy_utils.sanitize_url(proxy_request.url)

    # Prepare headers (sanitize for security)
    headers = security.sanitize_headers(
        proxy_request.headers if proxy_request.headers else {}
    )

    # Prepare body
    body = proxy_request.body.encode() if proxy_request.body else None

    # Fetch the target URL
    response = await proxy_utils.fetch_url(
        sanitized_url, proxy_request.method.value, headers, body
    )

    # Validate content type
    content_type = response.headers.get("content-type", "")
    if not security.validate_content_type(content_type):
        raise HTTPException(
            status_code=415, detail=f"Content type {content_type} is not allowed"
        )

    # Check if we should stream the response
    if proxy_utils.should_stream_response(response):
        logger.info(f"Streaming response for: {proxy_request.url}")
        return await proxy_utils.create_streaming_response(
            sanitized_url, proxy_request.method.value, headers, body
        )

    # Return buffered response for smaller files
    logger.info(f"Buffering response for: {proxy_request.url}")
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=security.sanitize_headers(dict(response.headers)),
        media_type=content_type,
    )


@app.options("/proxy")
async def proxy_options():
    """Handle OPTIONS requests for CORS"""
    return JSONResponse(content={"message": "OK"})


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
        headers=security.add_security_headers(Response()).headers,
    )


# Only for development
if __name__ == "__main__":
    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    config = Config()
    config.bind = [f"{settings.HOST}:{settings.PORT}"]
    config.use_reloader = settings.DEBUG
    config.workers = 4

    asyncio.run(serve(app, config))  # type: ignore

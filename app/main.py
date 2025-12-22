import asyncio
import logging
import threading
import time
import warnings
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.load_balancer import initialize_load_balancer, load_balancer
from app.middleware import (
    AuthenticationConfig,
    BufferingConfig,
    CircuitBreakerConfig,
    CompressionConfig,
    IPFilterConfig,
    RateLimitConfig,
    get_middleware_pipeline,
    initialize_default_middleware,
)
from app.model import HealthResponse, ProxyRequest
from app.rate_limiter import get_rate_limiter, rate_limit_exceeded_handler
from app.security import security
from app.utils import proxy_utils

# Import websockets with error handling
try:
    import websockets
    from fastapi import WebSocket, WebSocketDisconnect

    WEBSOCKETS_AVAILABLE = True
except ImportError:
    websockets = None
    WebSocketDisconnect = None
    WEBSOCKETS_AVAILABLE = False

# Suppress slowapi deprecation warnings
warnings.filterwarnings(
    "ignore",
    message="'asyncio.iscoroutinefunction' is deprecated",
    category=DeprecationWarning,
    module="slowapi.extension",
)

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

    # Initialize load balancer if enabled
    if settings.LOAD_BALANCER_ENABLED and settings.BACKEND_SERVERS:
        lb_config = settings.get_load_balancer_config()
        initialize_load_balancer(lb_config)

        # Add backend servers
        if load_balancer:
            for server in settings.BACKEND_SERVERS:
                load_balancer.add_server(server)

            # Start health checks
            await load_balancer.start_health_checks()
            logger.info(
                f"Load balancer initialized with {len(settings.BACKEND_SERVERS)} servers"
            )

    # Initialize middleware pipeline
    pipeline = get_middleware_pipeline()
    initialize_default_middleware()

    # Add middleware based on configuration
    if settings.MIDDLEWARE_RATE_LIMIT_ENABLED:
        from app.middleware import RateLimitMiddleware

        pipeline.add_middleware(
            RateLimitMiddleware(
                RateLimitConfig(
                    enabled=settings.MIDDLEWARE_RATE_LIMIT_ENABLED,
                    requests_per_minute=settings.MIDDLEWARE_RATE_LIMIT_REQUESTS_PER_MINUTE,
                    requests_per_hour=settings.MIDDLEWARE_RATE_LIMIT_REQUESTS_PER_HOUR,
                    burst_size=settings.MIDDLEWARE_RATE_LIMIT_BURST_SIZE,
                    block_duration=settings.MIDDLEWARE_RATE_LIMIT_BLOCK_DURATION,
                )
            )
        )

    if settings.MIDDLEWARE_CIRCUIT_BREAKER_ENABLED:
        from app.middleware import CircuitBreakerMiddleware

        pipeline.add_middleware(
            CircuitBreakerMiddleware(
                CircuitBreakerConfig(
                    enabled=settings.MIDDLEWARE_CIRCUIT_BREAKER_ENABLED,
                    failure_threshold=settings.MIDDLEWARE_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
                    recovery_timeout=settings.MIDDLEWARE_CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
                    half_open_max_requests=settings.MIDDLEWARE_CIRCUIT_BREAKER_HALF_OPEN_MAX_REQUESTS,
                    timeout=settings.MIDDLEWARE_CIRCUIT_BREAKER_TIMEOUT,
                )
            )
        )

    if settings.MIDDLEWARE_COMPRESSION_ENABLED:
        from app.middleware import CompressionMiddleware

        pipeline.add_middleware(
            CompressionMiddleware(
                CompressionConfig(
                    enabled=settings.MIDDLEWARE_COMPRESSION_ENABLED,
                    min_size=settings.MIDDLEWARE_COMPRESSION_MIN_SIZE,
                    compression_level=settings.MIDDLEWARE_COMPRESSION_COMPRESSION_LEVEL,
                    supported_encodings=settings.MIDDLEWARE_COMPRESSION_SUPPORTED_ENCODINGS,
                )
            )
        )

    if settings.MIDDLEWARE_BUFFERING_ENABLED:
        from app.middleware import BufferingMiddleware

        pipeline.add_middleware(
            BufferingMiddleware(
                BufferingConfig(
                    enabled=settings.MIDDLEWARE_BUFFERING_ENABLED,
                    max_buffer_size=settings.MIDDLEWARE_BUFFERING_MAX_BUFFER_SIZE,
                    buffer_timeout=settings.MIDDLEWARE_BUFFERING_BUFFER_TIMEOUT,
                    enable_streaming=settings.MIDDLEWARE_BUFFERING_ENABLE_STREAMING,
                )
            )
        )

    if settings.MIDDLEWARE_IP_FILTER_ENABLED:
        from app.middleware import IPFilterMiddleware

        pipeline.add_middleware(
            IPFilterMiddleware(
                IPFilterConfig(
                    enabled=settings.MIDDLEWARE_IP_FILTER_ENABLED,
                    whitelist=settings.MIDDLEWARE_IP_FILTER_WHITELIST,
                    blacklist=settings.MIDDLEWARE_IP_FILTER_BLACKLIST,
                    block_private_ips=settings.MIDDLEWARE_IP_FILTER_BLOCK_PRIVATE_IPS,
                    block_loopback=settings.MIDDLEWARE_IP_FILTER_BLOCK_LOOPBACK,
                )
            )
        )

    if settings.MIDDLEWARE_AUTHENTICATION_ENABLED:
        from app.middleware import AuthenticationMiddleware

        pipeline.add_middleware(
            AuthenticationMiddleware(
                AuthenticationConfig(
                    enabled=settings.MIDDLEWARE_AUTHENTICATION_ENABLED,
                    basic_auth=settings.MIDDLEWARE_AUTHENTICATION_BASIC_AUTH,
                    jwt_secret=settings.MIDDLEWARE_AUTHENTICATION_JWT_SECRET,
                    jwt_algorithm=settings.MIDDLEWARE_AUTHENTICATION_JWT_ALGORITHM,
                    required_scopes=settings.MIDDLEWARE_AUTHENTICATION_REQUIRED_SCOPES,
                )
            )
        )

    # Initialize rate limiter
    from app.rate_limiter import initialize_redis

    await initialize_redis()

    yield

    # Shutdown
    await proxy_utils.close_client()

    # Stop load balancer health checks
    if load_balancer:
        await load_balancer.stop_health_checks()


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
    health_data = {
        "status": "healthy",
        "timestamp": time.time(),
        "version": settings.VERSION,
        "load_balancer": None,
        "middleware": None,
        "metrics": metrics.get_stats(),
    }

    # Add load balancer status if enabled
    if load_balancer:
        health_data["load_balancer"] = {
            "enabled": True,
            "algorithm": load_balancer.config.algorithm.value,
            "total_servers": len(load_balancer.servers),
            "healthy_servers": len([s for s in load_balancer.servers if s.is_healthy]),
            "unhealthy_servers": len(
                [s for s in load_balancer.servers if not s.is_healthy]
            ),
        }

    # Add middleware status
    pipeline = get_middleware_pipeline()
    health_data["middleware"] = {
        "enabled": settings.MIDDLEWARE_ENABLED,
        "middleware_count": len(pipeline.middlewares),
    }

    return health_data


@app.get("/metrics")
async def get_metrics():
    """Enhanced metrics endpoint"""
    return metrics.get_stats()


@app.get("/stats")
async def get_haproxy_stats():
    """HAProxy-style stats endpoint"""
    stats = {
        "frontend": {
            "name": "frontend",
            "status": "OPEN",
            "requests": metrics.get_stats()["total_requests"],
            "bytes_in": 0,  # Would need to track this
            "bytes_out": 0,  # Would need to track this
            "session_rate": 0,  # Would need to calculate
        },
        "backend": [],
    }

    if load_balancer:
        for server in load_balancer.servers:
            server_stats = {
                "name": server.server_id,
                "status": server.state.value,
                "current_connections": server.current_connections,
                "max_connections": server.max_connections,
                "response_time": server.response_time,
                "consecutive_failures": server.consecutive_failures,
                "consecutive_successes": server.consecutive_successes,
                "weight": server.weight,
                "is_healthy": server.is_healthy,
            }
            stats["backend"].append(server_stats)

    return stats


@app.get("/proxy")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def proxy_get(request: Request, url: str, method: str = "GET"):
    """
    Enhanced proxy GET requests with intelligent streaming and load balancing
    """
    # Validate method parameter
    if method.upper() not in ["GET", "HEAD", "OPTIONS"]:
        raise HTTPException(status_code=400, detail="Invalid method for GET endpoint")

    await security.validate_request(request, url)
    sanitized_url = proxy_utils.sanitize_url(url)

    # Use load balancer if enabled
    if load_balancer and settings.LOAD_BALANCER_ENABLED:
        # Select server from load balancer
        request_info = {
            "client_ip": request.client.host if request.client else "unknown",
            "uri": sanitized_url,
            "headers": dict(request.headers),
        }

        server = await load_balancer.select_server(request_info)
        if not server:
            raise HTTPException(
                status_code=503, detail="No healthy backend servers available"
            )

        # Update URL to use selected server
        target_url = f"{server.protocol}://{server.host}:{server.port}{sanitized_url}"

        try:
            # Fetch the target URL
            response = await proxy_utils.fetch_url(target_url, method.upper())

            # Record success/failure
            if response.status_code < 500:
                load_balancer.record_success(server.server_id)
            else:
                load_balancer.record_failure(server.server_id)

            # Validate content type
            content_type = response.headers.get("content-type", "")
            if not security.validate_content_type(content_type):
                raise HTTPException(
                    status_code=415,
                    detail=f"Content type {content_type} is not allowed",
                )

            # Check if we should stream the response
            if proxy_utils.should_stream_response(response):
                logger.info(f"Streaming response for: {target_url}")
                return await proxy_utils.create_streaming_response(
                    target_url, method.upper()
                )

            # Return buffered response for smaller files
            logger.info(f"Buffering response for: {target_url}")
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=security.sanitize_headers(dict(response.headers)),
                media_type=content_type,
            )

        except Exception:
            load_balancer.record_failure(server.server_id)
            raise

    else:
        # Use regular proxy logic
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

    # Use load balancer if enabled
    if load_balancer and settings.LOAD_BALANCER_ENABLED:
        # Select server from load balancer
        request_info = {
            "client_ip": request.client.host if request.client else "unknown",
            "uri": sanitized_url,
            "headers": dict(request.headers),
        }

        server = await load_balancer.select_server(request_info)
        if not server:
            raise HTTPException(
                status_code=503, detail="No healthy backend servers available"
            )

        # Update URL to use selected server
        target_url = f"{server.protocol}://{server.host}:{server.port}{sanitized_url}"

        # Prepare headers (sanitize for security)
        headers = security.sanitize_headers(
            proxy_request.headers if proxy_request.headers else {}
        )

        # Prepare body
        body = proxy_request.body.encode() if proxy_request.body else None

        try:
            # Fetch the target URL
            response = await proxy_utils.fetch_url(
                target_url, proxy_request.method.value, headers, body
            )

            # Record success/failure
            if response.status_code < 500:
                load_balancer.record_success(server.server_id)
            else:
                load_balancer.record_failure(server.server_id)

            # Validate content type
            content_type = response.headers.get("content-type", "")
            if not security.validate_content_type(content_type):
                raise HTTPException(
                    status_code=415,
                    detail=f"Content type {content_type} is not allowed",
                )

            # Check if we should stream the response
            if proxy_utils.should_stream_response(response):
                logger.info(f"Streaming response for: {target_url}")
                return await proxy_utils.create_streaming_response(
                    target_url, proxy_request.method.value, headers, body
                )

            # Return buffered response for smaller files
            logger.info(f"Buffering response for: {target_url}")
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=security.sanitize_headers(dict(response.headers)),
                media_type=content_type,
            )

        except Exception:
            load_balancer.record_failure(server.server_id)
            raise

    else:
        # Use regular proxy logic
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


@app.websocket("/websocket")
async def websocket_proxy(websocket: WebSocket):
    """WebSocket proxy endpoint"""
    if not WEBSOCKETS_AVAILABLE:
        await websocket.close(code=1000, reason="WebSocket support not available")
        return

    await websocket.accept()

    try:
        while True:
            # Receive message from client
            data = await websocket.receive_text()

            # Here you would implement WebSocket proxying logic
            # For now, just echo back with a prefix
            await websocket.send_text(f"Proxied: {data}")

    except Exception as e:
        if WebSocketDisconnect and isinstance(e, WebSocketDisconnect):
            logger.info("WebSocket disconnected")
        else:
            logger.error(f"WebSocket error: {e}")
            await websocket.close(code=1011, reason=str(e))


@app.get("/logs")
async def get_logs(request: Request):
    """Logs endpoint for accessing server logs"""
    # Read the log file
    try:
        with open("proxy.log", "r", encoding="utf-8") as f:
            logs = f.read()

        # Return logs as plain text
        response = Response(
            content=logs,
            media_type="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=proxy.log",
                "X-Content-Type-Options": "nosniff",
            },
        )
        return security.add_security_headers(response)

    except FileNotFoundError:
        return JSONResponse(
            status_code=404,
            content={"error": "Log file not found"},
        )
    except Exception as exc:
        logger.error(f"Error reading logs: {exc}")
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to read logs"},
        )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler"""
    response = JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )
    return security.add_security_headers(response)


# Only for development
if __name__ == "__main__":
    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    config = Config()
    config.bind = [f"{settings.HOST}:{settings.PORT}"]
    config.use_reloader = settings.DEBUG
    config.workers = 4

    asyncio.run(serve(app, config))  # type: ignore
    asyncio.run(serve(app, config))  # type: ignore

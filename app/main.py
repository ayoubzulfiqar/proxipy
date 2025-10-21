import logging
import time
from collections import defaultdict
from contextlib import asynccontextmanager

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

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Metrics storage
request_metrics = defaultdict(int)
error_metrics = defaultdict(int)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Application lifespan events"""
    # Startup
    print(f"Starting {settings.APP_NAME} v{settings.VERSION}")
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
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return security.add_security_headers(response)


@app.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint with health information"""
    return HealthResponse(
        status="healthy",
        version=settings.VERSION,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
    )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": time.time()}


@app.get("/metrics")
async def metrics():
    """Metrics endpoint"""
    return {
        "total_requests": sum(request_metrics.values()),
        "requests_by_method": dict(request_metrics),
        "total_errors": sum(error_metrics.values()),
        "errors_by_type": dict(error_metrics),
        "uptime": time.time() - getattr(app.state, "start_time", time.time()),
    }


@app.get("/proxy")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def proxy_get(request: Request, url: str, method: str = "GET"):
    """
    Proxy GET requests with URL as query parameter
    """
    # Validate method parameter
    if method.upper() not in ["GET", "HEAD", "OPTIONS"]:
        raise HTTPException(status_code=400, detail="Invalid method for GET endpoint")

    await security.validate_request(request, url)
    sanitized_url = proxy_utils.sanitize_url(url)

    # Fetch the target URL
    response = await proxy_utils.fetch_url(sanitized_url, method.upper())

    # Validate content type
    content_type = response.headers.get("content-type", "").split(";")[0]
    if not security.validate_content_type(content_type):
        raise HTTPException(
            status_code=415, detail=f"Content type {content_type} is not allowed"
        )

    # Return response
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers),
        media_type=content_type,
    )


@app.api_route("/proxy", methods=["POST", "PUT", "DELETE", "PATCH"])
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def proxy_with_body(request: Request, proxy_request: ProxyRequest):
    """
    Proxy requests with request body and custom headers
    """
    # Validate request body size
    if proxy_request.body and len(proxy_request.body) > settings.MAX_CONTENT_LENGTH:
        raise HTTPException(
            status_code=413,
            detail=f"Request body too large. Maximum size: {settings.MAX_CONTENT_LENGTH} bytes",
        )

    await security.validate_request(request, proxy_request.url)
    sanitized_url = proxy_utils.sanitize_url(proxy_request.url)

    # Prepare headers (remove potentially dangerous headers)
    headers = {}
    if proxy_request.headers:
        for key, value in proxy_request.headers.items():
            if key.lower() not in ["host", "content-length"]:
                headers[key] = value

    # Prepare body
    body = proxy_request.body.encode() if proxy_request.body else None

    # Fetch the target URL
    response = await proxy_utils.fetch_url(
        sanitized_url, proxy_request.method.value, headers, body
    )

    # Validate content type
    content_type = response.headers.get("content-type", "").split(";")[0]
    if not security.validate_content_type(content_type):
        raise HTTPException(
            status_code=415, detail=f"Content type {content_type} is not allowed"
        )

    # Return response
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers),
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
    import asyncio

    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    config = Config()
    config.bind = [f"{settings.HOST}:{settings.PORT}"]
    config.use_reloader = settings.DEBUG
    config.workers = 4

    asyncio.run(serve(app, config))  # type: ignore

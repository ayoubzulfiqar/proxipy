import logging
import time

import redis
from fastapi import Request
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .config import settings

logger = logging.getLogger(__name__)

# Initialize Redis client with enhanced error handling
redis_available = False
redis_client = None


async def initialize_redis():
    """Initialize Redis client asynchronously"""
    global redis_available, redis_client

    if not settings.RATE_LIMIT_ENABLED:
        logger.info("Rate limiting disabled by configuration")
        return

    try:
        redis_client = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_timeout=5.0,
            socket_connect_timeout=5.0,
            retry_on_timeout=True,
            max_connections=20,
        )
        redis_client.ping()  # Test connection
        redis_available = True
        logger.info("Redis connection established for rate limiting")
    except redis.ConnectionError as e:
        redis_client = None
        logger.warning(f"Redis not available, falling back to memory storage: {e}")
    except Exception as e:
        redis_client = None
        logger.error(f"Unexpected error connecting to Redis: {e}")


# Redis initialization is now handled in main.py lifespan

# Enhanced rate limiter with multiple strategies
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.REDIS_URL if redis_available else "memory://",
    enabled=settings.RATE_LIMIT_ENABLED,
    strategy="fixed-window",  # More predictable than sliding window
)


def get_rate_limiter():
    """Get the configured rate limiter"""
    return limiter


def get_client_ip(request: Request) -> str:
    """Enhanced client IP detection"""
    # Check X-Forwarded-For header first (most common with proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP header (used by nginx)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Check X-Client-IP header (used by Apache)
    client_ip = request.headers.get("X-Client-IP")
    if client_ip:
        return client_ip.strip()

    # Fall back to direct connection
    return request.client.host if request.client else "unknown"


async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """Enhanced rate limit exceeded handler with detailed information"""
    client_ip = get_client_ip(request)

    # Parse the detail string to extract limit information
    detail_str = str(exc.detail)
    logger.warning(
        f"Rate limit exceeded for IP: {client_ip}, "
        f"Path: {request.url.path}, "
        f"Detail: {detail_str}"
    )

    # Extract retry_after from headers if available
    retry_after = request.headers.get("Retry-After", "60")

    return {
        "error": "Rate limit exceeded",
        "detail": detail_str,
        "retry_after": retry_after,
        "client_ip": client_ip,
        "timestamp": time.time(),
        "path": request.url.path,
        "method": request.method,
    }


def create_rate_limits():
    """Create rate limit configurations"""
    return {
        # Per-minute limits
        "per_minute": f"{settings.RATE_LIMIT_PER_MINUTE}/minute",
        # Per-hour limits
        "per_hour": f"{settings.RATE_LIMIT_PER_HOUR}/hour",
        # Burst limits (more restrictive for sensitive operations)
        "burst": f"{settings.RATE_LIMIT_BURST}/minute",
        # Different limits for different endpoints
        "health": "100/minute",  # Health checks can be more frequent
        "metrics": "30/minute",  # Metrics less frequent
        "proxy": f"{settings.RATE_LIMIT_PER_MINUTE}/minute",  # Main proxy endpoint
    }


# Rate limit configurations
RATE_LIMITS = create_rate_limits()


def get_rate_limit(limit_type: str = "per_minute") -> str:
    """Get rate limit configuration by type"""
    return RATE_LIMITS.get(limit_type, RATE_LIMITS["per_minute"])


async def check_redis_health() -> dict:
    """Check Redis health and return status"""
    if not redis_available or not redis_client:
        return {
            "available": False,
            "type": "memory",
            "error": "Redis not configured or unavailable",
        }

    try:
        start_time = time.time()
        redis_client.ping()
        response_time = time.time() - start_time

        # Get some basic stats
        info = await redis_client.info()

        return {
            "available": True,
            "type": "redis",
            "response_time": response_time,
            "connections": info.get("connected_clients", 0),
            "memory_used": info.get("used_memory_human", "unknown"),
        }
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return {"available": False, "type": "redis", "error": str(e)}

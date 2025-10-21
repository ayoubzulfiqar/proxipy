import redis
from fastapi import Request
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .config import settings

# Initialize Redis client
redis_available = False
if settings.RATE_LIMIT_ENABLED:
    try:
        redis_client = redis.from_url(settings.REDIS_URL)
        redis_client.ping()  # Test connection
        redis_available = True
    except redis.ConnectionError:
        redis_client = None
        print("Redis not available, falling back to memory storage")
else:
    redis_client = None

# Rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.REDIS_URL if redis_available else "memory://",
    enabled=settings.RATE_LIMIT_ENABLED,
)


def get_rate_limiter():
    return limiter


async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """Custom rate limit exceeded handler"""
    return {
        "error": "Rate limit exceeded",
        "detail": f"Maximum {exc.detail.limit} requests per {exc.detail.period}",  # type: ignore
        "retry_after": exc.detail.retry_after,  # type: ignore
    }

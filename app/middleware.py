import asyncio
import gzip
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from fastapi import HTTPException, Request, Response
from starlette.responses import StreamingResponse

if TYPE_CHECKING:
    from .config import Settings


# Lazy import to avoid circular imports
def get_settings() -> "Settings":
    from .config import settings

    return settings


logger = logging.getLogger(__name__)


class MiddlewarePriority(int, Enum):
    """Middleware execution priorities"""

    AUTHENTICATION = 10
    RATE_LIMITING = 20
    CIRCUIT_BREAKER = 30
    ROUTING = 40
    LOAD_BALANCER = 50
    HEADER_MANIPULATION = 60
    COMPRESSION = 70
    BUFFERING = 80
    LOGGING = 90


@dataclass
class MiddlewareConfig:
    """Base middleware configuration"""

    enabled: bool = True
    priority: MiddlewarePriority = MiddlewarePriority.LOGGING
    name: str = "middleware"


@dataclass
class RateLimitConfig(MiddlewareConfig):
    """Rate limiting configuration"""

    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_size: int = 10
    block_duration: float = 300.0  # 5 minutes
    key_func: Optional[Callable] = None


@dataclass
class CircuitBreakerConfig(MiddlewareConfig):
    """Circuit breaker configuration"""

    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_max_requests: int = 3
    timeout: float = 30.0


@dataclass
class CompressionConfig(MiddlewareConfig):
    """Compression configuration"""

    min_size: int = 1024
    compression_level: int = 6
    supported_encodings: List[str] = field(default_factory=lambda: ["gzip", "deflate"])


@dataclass
class BufferingConfig(MiddlewareConfig):
    """Buffering configuration"""

    max_buffer_size: int = 1024 * 1024  # 1MB
    buffer_timeout: float = 5.0
    enable_streaming: bool = True


@dataclass
class HeaderManipulationConfig(MiddlewareConfig):
    """Header manipulation configuration"""

    add_headers: Dict[str, str] = field(default_factory=dict)
    remove_headers: List[str] = field(default_factory=list)
    modify_headers: Dict[str, str] = field(default_factory=dict)
    strip_prefix: str = ""
    redirect_prefix: str = ""


@dataclass
class IPFilterConfig(MiddlewareConfig):
    """IP filtering configuration"""

    whitelist: List[str] = field(default_factory=list)
    blacklist: List[str] = field(default_factory=list)
    block_private_ips: bool = True
    block_loopback: bool = True


@dataclass
class AuthenticationConfig(MiddlewareConfig):
    """Authentication configuration"""

    basic_auth: Dict[str, str] = field(default_factory=dict)  # username: password
    jwt_secret: Optional[str] = None
    jwt_algorithm: str = "HS256"
    required_scopes: List[str] = field(default_factory=list)


class MiddlewareContext:
    """Context object for middleware communication"""

    def __init__(self):
        self.request: Optional[Request] = None
        self.response: Optional[Response] = None
        self.request_data: Dict[str, Any] = {}
        self.response_data: Dict[str, Any] = {}
        self.server: Optional[str] = None
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.error: Optional[Exception] = None
        self.skip_remaining: bool = False


class BaseMiddleware(ABC):
    """Abstract base class for middleware"""

    def __init__(self, config: MiddlewareConfig):
        self.config = config
        self.name = config.name or self.__class__.__name__

    @abstractmethod
    async def process_request(self, context: MiddlewareContext) -> None:
        """Process incoming request"""
        pass

    @abstractmethod
    async def process_response(self, context: MiddlewareContext) -> None:
        """Process outgoing response"""
        pass

    def should_execute(self, context: MiddlewareContext) -> bool:
        """Check if middleware should execute"""
        return self.config.enabled


class AuthenticationMiddleware(BaseMiddleware):
    """Authentication middleware"""

    def __init__(self, config: AuthenticationConfig):
        super().__init__(config)
        self.config = config

    async def process_request(self, context: MiddlewareContext) -> None:
        if not self.should_execute(context):
            return

        request = context.request
        if not request:
            return

        # Check for basic authentication
        if self.config.basic_auth:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Basic "):
                raise HTTPException(status_code=401, detail="Authentication required")

            import base64

            try:
                encoded_credentials = auth_header[6:]  # Remove "Basic "
                decoded_credentials = base64.b64decode(encoded_credentials).decode()
                username, password = decoded_credentials.split(":", 1)

                if (
                    username not in self.config.basic_auth
                    or self.config.basic_auth[username] != password
                ):
                    raise HTTPException(status_code=401, detail="Invalid credentials")

                context.request_data["authenticated_user"] = username
                logger.info(f"User {username} authenticated successfully")

            except Exception as e:
                logger.warning(f"Authentication failed: {e}")
                raise HTTPException(status_code=401, detail="Authentication failed")

    async def process_response(self, context: MiddlewareContext) -> None:
        pass


class RateLimitMiddleware(BaseMiddleware):
    """Rate limiting middleware with Redis support"""

    def __init__(self, config: RateLimitConfig):
        super().__init__(config)
        self.config = config
        self.requests: Dict[str, List[float]] = {}
        self.blocked_ips: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    def get_client_key(self, context: MiddlewareContext) -> str:
        """Get client identification key"""
        if self.config.key_func:
            return self.config.key_func(context.request)

        request = context.request
        if not request:
            return "unknown"

        # Try different headers for client IP
        for header in ["X-Forwarded-For", "X-Real-IP", "X-Client-IP"]:
            ip = request.headers.get(header)
            if ip:
                return ip.split(",")[0].strip()

        return request.client.host if request.client else "unknown"

    async def process_request(self, context: MiddlewareContext) -> None:
        if not self.should_execute(context):
            return

        client_key = self.get_client_key(context)

        async with self._lock:
            current_time = time.time()

            # Check if IP is blocked
            if client_key in self.blocked_ips:
                if (
                    current_time - self.blocked_ips[client_key]
                    < self.config.block_duration
                ):
                    raise HTTPException(status_code=429, detail="Too many requests")
                else:
                    del self.blocked_ips[client_key]

            # Clean old requests
            cutoff_time = current_time - 3600  # 1 hour
            if client_key in self.requests:
                self.requests[client_key] = [
                    req_time
                    for req_time in self.requests[client_key]
                    if req_time > cutoff_time
                ]
            else:
                self.requests[client_key] = []

            # Check rate limits
            minute_requests = [
                req_time
                for req_time in self.requests[client_key]
                if req_time > current_time - 60
            ]

            if len(minute_requests) >= self.config.requests_per_minute:
                self.blocked_ips[client_key] = current_time
                raise HTTPException(status_code=429, detail="Rate limit exceeded")

            # Add current request
            self.requests[client_key].append(current_time)

    async def process_response(self, context: MiddlewareContext) -> None:
        pass


class CircuitBreakerMiddleware(BaseMiddleware):
    """Circuit breaker middleware"""

    def __init__(self, config: CircuitBreakerConfig):
        super().__init__(config)
        self.config = config
        self.states: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    def get_circuit_key(self, context: MiddlewareContext) -> str:
        """Get circuit breaker key"""
        server = context.server or "default"
        return f"circuit_{server}"

    async def process_request(self, context: MiddlewareContext) -> None:
        if not self.should_execute(context):
            return

        circuit_key = self.get_circuit_key(context)

        async with self._lock:
            if circuit_key not in self.states:
                self.states[circuit_key] = {
                    "state": "closed",  # closed, open, half_open
                    "failure_count": 0,
                    "success_count": 0,
                    "last_failure_time": 0,
                    "half_open_requests": 0,
                }

            state = self.states[circuit_key]
            current_time = time.time()

            # Check if we should transition from open to half_open
            if state["state"] == "open":
                if (
                    current_time - state["last_failure_time"]
                    > self.config.recovery_timeout
                ):
                    state["state"] = "half_open"
                    state["half_open_requests"] = 0
                    logger.info(
                        f"Circuit breaker {circuit_key} transitioning to half-open"
                    )
                else:
                    raise HTTPException(status_code=503, detail="Service unavailable")

            # Check half-open state
            if state["state"] == "half_open":
                if state["half_open_requests"] >= self.config.half_open_max_requests:
                    raise HTTPException(status_code=503, detail="Service unavailable")
                state["half_open_requests"] += 1

    async def process_response(self, context: MiddlewareContext) -> None:
        if not self.should_execute(context):
            return

        circuit_key = self.get_circuit_key(context)

        async with self._lock:
            if circuit_key not in self.states:
                return

            state = self.states[circuit_key]

            if context.error:
                # Record failure
                state["failure_count"] += 1
                state["success_count"] = 0
                state["last_failure_time"] = time.time()

                if state["failure_count"] >= self.config.failure_threshold:
                    state["state"] = "open"
                    logger.warning(
                        f"Circuit breaker {circuit_key} opened due to failures"
                    )
            else:
                # Record success
                state["success_count"] += 1
                state["failure_count"] = 0

                if state["state"] == "half_open" and state["success_count"] >= 3:
                    state["state"] = "closed"
                    logger.info(
                        f"Circuit breaker {circuit_key} closed after successful requests"
                    )


class CompressionMiddleware(BaseMiddleware):
    """Response compression middleware"""

    def __init__(self, config: CompressionConfig):
        super().__init__(config)
        self.config = config

    async def process_request(self, context: MiddlewareContext) -> None:
        pass

    async def process_response(self, context: MiddlewareContext) -> None:
        if not self.should_execute(context) or not context.response:
            return

        response = context.response

        # Check if response is already compressed
        if response and response.headers.get("Content-Encoding"):
            return

        # Check content length
        if response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) < self.config.min_size:
                return

        # Check if client supports compression
        if context.request and context.request.headers:
            accept_encoding = context.request.headers.get("Accept-Encoding", "").lower()
            if not any(
                encoding in accept_encoding
                for encoding in self.config.supported_encodings
            ):
                return

        # Check content type for compression eligibility
        content_type = response.headers.get("content-type", "")
        if not content_type:
            return

        # Only compress text-based content types
        text_content_types = [
            "text/",
            "application/json",
            "application/xml",
            "application/javascript",
            "application/css",
            "application/x-javascript",
        ]

        if not any(ct in content_type for ct in text_content_types):
            return

        # Compress response
        if hasattr(response, "body"):
            content = response.body
            if isinstance(content, str):
                content = content.encode()

            compressed_content = gzip.compress(
                content, compresslevel=self.config.compression_level
            )

            if len(compressed_content) < len(content):
                response.body = compressed_content
                response.headers["Content-Encoding"] = "gzip"
                response.headers["Content-Length"] = str(len(compressed_content))
                response.headers["Vary"] = "Accept-Encoding"


class BufferingMiddleware(BaseMiddleware):
    """Response buffering middleware"""

    def __init__(self, config: BufferingConfig):
        super().__init__(config)
        self.config = config

    async def process_request(self, context: MiddlewareContext) -> None:
        pass

    async def process_response(self, context: MiddlewareContext) -> None:
        if not self.should_execute(context) or not context.response:
            return

        response = context.response

        # Only buffer small responses
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > self.config.max_buffer_size:
            return

        # Buffer streaming responses
        if isinstance(response, StreamingResponse):
            content = b""
            try:
                async for chunk in response.body_iterator:
                    if isinstance(chunk, str):
                        chunk = chunk.encode()
                    content += chunk
                    if len(content) > self.config.max_buffer_size:
                        # Too large, keep streaming
                        return
            except Exception:
                # If buffering fails, keep streaming
                return

            # Create buffered response
            from fastapi.responses import Response

            context.response = Response(
                content=content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )


class HeaderManipulationMiddleware(BaseMiddleware):
    """Header manipulation middleware"""

    def __init__(self, config: HeaderManipulationConfig):
        super().__init__(config)
        self.config = config

    async def process_request(self, context: MiddlewareContext) -> None:
        if not self.should_execute(context) or not context.request:
            return

        # Modify request headers
        if context.request and context.request.headers:
            headers = dict(context.request.headers)
        else:
            headers = {}

        # Remove headers
        for header in self.config.remove_headers:
            headers.pop(header.lower(), None)

        # Add headers
        headers.update(self.config.add_headers)

        # Modify headers
        for old_header, new_value in self.config.modify_headers.items():
            headers[old_header.lower()] = new_value

        context.request_data["modified_headers"] = headers

    async def process_response(self, context: MiddlewareContext) -> None:
        if not self.should_execute(context) or not context.response:
            return

        response = context.response

        # Remove headers
        for header in self.config.remove_headers:
            if header in response.headers:
                del response.headers[header]

        # Add headers
        for header, value in self.config.add_headers.items():
            response.headers[header] = value

        # Modify headers
        for old_header, new_value in self.config.modify_headers.items():
            if old_header in response.headers:
                response.headers[old_header] = new_value


class IPFilterMiddleware(BaseMiddleware):
    """IP filtering middleware"""

    def __init__(self, config: IPFilterConfig):
        super().__init__(config)
        self.config = config

    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            import ipaddress

            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except (ValueError, TypeError):
            return False

    def is_loopback_ip(self, ip: str) -> bool:
        """Check if IP is loopback"""
        try:
            import ipaddress

            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_loopback
        except (ValueError, TypeError):
            return False

    async def process_request(self, context: MiddlewareContext) -> None:
        if not self.should_execute(context) or not context.request:
            return

        client_ip = context.request.client.host if context.request.client else "unknown"

        # Check whitelist
        if self.config.whitelist and client_ip not in self.config.whitelist:
            raise HTTPException(status_code=403, detail="Access denied")

        # Check blacklist
        if client_ip in self.config.blacklist:
            raise HTTPException(status_code=403, detail="Access denied")

        # Check private IPs
        if self.config.block_private_ips and self.is_private_ip(client_ip):
            raise HTTPException(status_code=403, detail="Access to private IPs denied")

        # Check loopback
        if self.config.block_loopback and self.is_loopback_ip(client_ip):
            raise HTTPException(status_code=403, detail="Access to loopback denied")

    async def process_response(self, context: MiddlewareContext) -> None:
        pass


class LoggingMiddleware(BaseMiddleware):
    """Request/response logging middleware"""

    async def process_request(self, context: MiddlewareContext) -> None:
        context.start_time = time.time()

    async def process_response(self, context: MiddlewareContext) -> None:
        if not self.should_execute(context):
            return

        duration = time.time() - context.start_time
        request = context.request
        response = context.response

        log_data = {
            "timestamp": time.time(),
            "method": request.method if request else "UNKNOWN",
            "path": request.url.path if request else "UNKNOWN",
            "status_code": response.status_code if response else 500,
            "duration": duration,
            "client_ip": request.client.host
            if request and request.client
            else "unknown",
            "user_agent": request.headers.get("User-Agent", "unknown")
            if request
            else "unknown",
            "error": str(context.error) if context.error else None,
        }

        if get_settings().STRUCTURED_LOGGING:
            logger.info(f"Request completed: {log_data}")
        else:
            logger.info(
                f"{log_data['method']} {log_data['path']} - "
                f"{log_data['status_code']} - {duration:.3f}s - {log_data['client_ip']}"
            )


class MiddlewarePipeline:
    """Middleware pipeline manager"""

    def __init__(self):
        self.middlewares: List[Tuple[BaseMiddleware, MiddlewarePriority]] = []

    def add_middleware(self, middleware: BaseMiddleware):
        """Add middleware to pipeline"""
        self.middlewares.append((middleware, middleware.config.priority))
        # Sort by priority
        self.middlewares.sort(key=lambda x: x[1])

    async def process_request(self, context: MiddlewareContext) -> None:
        """Process request through middleware pipeline"""
        for middleware, _ in self.middlewares:
            try:
                await middleware.process_request(context)
                if context.skip_remaining:
                    break
            except Exception as e:
                context.error = e
                raise

    async def process_response(self, context: MiddlewareContext) -> None:
        """Process response through middleware pipeline"""
        for middleware, _ in reversed(self.middlewares):
            try:
                await middleware.process_response(context)
            except Exception as e:
                logger.error(f"Error in {middleware.name} response processing: {e}")
                # Don't raise, continue with other middleware


# Global middleware pipeline
middleware_pipeline = MiddlewarePipeline()


def get_middleware_pipeline() -> MiddlewarePipeline:
    """Get the global middleware pipeline"""
    return middleware_pipeline


def initialize_default_middleware():
    """Initialize default middleware stack"""
    pipeline = get_middleware_pipeline()

    # Add default middleware
    pipeline.add_middleware(
        LoggingMiddleware(
            MiddlewareConfig(name="logging", priority=MiddlewarePriority.LOGGING)
        )
    )

    return pipeline

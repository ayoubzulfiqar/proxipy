import asyncio
import logging
import re
import time
from typing import AsyncGenerator, Dict, Optional
from urllib.parse import urlparse, urlunparse

import httpx
from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from .config import settings

logger = logging.getLogger(__name__)

_HOST_REQUIRES_SCHEME = re.compile(
    r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?$"
)

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$")


def _is_valid_hostname(hostname: str) -> bool:
    if not hostname or hostname.endswith("."):
        return False

    if hostname.lower() in {"localhost", "127.0.0.1", "::1"}:
        return True

    try:
        import ipaddress

        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    if "." not in hostname:
        return False

    return all(_HOSTNAME_RE.match(part) for part in hostname.split("."))


class EnhancedProxyUtils:
    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._semaphore = asyncio.Semaphore(settings.MAX_CONNECTIONS)

    def sanitize_url(self, url: str) -> str:
        """Sanitize and validate URL"""
        # Remove potentially dangerous characters
        url = re.sub(r"[\x00-\x1F\x7F]", "", url).strip()

        if not url:
            raise ValueError("Empty URL is not allowed")

        # Ensure URL is properly formatted
        parsed = urlparse(url)

        if not parsed.scheme:
            candidate = "https://" + url
            parsed = urlparse(candidate)
            host_part = (parsed.netloc or parsed.path.split("/", 1)[0]).strip()
            if "/" in host_part:
                host_part = host_part.split("/", 1)[0]
            if not host_part or ":" in host_part.split(".")[0] or not _HOST_REQUIRES_SCHEME.match(host_part):
                raise ValueError(
                    f"Invalid URL format: {url}. Provide a full URL with scheme and hostname."
                )
            url = candidate

        if parsed.scheme and not parsed.netloc:
            if url.startswith("/"):
                raise ValueError(
                    f"Relative URL detected: {url}. Please provide a full URL with domain."
                )

        # Reconstruct URL without fragments
        sanitized = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                "",  # Remove fragment
            )
        )

        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                "Invalid URL format - must include scheme (http/https) and domain"
            )

        host = parsed.hostname
        if not host or not _is_valid_hostname(host):
            raise ValueError(
                "Invalid URL format - target host is not a valid hostname or IP"
            )

        return sanitized

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with connection pooling"""
        if self._client is None or self._client.is_closed:
            limits = httpx.Limits(
                max_keepalive_connections=20, max_connections=settings.MAX_CONNECTIONS
            )
            timeout = httpx.Timeout(
                timeout=settings.TIMEOUT,
                connect=settings.CONNECTION_TIMEOUT,
                read=settings.READ_TIMEOUT,
                write=settings.WRITE_TIMEOUT,
                pool=settings.TIMEOUT,
            )

            # Prepare headers with fingerprint spoofing
            headers = {}

            # Use fingerprint spoofing if enabled
            if settings.FINGERPRINT_SPOOFING_ENABLED:
                headers.update(
                    {
                        "User-Agent": settings.FINGERPRINT_SPOOFING_USER_AGENT,
                        "Accept": settings.FINGERPRINT_SPOOFING_ACCEPT,
                        "Accept-Encoding": settings.FINGERPRINT_SPOOFING_ACCEPT_ENCODING,
                        "Accept-Language": settings.FINGERPRINT_SPOOFING_ACCEPT_LANGUAGE,
                        "DNT": settings.FINGERPRINT_SPOOFING_DNT,
                        "Upgrade-Insecure-Requests": settings.FINGERPRINT_SPOOFING_UPGRADE_INSECURE_REQUESTS,
                    }
                )
            else:
                headers.update(
                    {
                        "User-Agent": settings.USER_AGENT,
                        "Accept-Encoding": "gzip, deflate"
                        if settings.ENABLE_COMPRESSION
                        else "identity",
                    }
                )

            self._client = httpx.AsyncClient(
                limits=limits,
                timeout=timeout,
                follow_redirects=True,
                max_redirects=settings.MAX_REDIRECTS,
                http2=settings.ENABLE_HTTP2,
                headers=headers,
            )
        return self._client

    async def fetch_url(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        stream: bool = False,
    ) -> httpx.Response:
        """Enhanced URL fetching with intelligent streaming"""
        async with self._semaphore:
            client = await self.get_client()

            # Prepare request headers
            request_headers = {"User-Agent": settings.USER_AGENT}
            if headers:
                request_headers.update(headers)

            # Remove problematic headers
            request_headers.pop("host", None)
            request_headers.pop("content-length", None)

            try:
                start_time = time.time()

                response = await client.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    content=body,
                    timeout=httpx.Timeout(
                        connect=settings.CONNECTION_TIMEOUT,
                        read=settings.READ_TIMEOUT,
                        write=settings.WRITE_TIMEOUT,
                        pool=settings.TIMEOUT,
                    ),
                )

                # Log request metrics
                process_time = time.time() - start_time
                logger.info(
                    f"Request completed: {method} {url} - "
                    f"Status: {response.status_code} - "
                    f"Time: {process_time:.3f}s - "
                    f"Size: {len(response.content) if not stream else 'streamed'}"
                )

                return response

            except httpx.TimeoutException as exc:
                logger.error(f"Request timeout: {method} {url}")
                raise HTTPException(status_code=504, detail="Request timeout") from exc
            except httpx.ConnectError as exc:
                logger.error(f"Connection error: {method} {url}")
                raise HTTPException(status_code=502, detail="Connection error") from exc
            except httpx.RequestError as exc:
                logger.error(f"Request failed: {method} {url} - {str(exc)}")
                raise HTTPException(
                    status_code=500, detail=f"Request failed: {str(exc)}"
                ) from exc
            except Exception as exc:
                logger.error(f"Unexpected error: {method} {url} - {str(exc)}")
                raise HTTPException(
                    status_code=500, detail=f"Unexpected error: {str(exc)}"
                ) from exc

    async def fetch_url_streaming(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> AsyncGenerator[bytes, None]:
        """Stream URL response for large files"""
        async with self._semaphore:
            client = await self.get_client()

            # Prepare request headers
            request_headers = {"User-Agent": settings.USER_AGENT}
            if headers:
                request_headers.update(headers)

            # Remove problematic headers
            request_headers.pop("host", None)
            request_headers.pop("content-length", None)

            try:
                start_time = time.time()

                async with client.stream(
                    method=method,
                    url=url,
                    headers=request_headers,
                    content=body,
                    timeout=httpx.Timeout(
                        timeout=settings.TIMEOUT,
                        connect=settings.CONNECTION_TIMEOUT,
                        read=settings.READ_TIMEOUT,
                        write=settings.WRITE_TIMEOUT,
                    ),
                ) as response:
                    if response.status_code >= 400:
                        error_content = await response.aread()
                        raise HTTPException(
                            status_code=response.status_code,
                            detail=error_content.decode()
                            if error_content
                            else "Request failed",
                        )

                    async for chunk in response.aiter_bytes(
                        chunk_size=settings.STREAM_CHUNK_SIZE
                    ):
                        yield chunk

                # Log streaming metrics
                process_time = time.time() - start_time
                logger.info(
                    f"Streaming completed: {method} {url} - "
                    f"Status: {response.status_code} - "
                    f"Time: {process_time:.3f}s"
                )

            except httpx.TimeoutException as exc:
                logger.error(f"Streaming timeout: {method} {url}")
                raise HTTPException(status_code=504, detail="Request timeout") from exc
            except httpx.ConnectError as exc:
                logger.error(f"Streaming connection error: {method} {url}")
                raise HTTPException(status_code=502, detail="Connection error") from exc
            except Exception as exc:
                logger.error(f"Streaming error: {method} {url} - {str(exc)}")
                raise HTTPException(
                    status_code=500, detail=f"Streaming failed: {str(exc)}"
                ) from exc

    def should_stream_response(self, response: httpx.Response) -> bool:
        """Determine if response should be streamed"""
        content_length = response.headers.get("content-length")
        length = None
        if content_length:
            try:
                length = int(content_length)
                if length > settings.STREAM_THRESHOLD:
                    return True
            except ValueError:
                pass

        content_type = response.headers.get("content-type", "")
        return settings.should_stream(length, content_type)

    async def create_streaming_response(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> StreamingResponse:
        """Create a streaming response for large files"""
        return StreamingResponse(
            self.fetch_url_streaming(url, method, headers, body),
            media_type="application/octet-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",  # Disable nginx buffering
            },
        )

    async def close_client(self):
        """Close HTTP client"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def reset_client(self):
        """Reset client (for testing purposes)"""
        if self._client:
            # Don't close in tests, just reset the reference
            self._client = None


proxy_utils = EnhancedProxyUtils()

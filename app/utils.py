import re
from typing import Dict, Optional
from urllib.parse import urlparse, urlunparse

import httpx
from fastapi import HTTPException

from .config import settings


class ProxyUtils:
    def sanitize_url(self, url: str) -> str:
        """Sanitize and validate URL"""
        # Remove potentially dangerous characters
        url = re.sub(r"[\x00-\x1F\x7F]", "", url)

        # Ensure URL is properly formatted
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
            parsed = urlparse(url)

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

        return sanitized

    async def fetch_url(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> httpx.Response:
        """Fetch URL with error handling"""
        # Create a new client for each request to avoid event loop issues
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
        timeout = httpx.Timeout(settings.TIMEOUT)

        async with httpx.AsyncClient(
            limits=limits,
            timeout=timeout,
            follow_redirects=True,
            max_redirects=settings.MAX_REDIRECTS,
            headers={
                "User-Agent": settings.USER_AGENT,
            },
        ) as client:
            try:
                response = await client.request(
                    method=method, url=url, headers=headers, content=body
                )
                return response
            except httpx.TimeoutException as exc:
                raise HTTPException(status_code=504, detail="Request timeout") from exc
            except httpx.ConnectError as exc:
                raise HTTPException(status_code=502, detail="Connection error") from exc
            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=500, detail=f"Request failed: {str(exc)}"
                ) from exc
            except Exception as exc:
                raise HTTPException(
                    status_code=500, detail=f"Unexpected error: {str(exc)}"
                ) from exc

    async def close_client(self):
        """Close HTTP client - no-op since we create clients per request"""
        return


proxy_utils = ProxyUtils()

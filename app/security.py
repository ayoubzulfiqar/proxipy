import ipaddress
from typing import Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from fastapi.responses import Response

from .config import settings


class SecurityMiddleware:
    def __init__(self):
        self.blocked_domains = settings.BLOCKED_DOMAINS
        self.allowed_content_types = settings.ALLOWED_CONTENT_TYPES

    async def validate_request(self, request: Request, target_url: str) -> None:
        """Validate the request for security concerns"""

        # Check if target URL is provided
        if not target_url or not isinstance(target_url, str):
            raise HTTPException(
                status_code=400, detail="URL parameter is required and must be a string"
            )

        # Check URL length to prevent extremely long URLs
        if len(target_url) > 2048:  # Common URL length limit
            raise HTTPException(status_code=400, detail="URL too long")

        # Parse and validate URL
        try:
            parsed_url = urlparse(target_url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise HTTPException(status_code=400, detail="Invalid URL format")
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid URL format") from exc

        # Check for blocked domains and IPs
        self._check_blocked_domains(parsed_url.netloc)

        # Validate scheme
        if parsed_url.scheme not in ["http", "https"]:
            raise HTTPException(
                status_code=400, detail="Only HTTP and HTTPS protocols are allowed"
            )

        # Additional security checks
        if ".." in parsed_url.path or ".." in parsed_url.netloc:
            raise HTTPException(
                status_code=400, detail="URL contains directory traversal"
            )

    def _check_blocked_domains(self, domain: str) -> None:
        """Check if the domain is in the blocked list"""
        for blocked in settings.BLOCKED_DOMAINS:
            if "/" in blocked:  # IP range
                try:
                    if ipaddress.ip_address(domain) in ipaddress.ip_network(
                        blocked, strict=False
                    ):
                        raise HTTPException(
                            status_code=403, detail="Access to this domain is blocked"
                        )
                except ValueError:
                    continue
            else:  # Domain or IP
                if blocked in domain or domain == blocked:
                    raise HTTPException(
                        status_code=403, detail="Access to this domain is blocked"
                    )

    def validate_content_type(self, content_type: Optional[str]) -> bool:
        """Validate if content type is allowed"""
        if not content_type:
            return True

        main_type = content_type.split(";")[0].strip()
        return main_type in self.allowed_content_types

    def add_security_headers(self, response: Response) -> Response:
        """Add security headers to response"""

        # CORS headers
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = ", ".join(
            settings.ALLOWED_METHODS
        )
        response.headers["Access-Control-Allow-Headers"] = ", ".join(
            settings.ALLOWED_HEADERS
        )

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        if settings.ENABLE_CSP:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'none'; object-src 'none'"
            )

        if settings.ENABLE_HSTS:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response


security = SecurityMiddleware()

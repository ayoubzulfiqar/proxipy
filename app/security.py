import ipaddress
import logging
import re
from typing import Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from fastapi.responses import Response

from .config import settings

logger = logging.getLogger(__name__)


class EnhancedSecurityMiddleware:
    def __init__(self):
        self.blocked_domains = set(settings.BLOCKED_DOMAINS)
        self.allowed_content_types = set(settings.ALLOWED_CONTENT_TYPES)
        self.suspicious_patterns = [
            r"\.\./",  # Directory traversal
            r"\.\.\\",  # Windows directory traversal
            r"%2e%2e%2f",  # URL encoded ../
            r"%2e%2e%5c",  # URL encoded ..\
            r"\.\.%2f",  # Mixed encoding
            r"javascript:",  # JavaScript URLs
            r"data:",  # Data URLs
            r"vbscript:",  # VBScript URLs
            r"file:",  # File URLs
            r"ftp:",  # FTP URLs
            r"<script",  # Script tags
            r"on\w+\s*=",  # Event handlers
        ]

    async def validate_request(self, request: Request, target_url: str) -> None:
        """Enhanced request validation with comprehensive security checks"""

        # Basic validation
        if not target_url or not isinstance(target_url, str):
            raise HTTPException(
                status_code=400, detail="URL parameter is required and must be a string"
            )

        # Check URL length to prevent extremely long URLs
        if len(target_url) > 2048:
            logger.warning(f"URL too long: {len(target_url)} characters")
            raise HTTPException(status_code=400, detail="URL too long")

        # Check for suspicious patterns
        self._check_suspicious_patterns(target_url)

        # Parse and validate URL
        try:
            parsed_url = urlparse(target_url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise HTTPException(status_code=400, detail="Invalid URL format")
        except Exception as exc:
            logger.warning(f"Invalid URL format: {target_url}")
            raise HTTPException(status_code=400, detail="Invalid URL format") from exc

        # Check for blocked domains and IPs
        self._check_blocked_domains(parsed_url.netloc)

        # Validate scheme
        if parsed_url.scheme not in ["http", "https"]:
            logger.warning(f"Invalid scheme: {parsed_url.scheme}")
            raise HTTPException(
                status_code=400, detail="Only HTTP and HTTPS protocols are allowed"
            )

        # Enhanced security checks
        if ".." in parsed_url.path or ".." in parsed_url.netloc:
            logger.warning(f"Directory traversal attempt: {target_url}")
            raise HTTPException(
                status_code=400, detail="URL contains directory traversal"
            )

        # Check for private IP access
        self._check_private_ip_access(parsed_url.netloc)

        # Rate limiting check based on IP
        client_ip = self._get_client_ip(request)
        self._check_rate_limit(client_ip)

    def _check_suspicious_patterns(self, url: str) -> None:
        """Check for suspicious patterns in URL"""
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                logger.warning(f"Suspicious pattern detected: {pattern} in {url}")
                raise HTTPException(
                    status_code=400, detail="URL contains suspicious content"
                )

    def _check_blocked_domains(self, domain: str) -> None:
        """Enhanced check for blocked domains and IPs"""
        # Remove port if present
        domain = domain.split(":")[0]

        for blocked in self.blocked_domains:
            if "/" in blocked:  # IP range
                try:
                    if ipaddress.ip_address(domain) in ipaddress.ip_network(
                        blocked, strict=False
                    ):
                        logger.warning(
                            f"Blocked IP range access: {domain} matches {blocked}"
                        )
                        raise HTTPException(
                            status_code=403, detail="Access to this domain is blocked"
                        )
                except ValueError:
                    continue
            else:  # Domain or IP
                if blocked in domain or domain.endswith(f".{blocked}"):
                    logger.warning(f"Blocked domain access: {domain}")
                    raise HTTPException(
                        status_code=403, detail="Access to this domain is blocked"
                    )

    def _check_private_ip_access(self, domain: str) -> None:
        """Prevent access to private IP ranges"""
        try:
            ip = ipaddress.ip_address(domain)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                logger.warning(f"Private IP access attempt: {domain}")
                raise HTTPException(
                    status_code=403, detail="Access to private IPs is not allowed"
                )
        except ValueError:
            # Not an IP address, check for localhost variations
            if domain.lower() in ["localhost", "127.0.0.1", "::1"]:
                logger.warning(f"Localhost access attempt: {domain}")
                raise HTTPException(
                    status_code=403, detail="Access to localhost is not allowed"
                )

    def _get_client_ip(self, request: Request) -> str:
        """Get real client IP from request"""
        # Check X-Forwarded-For header first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fall back to client host
        return request.client.host if request.client else "unknown"

    def _check_rate_limit(self, client_ip: str) -> None:
        """Basic rate limiting check (placeholder for more sophisticated implementation)"""
        # This is a placeholder - actual rate limiting is handled by slowapi middleware
        pass

    def validate_content_type(self, content_type: Optional[str]) -> bool:
        """Enhanced content type validation"""
        if not content_type:
            return True  # Allow unknown content types for flexibility

        main_type = content_type.split(";")[0].strip().lower()

        # Check against allowed types
        if main_type in self.allowed_content_types:
            return True

        # Allow some common variations
        type_mapping = {
            "application/x-javascript": "application/javascript",
            "application/x-json": "application/json",
            "text/x-json": "application/json",
        }

        return type_mapping.get(main_type, "") in self.allowed_content_types

    def add_security_headers(self, response: Response) -> Response:
        """Add comprehensive security headers to response"""

        # CORS headers (only if enabled)
        if settings.ENABLE_CORS:
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = ", ".join(
                settings.ALLOWED_METHODS
            )
            response.headers["Access-Control-Allow-Headers"] = ", ".join(
                settings.ALLOWED_HEADERS
            )
            response.headers["Access-Control-Max-Age"] = "86400"

        # Cross-Origin Policies
        if settings.ENABLE_CORP:
            response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"

        if settings.ENABLE_COEP:
            response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

        if settings.ENABLE_COOP:
            response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        # Basic security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )

        # Enhanced CSP
        if settings.ENABLE_CSP:
            csp_directives = [
                "default-src 'self'",
                "script-src 'none'",
                "object-src 'none'",
                "base-uri 'self'",
                "form-action 'self'",
                "frame-ancestors 'none'",
                "upgrade-insecure-requests",
            ]
            response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        # HSTS (only for HTTPS)
        if settings.ENABLE_HSTS:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # HTTPS enforcement
        if settings.ENABLE_HTTPS_ONLY:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # Additional security headers
        response.headers["X-DNS-Prefetch-Control"] = "off"
        response.headers["X-Download-Options"] = "noopen"
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        return response

    def sanitize_headers(self, headers: dict) -> dict:
        """Remove potentially dangerous headers"""
        dangerous_headers = {
            "host",
            "content-length",
            "content-encoding",
            "transfer-encoding",
            "connection",
            "upgrade",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-protocol",
            "sec-websocket-accept",
            "sec-websocket-extensions",
        }

        return {k: v for k, v in headers.items() if k.lower() not in dangerous_headers}


security = EnhancedSecurityMiddleware()

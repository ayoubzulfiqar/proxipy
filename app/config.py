from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Server Configuration
    APP_NAME: str = "CORS Proxy Server"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALLOWED_HOSTS: List[str] = ["*"]
    ALLOWED_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    ALLOWED_HEADERS: List[str] = ["*"]
    MAX_CONTENT_LENGTH: int = 50 * 1024 * 1024  # 50MB

    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    REDIS_URL: str = "redis://localhost:6379"
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000

    # Security Headers
    ENABLE_CSP: bool = True
    ENABLE_HSTS: bool = True

    # Proxy Configuration
    MAX_REDIRECTS: int = 5
    TIMEOUT: float = 30.0
    USER_AGENT: str = "CORS-Proxy-Server/1.0.0"

    # Blocked Domains (for security)
    BLOCKED_DOMAINS: List[str] = [
        "localhost",
        "127.0.0.1",
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "169.254.0.0/16",
    ]

    # Allowed Content Types
    ALLOWED_CONTENT_TYPES: List[str] = [
        "application/json",
        "application/xml",
        "text/plain",
        "text/html",
        "text/css",
        "application/javascript",
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/svg+xml",
    ]

    class Config:
        env_file = ".env"


settings = Settings()

import os
from typing import List, Optional

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    # Server Configuration
    APP_NAME: str = "CORS Proxy Server"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Performance & Concurrency
    MAX_CONNECTIONS: int = 100
    MAX_WORKERS: int = 4
    CONNECTION_TIMEOUT: float = 30.0
    READ_TIMEOUT: float = 60.0
    WRITE_TIMEOUT: float = 30.0
    STREAM_CHUNK_SIZE: int = 8192
    MAX_RESPONSE_SIZE: int = 100 * 1024 * 1024  # 100MB

    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALLOWED_HOSTS: List[str] = ["*"]
    ALLOWED_METHODS: List[str] = [
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "OPTIONS",
        "HEAD",
        "PATCH",
    ]
    ALLOWED_HEADERS: List[str] = ["*"]
    MAX_CONTENT_LENGTH: int = 50 * 1024 * 1024  # 50MB

    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    REDIS_URL: str = "redis://localhost:6379"
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000
    RATE_LIMIT_BURST: int = 10

    # Security Headers & Policies
    ENABLE_CSP: bool = True
    ENABLE_HSTS: bool = True
    ENABLE_HTTPS_ONLY: bool = False
    ENABLE_CORS: bool = True
    ENABLE_CORP: bool = True
    ENABLE_COEP: bool = True
    ENABLE_COOP: bool = True

    # Proxy Configuration
    MAX_REDIRECTS: int = 5
    TIMEOUT: float = 30.0
    USER_AGENT: str = "CORS-Proxy-Server/1.0.0"
    ENABLE_HTTP2: bool = True
    ENABLE_COMPRESSION: bool = True

    # Content Type Configuration
    STREAM_THRESHOLD: int = 1024 * 1024  # 1MB - files larger than this will be streamed

    # Blocked Domains (for security)
    BLOCKED_DOMAINS: List[str] = [
        "localhost",
        "127.0.0.1",
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "169.254.0.0/16",
        "::1",
        "0.0.0.0/8",
    ]

    # Enhanced Content Types - Binary (Streamed)
    BINARY_CONTENT_TYPES: List[str] = [
        "application/octet-stream",
        "application/pdf",
        "application/zip",
        "application/gzip",
        "application/x-tar",
        "application/x-gzip",
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/svg+xml",
        "image/bmp",
        "image/tiff",
        "image/avif",
        "video/mp4",
        "video/webm",
        "video/ogg",
        "audio/mpeg",
        "audio/wav",
        "audio/ogg",
        "font/woff",
        "font/woff2",
        "font/ttf",
        "font/otf",
        "application/x-font-ttf",
        "application/font-woff",
        "application/font-woff2",
    ]

    # Text Content Types (Buffered)
    TEXT_CONTENT_TYPES: List[str] = [
        "application/json",
        "application/xml",
        "application/javascript",
        "text/plain",
        "text/html",
        "text/css",
        "text/javascript",
        "text/xml",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/graphql",
        "text/csv",
        "text/tab-separated-values",
        "application/ld+json",
        "application/rss+xml",
        "application/atom+xml",
    ]

    # All Allowed Content Types
    ALLOWED_CONTENT_TYPES: List[str] = Field(
        default_factory=lambda: [
            # Text types
            "application/json",
            "application/xml",
            "application/javascript",
            "text/plain",
            "text/html",
            "text/css",
            "text/javascript",
            "text/xml",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "application/graphql",
            "text/csv",
            "text/tab-separated-values",
            "application/ld+json",
            "application/rss+xml",
            "application/atom+xml",
            # Binary types
            "application/octet-stream",
            "application/pdf",
            "application/zip",
            "application/gzip",
            "application/x-tar",
            "application/x-gzip",
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            "image/svg+xml",
            "image/bmp",
            "image/tiff",
            "image/avif",
            "video/mp4",
            "video/webm",
            "video/ogg",
            "audio/mpeg",
            "audio/wav",
            "audio/ogg",
            "font/woff",
            "font/woff2",
            "font/ttf",
            "font/otf",
            "application/x-font-ttf",
            "application/font-woff",
            "application/font-woff2",
        ]
    )

    # Logging Configuration
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE: str = "proxy.log"
    STRUCTURED_LOGGING: bool = True

    # Health Check Configuration
    HEALTH_CHECK_PATH: str = "/health"
    METRICS_PATH: str = "/metrics"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.load_config_file()

    def load_config_file(self, config_file: str = "config.yaml"):
        """Load configuration from YAML file if it exists"""
        if os.path.exists(config_file):
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    yaml_config = yaml.safe_load(f)
                if yaml_config:
                    for key, value in yaml_config.items():
                        if hasattr(self, key.upper()):
                            setattr(self, key.upper(), value)
            except Exception as e:
                print(f"Warning: Could not load config file {config_file}: {e}")

    def is_binary_content(self, content_type: Optional[str]) -> bool:
        """Check if content type should be streamed as binary"""
        if not content_type:
            return False
        main_type = content_type.split(";")[0].strip()
        return main_type in self.BINARY_CONTENT_TYPES

    def is_text_content(self, content_type: Optional[str]) -> bool:
        """Check if content type should be buffered as text"""
        if not content_type:
            return True  # Default to text for unknown types
        main_type = content_type.split(";")[0].strip()
        return main_type in self.TEXT_CONTENT_TYPES

    def should_stream(
        self, content_length: Optional[int], content_type: Optional[str]
    ) -> bool:
        """Determine if response should be streamed"""
        if content_length and content_length > self.STREAM_THRESHOLD:
            return True
        return self.is_binary_content(content_type)


settings = Settings()

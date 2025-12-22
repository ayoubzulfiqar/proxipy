import os
from typing import List, Optional

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .load_balancer import (
    BackendServer,
    HealthCheckConfig,
    LoadBalancerConfig,
    LoadBalancingAlgorithm,
)
from .middleware import (
    AuthenticationConfig,
    BufferingConfig,
    CircuitBreakerConfig,
    CompressionConfig,
    HeaderManipulationConfig,
    IPFilterConfig,
    RateLimitConfig,
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    # Server Configuration
    APP_NAME: str = "Proxipy"
    VERSION: str = "2.5.8"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8080

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
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ENABLE_HTTP2: bool = True
    ENABLE_COMPRESSION: bool = True

    # Fingerprint Spoofing Configuration
    FINGERPRINT_SPOOFING_ENABLED: bool = True
    FINGERPRINT_SPOOFING_JA4_ENABLED: bool = True
    FINGERPRINT_SPOOFING_JA4H_ENABLED: bool = True
    FINGERPRINT_SPOOFING_CHROME_MATCHING: bool = True
    FINGERPRINT_SPOOFING_USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    FINGERPRINT_SPOOFING_ACCEPT: str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
    FINGERPRINT_SPOOFING_ACCEPT_ENCODING: str = "gzip, deflate, br"
    FINGERPRINT_SPOOFING_ACCEPT_LANGUAGE: str = "en-US,en;q=0.9"
    FINGERPRINT_SPOOFING_DNT: str = "1"
    FINGERPRINT_SPOOFING_UPGRADE_INSECURE_REQUESTS: str = "1"

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

    # Load Balancer Configuration
    LOAD_BALANCER_ENABLED: bool = True
    LOAD_BALANCER_ALGORITHM: LoadBalancingAlgorithm = LoadBalancingAlgorithm.ROUND_ROBIN
    LOAD_BALANCER_SESSION_STICKINESS: bool = False
    LOAD_BALANCER_SESSION_COOKIE_NAME: str = "PROXIPY_SESSION"
    LOAD_BALANCER_SESSION_TIMEOUT: int = 3600  # 1 hour
    LOAD_BALANCER_ENABLE_CIRCUIT_BREAKER: bool = True
    LOAD_BALANCER_CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = 5
    LOAD_BALANCER_CIRCUIT_BREAKER_RECOVERY_TIMEOUT: float = 60.0

    # Health Check Configuration for Load Balancer
    LOAD_BALANCER_HEALTH_CHECK_PROTOCOL: str = "http"
    LOAD_BALANCER_HEALTH_CHECK_PATH: str = "/health"
    LOAD_BALANCER_HEALTH_CHECK_PORT: Optional[int] = None
    LOAD_BALANCER_HEALTH_CHECK_INTERVAL: float = 30.0
    LOAD_BALANCER_HEALTH_CHECK_TIMEOUT: float = 5.0
    LOAD_BALANCER_HEALTH_CHECK_HEALTHY_THRESHOLD: int = 2
    LOAD_BALANCER_HEALTH_CHECK_UNHEALTHY_THRESHOLD: int = 3
    LOAD_BALANCER_HEALTH_CHECK_EXPECTED_STATUS: int = 200

    # Backend Servers Configuration
    BACKEND_SERVERS: List[BackendServer] = Field(
        default_factory=lambda: [
            BackendServer(
                host="httpbin.org",
                port=443,
                protocol="https",
                weight=1,
                max_connections=100,
                server_id="httpbin_server",
            ),
            BackendServer(
                host="httpbingo.org",
                port=443,
                protocol="https",
                weight=1,
                max_connections=100,
                server_id="httpbingo_server",
            ),
        ]
    )

    # Middleware Configuration
    MIDDLEWARE_ENABLED: bool = True
    MIDDLEWARE_RATE_LIMIT_ENABLED: bool = True
    MIDDLEWARE_RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60
    MIDDLEWARE_RATE_LIMIT_REQUESTS_PER_HOUR: int = 1000
    MIDDLEWARE_RATE_LIMIT_BURST_SIZE: int = 10
    MIDDLEWARE_RATE_LIMIT_BLOCK_DURATION: float = 300.0

    MIDDLEWARE_CIRCUIT_BREAKER_ENABLED: bool = True
    MIDDLEWARE_CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = 5
    MIDDLEWARE_CIRCUIT_BREAKER_RECOVERY_TIMEOUT: float = 60.0
    MIDDLEWARE_CIRCUIT_BREAKER_HALF_OPEN_MAX_REQUESTS: int = 3
    MIDDLEWARE_CIRCUIT_BREAKER_TIMEOUT: float = 30.0

    MIDDLEWARE_COMPRESSION_ENABLED: bool = True
    MIDDLEWARE_COMPRESSION_MIN_SIZE: int = 1024
    MIDDLEWARE_COMPRESSION_COMPRESSION_LEVEL: int = 6
    MIDDLEWARE_COMPRESSION_SUPPORTED_ENCODINGS: List[str] = Field(
        default_factory=lambda: ["gzip", "deflate"]
    )

    MIDDLEWARE_BUFFERING_ENABLED: bool = True
    MIDDLEWARE_BUFFERING_MAX_BUFFER_SIZE: int = 1024 * 1024  # 1MB
    MIDDLEWARE_BUFFERING_BUFFER_TIMEOUT: float = 5.0
    MIDDLEWARE_BUFFERING_ENABLE_STREAMING: bool = True

    MIDDLEWARE_HEADER_MANIPULATION_ENABLED: bool = True
    MIDDLEWARE_HEADER_MANIPULATION_ADD_HEADERS: dict = Field(default_factory=dict)
    MIDDLEWARE_HEADER_MANIPULATION_REMOVE_HEADERS: List[str] = Field(
        default_factory=list
    )
    MIDDLEWARE_HEADER_MANIPULATION_MODIFY_HEADERS: dict = Field(default_factory=dict)
    MIDDLEWARE_HEADER_MANIPULATION_STRIP_PREFIX: str = ""
    MIDDLEWARE_HEADER_MANIPULATION_REDIRECT_PREFIX: str = ""

    MIDDLEWARE_IP_FILTER_ENABLED: bool = True
    MIDDLEWARE_IP_FILTER_WHITELIST: List[str] = Field(default_factory=list)
    MIDDLEWARE_IP_FILTER_BLACKLIST: List[str] = Field(default_factory=list)
    MIDDLEWARE_IP_FILTER_BLOCK_PRIVATE_IPS: bool = True
    MIDDLEWARE_IP_FILTER_BLOCK_LOOPBACK: bool = True

    MIDDLEWARE_AUTHENTICATION_ENABLED: bool = False
    MIDDLEWARE_AUTHENTICATION_BASIC_AUTH: dict = Field(default_factory=dict)
    MIDDLEWARE_AUTHENTICATION_JWT_SECRET: Optional[str] = None
    MIDDLEWARE_AUTHENTICATION_JWT_ALGORITHM: str = "HS256"
    MIDDLEWARE_AUTHENTICATION_REQUIRED_SCOPES: List[str] = Field(default_factory=list)

    # Protocol Support Configuration
    PROTOCOL_HTTP_ENABLED: bool = True
    PROTOCOL_HTTPS_ENABLED: bool = True
    PROTOCOL_WEBSOCKET_ENABLED: bool = True
    PROTOCOL_WEBSOCKETS_ENABLED: bool = True
    PROTOCOL_TCP_ENABLED: bool = False
    PROTOCOL_UDP_ENABLED: bool = False
    PROTOCOL_GRPC_ENABLED: bool = False

    # Advanced Routing Configuration
    ROUTING_ENABLED: bool = False
    ROUTING_REGEX_ENABLED: bool = False
    ROUTING_PRIORITY_ENABLED: bool = False
    ROUTING_PATH_REWRITING_ENABLED: bool = False

    # Metrics & Monitoring Configuration
    METRICS_ENABLED: bool = True
    METRICS_PROMETHEUS_ENABLED: bool = False
    METRICS_HAPROXY_STYLE_ENABLED: bool = True

    # Authentication Configuration
    AUTHENTICATION_BASIC_ENABLED: bool = True
    AUTHENTICATION_BASIC_USERS: dict = Field(
        default_factory=lambda: {"admin": "password123", "user": "user123"}
    )
    AUTHENTICATION_JWT_ENABLED: bool = False
    AUTHENTICATION_JWT_SECRET: Optional[str] = None
    AUTHENTICATION_JWT_ALGORITHM: str = "HS256"
    AUTHENTICATION_CLIENT_CERT_ENABLED: bool = False

    # Fingerprint Spoofing Configuration
    FINGERPRINT_SPOOFING_ENABLED: bool = False
    FINGERPRINT_SPOOFING_JA4_ENABLED: bool = False
    FINGERPRINT_SPOOFING_JA4H_ENABLED: bool = False
    FINGERPRINT_SPOOFING_CHROME_MATCHING: bool = False

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
                    self._apply_yaml_config(yaml_config)
            except Exception as e:
                print(f"Warning: Could not load config file {config_file}: {e}")

    def _apply_yaml_config(self, yaml_config: dict):
        """Apply YAML configuration to settings"""
        # Server configuration
        if "server" in yaml_config:
            server_config = yaml_config["server"]
            if "name" in server_config:
                self.APP_NAME = server_config["name"]
            if "version" in server_config:
                self.VERSION = server_config["version"]
            if "debug" in server_config:
                self.DEBUG = server_config["debug"]
            if "host" in server_config:
                self.HOST = server_config["host"]
            if "port" in server_config:
                self.PORT = server_config["port"]

        # Performance configuration
        if "performance" in yaml_config:
            perf_config = yaml_config["performance"]
            if "max_connections" in perf_config:
                self.MAX_CONNECTIONS = perf_config["max_connections"]
            if "max_workers" in perf_config:
                self.MAX_WORKERS = perf_config["max_workers"]
            if "connection_timeout" in perf_config:
                self.CONNECTION_TIMEOUT = perf_config["connection_timeout"]
            if "read_timeout" in perf_config:
                self.READ_TIMEOUT = perf_config["read_timeout"]
            if "write_timeout" in perf_config:
                self.WRITE_TIMEOUT = perf_config["write_timeout"]

        # Load balancer configuration
        if "load_balancer" in yaml_config:
            lb_config = yaml_config["load_balancer"]
            if "enabled" in lb_config:
                self.LOAD_BALANCER_ENABLED = lb_config["enabled"]
            if "algorithm" in lb_config:
                self.LOAD_BALANCER_ALGORITHM = LoadBalancingAlgorithm(
                    lb_config["algorithm"]
                )
            if "session_stickiness" in lb_config:
                self.LOAD_BALANCER_SESSION_STICKINESS = lb_config["session_stickiness"]
            if "enable_circuit_breaker" in lb_config:
                self.LOAD_BALANCER_ENABLE_CIRCUIT_BREAKER = lb_config[
                    "enable_circuit_breaker"
                ]

        # Backend servers configuration
        if "backend_servers" in yaml_config:
            self.BACKEND_SERVERS = []
            for server_config in yaml_config["backend_servers"]:
                server = BackendServer(
                    host=server_config["host"],
                    port=server_config["port"],
                    protocol=server_config.get("protocol", "http"),
                    weight=server_config.get("weight", 1),
                    max_connections=server_config.get("max_connections", 100),
                )
                self.BACKEND_SERVERS.append(server)

        # Middleware configuration
        if "middleware" in yaml_config:
            middleware_config = yaml_config["middleware"]

            # Rate limiting
            if "rate_limit" in middleware_config:
                rl_config = middleware_config["rate_limit"]
                if "enabled" in rl_config:
                    self.MIDDLEWARE_RATE_LIMIT_ENABLED = rl_config["enabled"]
                if "requests_per_minute" in rl_config:
                    self.MIDDLEWARE_RATE_LIMIT_REQUESTS_PER_MINUTE = rl_config[
                        "requests_per_minute"
                    ]
                if "requests_per_hour" in rl_config:
                    self.MIDDLEWARE_RATE_LIMIT_REQUESTS_PER_HOUR = rl_config[
                        "requests_per_hour"
                    ]

            # Circuit breaker
            if "circuit_breaker" in middleware_config:
                cb_config = middleware_config["circuit_breaker"]
                if "enabled" in cb_config:
                    self.MIDDLEWARE_CIRCUIT_BREAKER_ENABLED = cb_config["enabled"]
                if "failure_threshold" in cb_config:
                    self.MIDDLEWARE_CIRCUIT_BREAKER_FAILURE_THRESHOLD = cb_config[
                        "failure_threshold"
                    ]

            # IP filtering
            if "ip_filter" in middleware_config:
                ip_config = middleware_config["ip_filter"]
                if "whitelist" in ip_config:
                    self.MIDDLEWARE_IP_FILTER_WHITELIST = ip_config["whitelist"]
                if "blacklist" in ip_config:
                    self.MIDDLEWARE_IP_FILTER_BLACKLIST = ip_config["blacklist"]

            # Authentication
            if "authentication" in middleware_config:
                auth_config = middleware_config["authentication"]
                if "basic_auth" in auth_config:
                    self.MIDDLEWARE_AUTHENTICATION_BASIC_AUTH = auth_config[
                        "basic_auth"
                    ]

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

    def get_load_balancer_config(self) -> LoadBalancerConfig:
        """Get load balancer configuration"""
        health_check = HealthCheckConfig(
            protocol=self.LOAD_BALANCER_HEALTH_CHECK_PROTOCOL,
            path=self.LOAD_BALANCER_HEALTH_CHECK_PATH,
            port=self.LOAD_BALANCER_HEALTH_CHECK_PORT,
            interval=self.LOAD_BALANCER_HEALTH_CHECK_INTERVAL,
            timeout=self.LOAD_BALANCER_HEALTH_CHECK_TIMEOUT,
            healthy_threshold=self.LOAD_BALANCER_HEALTH_CHECK_HEALTHY_THRESHOLD,
            unhealthy_threshold=self.LOAD_BALANCER_HEALTH_CHECK_UNHEALTHY_THRESHOLD,
            expected_status=self.LOAD_BALANCER_HEALTH_CHECK_EXPECTED_STATUS,
        )

        return LoadBalancerConfig(
            algorithm=self.LOAD_BALANCER_ALGORITHM,
            health_check=health_check,
            session_stickiness=self.LOAD_BALANCER_SESSION_STICKINESS,
            session_cookie_name=self.LOAD_BALANCER_SESSION_COOKIE_NAME,
            session_timeout=self.LOAD_BALANCER_SESSION_TIMEOUT,
            enable_circuit_breaker=self.LOAD_BALANCER_ENABLE_CIRCUIT_BREAKER,
            circuit_breaker_failure_threshold=self.LOAD_BALANCER_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
            circuit_breaker_recovery_timeout=self.LOAD_BALANCER_CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
        )

    def get_rate_limit_config(self) -> RateLimitConfig:
        """Get rate limiting configuration"""
        return RateLimitConfig(
            enabled=self.MIDDLEWARE_RATE_LIMIT_ENABLED,
            requests_per_minute=self.MIDDLEWARE_RATE_LIMIT_REQUESTS_PER_MINUTE,
            requests_per_hour=self.MIDDLEWARE_RATE_LIMIT_REQUESTS_PER_HOUR,
            burst_size=self.MIDDLEWARE_RATE_LIMIT_BURST_SIZE,
            block_duration=self.MIDDLEWARE_RATE_LIMIT_BLOCK_DURATION,
        )

    def get_circuit_breaker_config(self) -> CircuitBreakerConfig:
        """Get circuit breaker configuration"""
        return CircuitBreakerConfig(
            enabled=self.MIDDLEWARE_CIRCUIT_BREAKER_ENABLED,
            failure_threshold=self.MIDDLEWARE_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
            recovery_timeout=self.MIDDLEWARE_CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
            half_open_max_requests=self.MIDDLEWARE_CIRCUIT_BREAKER_HALF_OPEN_MAX_REQUESTS,
            timeout=self.MIDDLEWARE_CIRCUIT_BREAKER_TIMEOUT,
        )

    def get_compression_config(self) -> CompressionConfig:
        """Get compression configuration"""
        return CompressionConfig(
            enabled=self.MIDDLEWARE_COMPRESSION_ENABLED,
            min_size=self.MIDDLEWARE_COMPRESSION_MIN_SIZE,
            compression_level=self.MIDDLEWARE_COMPRESSION_COMPRESSION_LEVEL,
            supported_encodings=self.MIDDLEWARE_COMPRESSION_SUPPORTED_ENCODINGS,
        )

    def get_buffering_config(self) -> BufferingConfig:
        """Get buffering configuration"""
        return BufferingConfig(
            enabled=self.MIDDLEWARE_BUFFERING_ENABLED,
            max_buffer_size=self.MIDDLEWARE_BUFFERING_MAX_BUFFER_SIZE,
            buffer_timeout=self.MIDDLEWARE_BUFFERING_BUFFER_TIMEOUT,
            enable_streaming=self.MIDDLEWARE_BUFFERING_ENABLE_STREAMING,
        )

    def get_header_manipulation_config(self) -> HeaderManipulationConfig:
        """Get header manipulation configuration"""
        return HeaderManipulationConfig(
            enabled=self.MIDDLEWARE_HEADER_MANIPULATION_ENABLED,
            add_headers=self.MIDDLEWARE_HEADER_MANIPULATION_ADD_HEADERS,
            remove_headers=self.MIDDLEWARE_HEADER_MANIPULATION_REMOVE_HEADERS,
            modify_headers=self.MIDDLEWARE_HEADER_MANIPULATION_MODIFY_HEADERS,
            strip_prefix=self.MIDDLEWARE_HEADER_MANIPULATION_STRIP_PREFIX,
            redirect_prefix=self.MIDDLEWARE_HEADER_MANIPULATION_REDIRECT_PREFIX,
        )

    def get_ip_filter_config(self) -> IPFilterConfig:
        """Get IP filter configuration"""
        return IPFilterConfig(
            enabled=self.MIDDLEWARE_IP_FILTER_ENABLED,
            whitelist=self.MIDDLEWARE_IP_FILTER_WHITELIST,
            blacklist=self.MIDDLEWARE_IP_FILTER_BLACKLIST,
            block_private_ips=self.MIDDLEWARE_IP_FILTER_BLOCK_PRIVATE_IPS,
            block_loopback=self.MIDDLEWARE_IP_FILTER_BLOCK_LOOPBACK,
        )

    def get_authentication_config(self) -> AuthenticationConfig:
        """Get authentication configuration"""
        return AuthenticationConfig(
            enabled=self.MIDDLEWARE_AUTHENTICATION_ENABLED,
            basic_auth=self.MIDDLEWARE_AUTHENTICATION_BASIC_AUTH,
            jwt_secret=self.MIDDLEWARE_AUTHENTICATION_JWT_SECRET,
            jwt_algorithm=self.MIDDLEWARE_AUTHENTICATION_JWT_ALGORITHM,
            required_scopes=self.MIDDLEWARE_AUTHENTICATION_REQUIRED_SCOPES,
        )


settings = Settings()

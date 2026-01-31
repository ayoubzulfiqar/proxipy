import asyncio
import logging
import time
import uuid
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, Optional, Tuple

import httpx
import websockets
from fastapi import HTTPException

from .config import settings

logger = logging.getLogger(__name__)

# Type aliases for better type checking
WebSocketProtocol = Any  # websockets.WebSocketClientProtocol


class ProtocolType(str, Enum):
    """Supported protocol types"""

    HTTP = "http"
    HTTPS = "https"
    WEBSOCKET = "websocket"
    WEBSOCKETS = "wss"
    GRPC = "grpc"
    TCP = "tcp"
    UDP = "udp"


class ProtocolConfig:
    """Protocol-specific configuration"""

    def __init__(self, protocol_type: ProtocolType, **kwargs):
        self.protocol_type = protocol_type
        self.timeout = kwargs.get("timeout", 30.0)
        self.retries = kwargs.get("retries", 3)
        self.buffer_size = kwargs.get("buffer_size", 8192)
        self.ssl_verify = kwargs.get("ssl_verify", True)
        self.ssl_cert = kwargs.get("ssl_cert", None)
        self.ssl_key = kwargs.get("ssl_key", None)


class ProtocolContext:
    """Context for protocol operations"""

    def __init__(self, request_id: str, protocol_config: ProtocolConfig):
        self.request_id = request_id
        self.protocol_config = protocol_config
        self.start_time = time.time()
        self.metadata: Dict[str, Any] = {}
        self.error: Optional[Exception] = None


class ProtocolHandler(ABC):
    """Abstract base class for protocol handlers"""

    def __init__(self, config: ProtocolConfig):
        self.config = config

    @abstractmethod
    async def connect(self, target_host: str, target_port: int) -> Any:
        """Establish connection to target"""
        pass

    @abstractmethod
    async def send_request(self, connection: Any, request_data: bytes) -> bytes:
        """Send request and receive response"""
        pass

    @abstractmethod
    async def close(self, connection: Any) -> None:
        """Close connection"""
        pass

    @abstractmethod
    def get_protocol_type(self) -> ProtocolType:
        """Get protocol type"""
        pass


class HTTPProtocolHandler(ProtocolHandler):
    """HTTP/HTTPS protocol handler"""

    def __init__(self, config: ProtocolConfig):
        super().__init__(config)
        self.client: Optional[httpx.AsyncClient] = None

    async def connect(self, target_host: str, target_port: int) -> httpx.AsyncClient:
        """Create HTTP client"""
        if self.client is None or self.client.is_closed:
            limits = httpx.Limits(
                max_keepalive_connections=20, max_connections=settings.MAX_CONNECTIONS
            )
            timeout = httpx.Timeout(
                connect=settings.CONNECTION_TIMEOUT,
                read=settings.READ_TIMEOUT,
                write=settings.WRITE_TIMEOUT,
                pool=settings.TIMEOUT,
            )

            self.client = httpx.AsyncClient(
                limits=limits,
                timeout=timeout,
                follow_redirects=True,
                max_redirects=5,
                http2=settings.ENABLE_HTTP2,
                verify=self.config.ssl_verify,
            )

        return self.client

    async def send_request(self, connection: Any, request_data: bytes) -> bytes:
        """Send HTTP request"""
        client = connection
        # Parse request data
        request_lines = request_data.decode().split("\r\n")
        method_line = request_lines[0]
        method, url, version = method_line.split()

        # Parse headers
        headers = {}
        for line in request_lines[1:]:
            if not line:
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()

        # Get body
        body_start = request_data.find(b"\r\n\r\n") + 4
        body = request_data[body_start:] if body_start > 3 else b""

        try:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            )

            # Build response
            response_data = f"{response.http_version} {response.status_code} {response.reason_phrase}\r\n"
            for key, value in response.headers.items():
                response_data += f"{key}: {value}\r\n"
            response_data += "\r\n"
            response_data = response_data.encode() + response.content

            return response_data

        except Exception as e:
            logger.error(f"HTTP request failed: {e}")
            raise HTTPException(status_code=500, detail=f"HTTP request failed: {e}")

    async def close(self, connection: Any) -> None:
        """Close HTTP client"""
        client = connection
        if client and not client.is_closed:
            await client.aclose()

    def get_protocol_type(self) -> ProtocolType:
        return ProtocolType.HTTP


class WebSocketProtocolHandler(ProtocolHandler):
    """WebSocket protocol handler"""

    def __init__(self, config: ProtocolConfig):
        super().__init__(config)
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None

    async def connect(self, target_host: str, target_port: int) -> WebSocketProtocol:
        """Connect to WebSocket server"""
        try:
            uri = f"ws://{target_host}:{target_port}"
            self.websocket = await websockets.connect(
                uri,
                timeout=self.config.timeout,
                max_size=1024 * 1024 * 10,  # 10MB
                ping_interval=20,
                ping_timeout=20,
            )
            return self.websocket
        except Exception as e:
            logger.error(f"WebSocket connection failed: {e}")
            raise HTTPException(
                status_code=500, detail=f"WebSocket connection failed: {e}"
            )

    async def send_request(self, connection: Any, request_data: bytes) -> bytes:
        """Send WebSocket message"""
        websocket = connection
        try:
            # For WebSocket, request_data is the message to send
            await websocket.send(request_data)

            # Receive response
            response = await asyncio.wait_for(
                websocket.recv(), timeout=self.config.timeout
            )

            if isinstance(response, str):
                return response.encode()
            return response

        except Exception as e:
            logger.error(f"WebSocket message failed: {e}")
            raise HTTPException(
                status_code=500, detail=f"WebSocket message failed: {e}"
            )

    async def close(self, connection: Any) -> None:
        """Close WebSocket connection"""
        websocket = connection
        if websocket:
            await websocket.close()

    def get_protocol_type(self) -> ProtocolType:
        return ProtocolType.WEBSOCKET


class TCPProtocolHandler(ProtocolHandler):
    """TCP protocol handler"""

    def __init__(self, config: ProtocolConfig):
        super().__init__(config)
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    async def connect(
        self, target_host: str, target_port: int
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to TCP server"""
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=self.config.timeout,
            )
            return self.reader, self.writer
        except Exception as e:
            logger.error(f"TCP connection failed: {e}")
            raise HTTPException(status_code=500, detail=f"TCP connection failed: {e}")

    async def send_request(
        self,
        connection: Tuple[asyncio.StreamReader, asyncio.StreamWriter],
        request_data: bytes,
    ) -> bytes:
        """Send TCP data"""
        reader, writer = connection

        try:
            # Send data
            writer.write(request_data)
            await writer.drain()

            # Read response
            response = await asyncio.wait_for(
                reader.read(self.config.buffer_size), timeout=self.config.timeout
            )

            return response

        except Exception as e:
            logger.error(f"TCP request failed: {e}")
            raise HTTPException(status_code=500, detail=f"TCP request failed: {e}")

    async def close(
        self, connection: Tuple[asyncio.StreamReader, asyncio.StreamWriter]
    ) -> None:
        """Close TCP connection"""
        reader, writer = connection
        if writer:
            writer.close()
            await writer.wait_closed()

    def get_protocol_type(self) -> ProtocolType:
        return ProtocolType.TCP


class UDPProtocolHandler(ProtocolHandler):
    """UDP protocol handler"""

    def __init__(self, config: ProtocolConfig):
        super().__init__(config)
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[asyncio.DatagramProtocol] = None
        self.response_future: Optional[asyncio.Future] = None

    class UDPProtocol(asyncio.DatagramProtocol):
        """UDP protocol implementation"""

        def __init__(self):
            self.response_future: Optional[asyncio.Future[bytes]] = None

        def connection_made(self, transport: asyncio.DatagramTransport) -> None:
            self.transport = transport

        def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
            if (
                hasattr(self, "response_future")
                and self.response_future is not None
                and not self.response_future.done()
            ):
                self.response_future.set_result(data)

        def error_received(self, exc: Exception) -> None:
            if (
                hasattr(self, "response_future")
                and self.response_future is not None
                and not self.response_future.done()
            ):
                self.response_future.set_exception(exc)

    async def connect(
        self, target_host: str, target_port: int
    ) -> Tuple[asyncio.DatagramTransport, asyncio.DatagramProtocol]:
        """Connect to UDP server"""
        try:
            loop = asyncio.get_event_loop()
            self.protocol = self.UDPProtocol()
            self.transport, protocol = await loop.create_datagram_endpoint(
                lambda: self.protocol, remote_addr=(target_host, target_port)
            )
            return self.transport, self.protocol
        except Exception as e:
            logger.error(f"UDP connection failed: {e}")
            raise HTTPException(status_code=500, detail=f"UDP connection failed: {e}")

    async def send_request(
        self,
        connection: Tuple[asyncio.DatagramTransport, asyncio.DatagramProtocol],
        request_data: bytes,
    ) -> bytes:
        """Send UDP datagram"""
        transport, protocol = connection
        response_future: Optional[asyncio.Future] = None

        try:
            # Create future for response
            response_future = asyncio.Future()

            # Send datagram
            transport.sendto(request_data)

            # Wait for response
            response = await asyncio.wait_for(
                response_future, timeout=self.config.timeout
            )

            return response

        except Exception as e:
            logger.error(f"UDP request failed: {e}")
            raise HTTPException(status_code=500, detail=f"UDP request failed: {e}")
        finally:
            if response_future and not response_future.done():
                response_future.cancel()

    async def close(
        self, connection: Tuple[asyncio.DatagramTransport, asyncio.DatagramProtocol]
    ) -> None:
        """Close UDP connection"""
        transport, protocol = connection
        if transport:
            transport.close()

    def get_protocol_type(self) -> ProtocolType:
        return ProtocolType.UDP


class ProtocolRouter:
    """Protocol router for handling different protocols"""

    def __init__(self):
        self.handlers: Dict[ProtocolType, ProtocolHandler] = {}
        self._init_handlers()

    def _init_handlers(self):
        """Initialize protocol handlers"""
        self.handlers[ProtocolType.HTTP] = HTTPProtocolHandler(
            ProtocolConfig(ProtocolType.HTTP)
        )
        self.handlers[ProtocolType.HTTPS] = HTTPProtocolHandler(
            ProtocolConfig(ProtocolType.HTTPS, ssl_verify=True)
        )
        self.handlers[ProtocolType.WEBSOCKET] = WebSocketProtocolHandler(
            ProtocolConfig(ProtocolType.WEBSOCKET)
        )
        self.handlers[ProtocolType.WEBSOCKETS] = WebSocketProtocolHandler(
            ProtocolConfig(ProtocolType.WEBSOCKETS, ssl_verify=True)
        )
        self.handlers[ProtocolType.TCP] = TCPProtocolHandler(
            ProtocolConfig(ProtocolType.TCP)
        )
        self.handlers[ProtocolType.UDP] = UDPProtocolHandler(
            ProtocolConfig(ProtocolType.UDP)
        )

    def detect_protocol(self, target_url: str) -> ProtocolType:
        """Detect protocol from URL"""
        if target_url.startswith("wss://"):
            return ProtocolType.WEBSOCKETS
        elif target_url.startswith("ws://"):
            return ProtocolType.WEBSOCKET
        elif target_url.startswith("https://"):
            return ProtocolType.HTTPS
        elif target_url.startswith("http://"):
            return ProtocolType.HTTP
        else:
            # Default to HTTP for unknown protocols
            return ProtocolType.HTTP

    def get_handler(self, protocol_type: ProtocolType) -> ProtocolHandler:
        """Get protocol handler"""
        if protocol_type not in self.handlers:
            raise HTTPException(
                status_code=400, detail=f"Protocol {protocol_type} not supported"
            )
        return self.handlers[protocol_type]

    async def proxy_request(self, target_url: str, request_data: bytes) -> bytes:
        """Proxy request using appropriate protocol"""
        protocol_type = self.detect_protocol(target_url)
        handler = self.get_handler(protocol_type)

        # Parse target URL
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        target_host = parsed.hostname or "localhost"
        target_port = parsed.port or (
            443
            if protocol_type in [ProtocolType.HTTPS, ProtocolType.WEBSOCKETS]
            else 80
        )

        context = ProtocolContext(str(uuid.uuid4()), handler.config)

        try:
            # Connect to target
            connection = await handler.connect(target_host, target_port)

            # Send request and get response
            response_data = await handler.send_request(connection, request_data)

            # Close connection
            await handler.close(connection)

            return response_data

        except Exception as e:
            context.error = e
            logger.error(f"Protocol proxy failed: {e}")
            raise HTTPException(status_code=500, detail=f"Protocol proxy failed: {e}")


class ProtocolProxy:
    """Multi-protocol proxy implementation"""

    def __init__(self):
        self.router = ProtocolRouter()
        self.stats = {
            "requests": 0,
            "errors": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "response_times": [],
        }

    async def proxy_http_request(
        self, target_url: str, method: str, headers: dict, body: bytes
    ) -> bytes:
        """Proxy HTTP request"""
        # Build HTTP request
        request_line = f"{method.upper()} {target_url} HTTP/1.1\r\n"
        header_lines = ""
        for key, value in headers.items():
            header_lines += f"{key}: {value}\r\n"
        request_data = f"{request_line}{header_lines}\r\n".encode() + body

        response_data = await self.router.proxy_request(target_url, request_data)
        return response_data

    async def proxy_websocket_request(self, target_url: str, message: bytes) -> bytes:
        """Proxy WebSocket request"""
        response_data = await self.router.proxy_request(target_url, message)
        return response_data

    async def proxy_tcp_request(
        self, target_host: str, target_port: int, data: bytes
    ) -> bytes:
        """Proxy TCP request"""
        target_url = f"tcp://{target_host}:{target_port}"
        response_data = await self.router.proxy_request(target_url, data)
        return response_data

    async def proxy_udp_request(
        self, target_host: str, target_port: int, data: bytes
    ) -> bytes:
        """Proxy UDP request"""
        target_url = f"udp://{target_host}:{target_port}"
        response_data = await self.router.proxy_request(target_url, data)
        return response_data

    def get_stats(self) -> dict:
        """Get protocol proxy statistics"""
        return self.stats


# Global protocol proxy instance
protocol_proxy = ProtocolProxy()


def get_protocol_proxy() -> ProtocolProxy:
    """Get the global protocol proxy instance"""
    return protocol_proxy

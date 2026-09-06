from enum import Enum
from typing import Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ProxyRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "url": "https://api.example.com/data",
                "method": "GET",
                "headers": {"Accept": "application/json"},
            }
        }
    )

    url: str = Field(..., description="Target URL to proxy")
    method: HTTPMethod = Field(HTTPMethod.GET, description="HTTP method")
    headers: Optional[Dict[str, str]] = Field(None, description="Custom headers")
    body: Optional[str] = Field(None, description="Request body")


class ProxyResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status_code": 200,
                "content": '{"data": "example"}',
                "headers": {"content-type": "application/json"},
                "content_type": "application/json",
            }
        }
    )

    status_code: int
    content: str
    headers: Dict[str, str]
    content_type: Optional[str]


class HealthResponse(BaseModel):
    model_config = ConfigDict()

    status: str
    version: str
    timestamp: str


class WebSocketProxyRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "target_url": "ws://example.com/ws",
                "message": "hello",
            }
        }
    )

    target_url: str = Field(..., description="Target WebSocket URL")
    message: str = Field(..., description="Message to send")


class TCPProxyRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "host": "127.0.0.1",
                "port": 1234,
                "data": "base64-or-plain",
            }
        }
    )

    host: str = Field(..., description="Target TCP host")
    port: int = Field(..., ge=1, le=65535, description="Target TCP port")
    data: str = Field(..., description="Data to send")


class UDPProxyRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "host": "127.0.0.1",
                "port": 1234,
                "data": "base64-or-plain",
            }
        }
    )

    host: str = Field(..., description="Target UDP host")
    port: int = Field(..., ge=1, le=65535, description="Target UDP port")
    data: str = Field(..., description="Datagram payload")


class StructuredLogEntry(BaseModel):
    timestamp: str
    level: str
    logger: str
    message: str
    path: Optional[str] = None
    line: Optional[int] = None
    exception: Optional[str] = None

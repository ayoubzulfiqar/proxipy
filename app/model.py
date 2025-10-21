from enum import Enum
from typing import Dict, Optional

from pydantic import BaseModel, Field


class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ProxyRequest(BaseModel):
    url: str = Field(..., description="Target URL to proxy")
    method: HTTPMethod = Field(HTTPMethod.GET, description="HTTP method")
    headers: Optional[Dict[str, str]] = Field(None, description="Custom headers")
    body: Optional[str] = Field(None, description="Request body")

    class Config:
        schema_extra = {
            "example": {
                "url": "https://api.example.com/data",
                "method": "GET",
                "headers": {"Accept": "application/json"},
            }
        }


class ProxyResponse(BaseModel):
    status_code: int
    content: str
    headers: Dict[str, str]
    content_type: Optional[str]

    class Config:
        schema_extra = {
            "example": {
                "status_code": 200,
                "content": '{"data": "example"}',
                "headers": {"content-type": "application/json"},
                "content_type": "application/json",
            }
        }


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str

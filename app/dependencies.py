from typing import Generator

from app.config import settings
from app.load_balancer import LoadBalancer, LoadBalancerConfig, LoadBalancingAlgorithm
from app.middleware import get_middleware_pipeline
from app.rate_limiter import get_rate_limiter
from app.security import EnhancedSecurityMiddleware
from app.security import security as _security


def get_settings_dep():
    return settings


def get_security() -> EnhancedSecurityMiddleware:
    return _security


def get_protocol_proxy():
    from app.protocols import get_protocol_proxy as _get_protocol_proxy

    return _get_protocol_proxy()


def get_metrics():
    from app.app import metrics as _metrics

    return _metrics


def get_load_balancer():
    from app.load_balancer import load_balancer

    return load_balancer


def get_rate_limiter_dep():
    return get_rate_limiter()


def get_middleware_pipeline_dep():
    return get_middleware_pipeline()


def ensure_load_balancer() -> LoadBalancer:
    lb = get_load_balancer()
    if lb is None:
        raise RuntimeError("Load balancer is not initialized")
    return lb


def build_test_load_balancer() -> LoadBalancer:
    config = LoadBalancerConfig(
        algorithm=LoadBalancingAlgorithm.ROUND_ROBIN,
        session_stickiness=False,
        enable_circuit_breaker=True,
        circuit_breaker_failure_threshold=3,
        circuit_breaker_recovery_timeout=60.0,
    )
    return LoadBalancer(config)

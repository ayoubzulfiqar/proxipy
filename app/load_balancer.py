import asyncio
import hashlib
import logging
import random
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class ServerState(str, Enum):
    """Server health states"""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DRAINING = "draining"
    MAINTENANCE = "maintenance"


class LoadBalancingAlgorithm(str, Enum):
    """Available load balancing algorithms"""

    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    LEAST_RESPONSE_TIME = "least_response_time"
    SOURCE_IP_HASH = "source_ip_hash"
    URI_HASH = "uri_hash"
    HEADER_HASH = "header_hash"
    RANDOM = "random"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    WEIGHTED_LEAST_CONNECTIONS = "weighted_least_connections"


@dataclass
class BackendServer:
    """Represents a backend server"""

    host: str
    port: int
    protocol: str = "http"
    weight: int = 1
    max_connections: int = 100
    state: ServerState = ServerState.HEALTHY
    current_connections: int = 0
    response_time: float = 0.0
    last_health_check: float = 0.0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    session_stickiness: Dict[str, str] = field(
        default_factory=dict
    )  # session_id -> server_id
    server_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def url(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}"

    @property
    def is_healthy(self) -> bool:
        return (
            self.state == ServerState.HEALTHY
            and self.current_connections < self.max_connections
        )

    def increment_connections(self):
        self.current_connections += 1

    def decrement_connections(self):
        self.current_connections = max(0, self.current_connections - 1)

    def update_response_time(self, response_time: float):
        # Exponential moving average
        alpha = 0.3
        self.response_time = alpha * response_time + (1 - alpha) * self.response_time

    def mark_success(self):
        self.consecutive_failures = 0
        self.consecutive_successes += 1
        self.state = ServerState.HEALTHY

    def mark_failure(self):
        self.consecutive_failures += 1
        self.consecutive_successes = 0
        if self.consecutive_failures >= 3:
            self.state = ServerState.UNHEALTHY


@dataclass
class HealthCheckConfig:
    """Health check configuration"""

    protocol: str = "http"
    path: str = "/health"
    port: Optional[int] = None
    interval: float = 30.0
    timeout: float = 5.0
    healthy_threshold: int = 2
    unhealthy_threshold: int = 3
    expected_status: int = 200


@dataclass
class LoadBalancerConfig:
    """Load balancer configuration"""

    algorithm: LoadBalancingAlgorithm = LoadBalancingAlgorithm.ROUND_ROBIN
    health_check: HealthCheckConfig = field(default_factory=HealthCheckConfig)
    session_stickiness: bool = False
    session_cookie_name: str = "PROXIPY_SESSION"
    session_timeout: int = 3600  # 1 hour
    enable_circuit_breaker: bool = True
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: float = 60.0


class LoadBalancerStrategy(ABC):
    """Abstract base class for load balancing strategies"""

    def __init__(self, servers: List[BackendServer], config: LoadBalancerConfig):
        self.servers = servers
        self.config = config
        self.current_index = 0
        self.request_count = defaultdict(int)

    @abstractmethod
    def select_server(self, request_info: Dict[str, Any]) -> Optional[BackendServer]:
        """Select a server based on the strategy"""
        pass


class RoundRobinStrategy(LoadBalancerStrategy):
    """Round robin load balancing"""

    def select_server(self, request_info: Dict[str, Any]) -> Optional[BackendServer]:
        healthy_servers = [s for s in self.servers if s.is_healthy]
        if not healthy_servers:
            return None

        for _ in range(len(healthy_servers)):
            server = healthy_servers[self.current_index % len(healthy_servers)]
            self.current_index = (self.current_index + 1) % len(healthy_servers)

            if server.is_healthy:
                return server

        return None


class WeightedRoundRobinStrategy(LoadBalancerStrategy):
    """Weighted round robin load balancing"""

    def select_server(self, request_info: Dict[str, Any]) -> Optional[BackendServer]:
        healthy_servers = [s for s in self.servers if s.is_healthy]
        if not healthy_servers:
            return None

        # Create a weighted list of servers
        weighted_servers = []
        for server in healthy_servers:
            weighted_servers.extend([server] * server.weight)

        if not weighted_servers:
            return None

        server = weighted_servers[self.current_index % len(weighted_servers)]
        self.current_index = (self.current_index + 1) % len(weighted_servers)
        return server


class LeastConnectionsStrategy(LoadBalancerStrategy):
    """Least connections load balancing"""

    def select_server(self, request_info: Dict[str, Any]) -> Optional[BackendServer]:
        healthy_servers = [s for s in self.servers if s.is_healthy]
        if not healthy_servers:
            return None

        return min(healthy_servers, key=lambda s: s.current_connections)


class WeightedLeastConnectionsStrategy(LoadBalancerStrategy):
    """Weighted least connections load balancing"""

    def select_server(self, request_info: Dict[str, Any]) -> Optional[BackendServer]:
        healthy_servers = [s for s in self.servers if s.is_healthy]
        if not healthy_servers:
            return None

        # Calculate connections per weight ratio
        def connections_per_weight(server: BackendServer) -> float:
            return server.current_connections / server.weight

        return min(healthy_servers, key=connections_per_weight)


class LeastResponseTimeStrategy(LoadBalancerStrategy):
    """Least response time load balancing"""

    def select_server(self, request_info: Dict[str, Any]) -> Optional[BackendServer]:
        healthy_servers = [s for s in self.servers if s.is_healthy]
        if not healthy_servers:
            return None

        return min(healthy_servers, key=lambda s: s.response_time)


class SourceIPHashStrategy(LoadBalancerStrategy):
    """Source IP hash load balancing for session stickiness"""

    def select_server(self, request_info: Dict[str, Any]) -> Optional[BackendServer]:
        client_ip = request_info.get("client_ip", "")
        if not client_ip:
            return None

        healthy_servers = [s for s in self.servers if s.is_healthy]
        if not healthy_servers:
            return None

        # Hash the client IP to select a server
        hash_value = int(hashlib.md5(client_ip.encode()).hexdigest(), 16)
        server_index = hash_value % len(healthy_servers)
        return healthy_servers[server_index]


class URIHashStrategy(LoadBalancerStrategy):
    """URI hash load balancing"""

    def select_server(self, request_info: Dict[str, Any]) -> Optional[BackendServer]:
        uri = request_info.get("uri", "")
        if not uri:
            return None

        healthy_servers = [s for s in self.servers if s.is_healthy]
        if not healthy_servers:
            return None

        # Hash the URI to select a server
        hash_value = int(hashlib.md5(uri.encode()).hexdigest(), 16)
        server_index = hash_value % len(healthy_servers)
        return healthy_servers[server_index]


class HeaderHashStrategy(LoadBalancerStrategy):
    """Header hash load balancing"""

    def select_server(self, request_info: Dict[str, Any]) -> Optional[BackendServer]:
        header_name = request_info.get("hash_header_name", "X-Session-ID")
        header_value = request_info.get("headers", {}).get(header_name)

        if not header_value:
            return None

        healthy_servers = [s for s in self.servers if s.is_healthy]
        if not healthy_servers:
            return None

        # Hash the header value to select a server
        hash_value = int(hashlib.md5(header_value.encode()).hexdigest(), 16)
        server_index = hash_value % len(healthy_servers)
        return healthy_servers[server_index]


class RandomStrategy(LoadBalancerStrategy):
    """Random load balancing"""

    def select_server(self, request_info: Dict[str, Any]) -> Optional[BackendServer]:
        healthy_servers = [s for s in self.servers if s.is_healthy]
        if not healthy_servers:
            return None

        return random.choice(healthy_servers)


class LoadBalancer:
    """Main load balancer implementation"""

    def __init__(self, config: LoadBalancerConfig):
        self.config = config
        self.servers: List[BackendServer] = []
        self.strategy: Optional[LoadBalancerStrategy] = None
        self.health_check_task: Optional[asyncio.Task] = None
        self.circuit_breaker_states: Dict[str, Dict[str, Any]] = {}
        self.session_store: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

        # Initialize strategy
        self._init_strategy()

    def _init_strategy(self):
        """Initialize the load balancing strategy"""
        strategies = {
            LoadBalancingAlgorithm.ROUND_ROBIN: RoundRobinStrategy,
            LoadBalancingAlgorithm.WEIGHTED_ROUND_ROBIN: WeightedRoundRobinStrategy,
            LoadBalancingAlgorithm.LEAST_CONNECTIONS: LeastConnectionsStrategy,
            LoadBalancingAlgorithm.WEIGHTED_LEAST_CONNECTIONS: WeightedLeastConnectionsStrategy,
            LoadBalancingAlgorithm.LEAST_RESPONSE_TIME: LeastResponseTimeStrategy,
            LoadBalancingAlgorithm.SOURCE_IP_HASH: SourceIPHashStrategy,
            LoadBalancingAlgorithm.URI_HASH: URIHashStrategy,
            LoadBalancingAlgorithm.HEADER_HASH: HeaderHashStrategy,
            LoadBalancingAlgorithm.RANDOM: RandomStrategy,
        }

        strategy_class = strategies.get(self.config.algorithm, RoundRobinStrategy)
        self.strategy = strategy_class(self.servers, self.config)

    def add_server(self, server: BackendServer):
        """Add a server to the load balancer"""
        self.servers.append(server)
        self._init_strategy()  # Reinitialize strategy with new server

    def remove_server(self, server_id: str):
        """Remove a server from the load balancer"""
        self.servers = [s for s in self.servers if s.server_id != server_id]
        self._init_strategy()  # Reinitialize strategy without removed server

    def update_server_weight(self, server_id: str, weight: int):
        """Update server weight"""
        for server in self.servers:
            if server.server_id == server_id:
                server.weight = weight
                break
        self._init_strategy()  # Reinitialize strategy with updated weights

    def get_server_stats(self) -> List[Dict[str, Any]]:
        """Get statistics for all servers"""
        return [
            {
                "server_id": server.server_id,
                "url": server.url,
                "weight": server.weight,
                "state": server.state.value,
                "current_connections": server.current_connections,
                "max_connections": server.max_connections,
                "response_time": server.response_time,
                "consecutive_failures": server.consecutive_failures,
                "consecutive_successes": server.consecutive_successes,
                "is_healthy": server.is_healthy,
            }
            for server in self.servers
        ]

    async def select_server(
        self, request_info: Dict[str, Any]
    ) -> Optional[BackendServer]:
        """Select a server for the request"""
        if not self.strategy:
            return None

        # Check circuit breaker
        if self.config.enable_circuit_breaker:
            server = await self._select_with_circuit_breaker(request_info)
        else:
            server = self.strategy.select_server(request_info)

        if server:
            server.increment_connections()

        return server

    async def _select_with_circuit_breaker(
        self, request_info: Dict[str, Any]
    ) -> Optional[BackendServer]:
        """Select server with circuit breaker protection"""
        healthy_servers = [s for s in self.servers if s.is_healthy]
        if not healthy_servers:
            return None

        # Check circuit breaker state for each server
        available_servers = []
        for server in healthy_servers:
            circuit_state = self._get_circuit_state(server.server_id)

            if circuit_state["state"] == "closed":
                available_servers.append(server)
            elif circuit_state["state"] == "half_open":
                # Allow one request to test recovery
                if not circuit_state.get("testing", False):
                    circuit_state["testing"] = True
                    available_servers.append(server)

        if not available_servers:
            return None

        # Use strategy to select from available servers
        if self.strategy:
            original_servers = self.strategy.servers
            self.strategy.servers = available_servers
            selected_server = self.strategy.select_server(request_info)
            self.strategy.servers = original_servers
            return selected_server

        return None

    def _get_circuit_state(self, server_id: str) -> Dict[str, Any]:
        """Get circuit breaker state for a server"""
        if server_id not in self.circuit_breaker_states:
            self.circuit_breaker_states[server_id] = {
                "state": "closed",  # closed, open, half_open
                "failure_count": 0,
                "last_failure_time": 0,
                "testing": False,
            }

        state = self.circuit_breaker_states[server_id]

        # Check if we should transition from open to half_open
        if state["state"] == "open":
            if (
                time.time() - state["last_failure_time"]
                > self.config.circuit_breaker_recovery_timeout
            ):
                state["state"] = "half_open"
                state["failure_count"] = 0

        return state

    def record_success(self, server_id: str):
        """Record a successful request"""
        server = self._get_server_by_id(server_id)
        if server:
            server.mark_success()

        # Reset circuit breaker on success
        if server_id in self.circuit_breaker_states:
            self.circuit_breaker_states[server_id]["failure_count"] = 0
            self.circuit_breaker_states[server_id]["state"] = "closed"
            self.circuit_breaker_states[server_id]["testing"] = False

    def record_failure(self, server_id: str):
        """Record a failed request"""
        server = self._get_server_by_id(server_id)
        if server:
            server.mark_failure()

        # Update circuit breaker
        if server_id in self.circuit_breaker_states:
            state = self.circuit_breaker_states[server_id]
            state["failure_count"] += 1
            state["last_failure_time"] = time.time()

            if state["failure_count"] >= self.config.circuit_breaker_failure_threshold:
                state["state"] = "open"

    def _get_server_by_id(self, server_id: str) -> Optional[BackendServer]:
        """Get server by ID"""
        for server in self.servers:
            if server.server_id == server_id:
                return server
        return None

    async def start_health_checks(self):
        """Start background health check task"""
        if self.health_check_task:
            return

        self.health_check_task = asyncio.create_task(self._health_check_loop())
        logger.info("Health check task started")

    async def stop_health_checks(self):
        """Stop background health check task"""
        if self.health_check_task:
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass
            self.health_check_task = None
            logger.info("Health check task stopped")

    async def _health_check_loop(self):
        """Background health check loop"""
        while True:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self.config.health_check.interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")
                await asyncio.sleep(5)  # Wait before retrying

    async def _perform_health_checks(self):
        """Perform health checks on all servers"""

        async def check_server(server: BackendServer):
            try:
                health_url = self._build_health_check_url(server)
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        health_url,
                        timeout=self.config.health_check.timeout,
                        follow_redirects=True,
                    )

                    if response.status_code == self.config.health_check.expected_status:
                        server.mark_success()
                        logger.debug(f"Health check passed for {server.url}")
                    else:
                        server.mark_failure()
                        logger.warning(
                            f"Health check failed for {server.url}: {response.status_code}"
                        )

            except Exception as e:
                server.mark_failure()
                logger.warning(f"Health check failed for {server.url}: {e}")

        # Perform health checks concurrently
        tasks = [check_server(server) for server in self.servers]
        await asyncio.gather(*tasks, return_exceptions=True)

    def _build_health_check_url(self, server: BackendServer) -> str:
        """Build health check URL for a server"""
        health_check = self.config.health_check
        port = health_check.port or server.port
        path = health_check.path

        return f"{health_check.protocol}://{server.host}:{port}{path}"

    def get_load_balancer_stats(self) -> Dict[str, Any]:
        """Get load balancer statistics"""
        return {
            "algorithm": self.config.algorithm.value,
            "total_servers": len(self.servers),
            "healthy_servers": len([s for s in self.servers if s.is_healthy]),
            "unhealthy_servers": len([s for s in self.servers if not s.is_healthy]),
            "session_stickiness_enabled": self.config.session_stickiness,
            "circuit_breaker_enabled": self.config.enable_circuit_breaker,
            "server_stats": self.get_server_stats(),
        }


# Global load balancer instance
load_balancer: Optional[LoadBalancer] = None


def get_load_balancer() -> Optional[LoadBalancer]:
    """Get the global load balancer instance"""
    return load_balancer


def initialize_load_balancer(
    config: Optional[LoadBalancerConfig] = None,
) -> LoadBalancer:
    """Initialize the global load balancer instance"""
    global load_balancer

    if load_balancer is None:
        if config is None:
            config = LoadBalancerConfig()
        load_balancer = LoadBalancer(config)

    return load_balancer

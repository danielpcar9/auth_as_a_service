"""
Business observability metrics backed by Redis sorted sets.

Each event is stored as a member in a sorted set with its Unix timestamp
as the score.  This gives us efficient sliding-window counts without
external dependencies beyond the Redis instance the project already uses.
"""

import time
import uuid

from src.core.redis import redis_client

# Default sliding window for dashboard queries
DEFAULT_WINDOW_SECONDS = 60


class MetricsService:
    """Lightweight business metrics using Redis sorted sets."""

    _PREFIX = "metrics"

    def _key(self, event_type: str) -> str:
        return f"{self._PREFIX}:{event_type}"

    def record_event(self, event_type: str) -> None:
        """Record a timestamped event (e.g. 'login_success')."""
        now = time.time()
        # uuid4 suffix guarantees uniqueness so ZADD never overwrites
        member = f"{now}:{uuid.uuid4().hex[:8]}"
        key = self._key(event_type)
        redis_client.zadd(key, {member: now})
        # Prune entries older than 5 minutes to keep memory bounded
        redis_client.zremrangebyscore(key, "-inf", now - 300)

    def count(self, event_type: str, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> int:
        """Count events within the sliding window."""
        now = time.time()
        return redis_client.zcount(
            self._key(event_type), now - window_seconds, now
        )

    def get_dashboard(self, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> dict:
        """Return all business metrics for the given window."""
        return {
            "window_seconds": window_seconds,
            "login_success": self.count("login_success", window_seconds),
            "login_failure": self.count("login_failure", window_seconds),
            "fraud_blocked": self.count("fraud_blocked", window_seconds),
            "rate_limited": self.count("rate_limited", window_seconds),
        }


# Singleton
metrics_service = MetricsService()

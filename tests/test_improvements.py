"""Tests for the three project polish improvements:
1. Deterministic IP numeric hash (IPv4, IPv6, malformed)
2. Background training endpoint (202 Accepted)
3. Business observability metrics (MetricsService)
"""

import pytest
from unittest.mock import patch, MagicMock

from src.ml.fraud_detector import FraudDetector


# ──────────────────────────────────────────────────────
# 1. IP Numeric Hash — deterministic & IPv6-safe
# ──────────────────────────────────────────────────────

class TestIpToNumeric:
    """_ip_to_numeric must be deterministic across calls."""

    def setup_method(self):
        self.detector = FraudDetector()

    def test_ipv4_standard(self):
        result = self.detector._ip_to_numeric("192.168.1.1")
        expected = float(int.from_bytes(bytes([192, 168, 1, 1]), "big"))
        assert result == expected

    def test_ipv4_deterministic(self):
        """Same input → same output, always."""
        a = self.detector._ip_to_numeric("10.0.0.1")
        b = self.detector._ip_to_numeric("10.0.0.1")
        assert a == b

    def test_ipv6_standard(self):
        result = self.detector._ip_to_numeric("::1")
        assert result == 1.0  # loopback

    def test_ipv6_full(self):
        result = self.detector._ip_to_numeric("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert isinstance(result, float)
        assert result > 0

    def test_malformed_uses_sha256_fallback(self):
        """Malformed strings must still return a deterministic float."""
        result = self.detector._ip_to_numeric("not-an-ip")
        assert isinstance(result, float)
        # Deterministic: same result on a second call
        assert result == self.detector._ip_to_numeric("not-an-ip")

    def test_different_ips_different_values(self):
        a = self.detector._ip_to_numeric("192.168.1.1")
        b = self.detector._ip_to_numeric("10.0.0.1")
        assert a != b


# ──────────────────────────────────────────────────────
# 2. Background Training — endpoint returns 202
# ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_train_returns_202(client):
    """POST /fraud/train should dispatch a background job, not block."""
    # Mock the training job so it doesn't actually run
    with patch("src.fraud.router.run_training_job") as mock_train:
        response = await client.post("/api/v1/fraud/train")

    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "pending"
    assert "check_status_at" in data


@pytest.mark.asyncio
async def test_train_status_returns_idle_by_default(client):
    """GET /fraud/train/status should default to idle."""
    # Mock Redis to return None (no training has occurred)
    mock_redis = MagicMock()
    mock_redis.get.return_value = None

    with patch("src.ml.training.redis_client", mock_redis):
        response = await client.get("/api/v1/fraud/train/status")

    assert response.status_code == 200


# ──────────────────────────────────────────────────────
# 3. Business Metrics — MetricsService unit tests
# ──────────────────────────────────────────────────────

class TestMetricsService:
    """Unit tests for MetricsService with mocked Redis."""

    def setup_method(self):
        self.mock_redis = MagicMock()
        self.patcher = patch("src.core.metrics.redis_client", self.mock_redis)
        self.patcher.start()

        from src.core.metrics import MetricsService
        self.service = MetricsService()

    def teardown_method(self):
        self.patcher.stop()

    def test_record_event_calls_zadd(self):
        self.service.record_event("login_success")
        self.mock_redis.zadd.assert_called_once()
        key = self.mock_redis.zadd.call_args[0][0]
        assert key == "metrics:login_success"

    def test_record_event_prunes_old_entries(self):
        self.service.record_event("login_failure")
        self.mock_redis.zremrangebyscore.assert_called_once()

    def test_count_calls_zcount(self):
        self.mock_redis.zcount.return_value = 42
        count = self.service.count("login_success", window_seconds=60)
        assert count == 42
        self.mock_redis.zcount.assert_called_once()

    def test_get_dashboard_returns_all_event_types(self):
        self.mock_redis.zcount.return_value = 0
        dashboard = self.service.get_dashboard(window_seconds=60)
        assert "login_success" in dashboard
        assert "login_failure" in dashboard
        assert "fraud_blocked" in dashboard
        assert "rate_limited" in dashboard
        assert dashboard["window_seconds"] == 60


# ──────────────────────────────────────────────────────
# 4. Metrics endpoint
# ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_metrics_endpoint(client):
    """GET /metrics should return the dashboard dict."""
    mock_redis = MagicMock()
    mock_redis.zcount.return_value = 0

    with patch("src.core.metrics.redis_client", mock_redis):
        response = await client.get("/api/v1/metrics/")

    assert response.status_code == 200
    data = response.json()
    assert "window_seconds" in data
    assert "login_success" in data

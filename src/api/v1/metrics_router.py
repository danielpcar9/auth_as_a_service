"""Metrics API endpoint for business observability."""

from fastapi import APIRouter, Query

from src.core.metrics import metrics_service

router = APIRouter(tags=["metrics"])


@router.get(
    "/",
    summary="Business metrics dashboard",
    description="Returns sliding-window counts of login events "
                "(success, failure, fraud-blocked, rate-limited).",
)
def get_metrics(
    window: int = Query(
        default=60,
        ge=10,
        le=3600,
        description="Sliding window in seconds (default 60)",
    ),
):
    """Return business observability metrics."""
    return metrics_service.get_dashboard(window_seconds=window)

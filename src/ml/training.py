"""
Background training job for the fraud detection model.

Decouples ML training from the API event loop by running the CPU-bound
work in a thread pool.  Training status is tracked in Redis so the API
can report progress via GET /train/status.
"""

import asyncio
import logging
from datetime import datetime, UTC

import numpy as np
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, col

from src.core.redis import redis_client
from src.fraud.models import LoginAttempt
from src.ml.fraud_detector import fraud_detector

logger = logging.getLogger(__name__)

# Redis keys
_STATUS_KEY = "training:status"
_LAST_RUN_KEY = "training:last_run"
_SAMPLES_KEY = "training:samples_used"
_ERROR_KEY = "training:error"


def _get_training_status() -> dict:
    """Read current training status from Redis."""
    return {
        "status": redis_client.get(_STATUS_KEY) or "idle",
        "last_run": redis_client.get(_LAST_RUN_KEY),
        "samples_used": int(redis_client.get(_SAMPLES_KEY) or 0),
        "error": redis_client.get(_ERROR_KEY),
    }


async def _fetch_training_data(
    db: AsyncSession, limit: int = 10_000
) -> list[LoginAttempt]:
    """Fetch historical login attempts for training."""
    stmt = (
        select(LoginAttempt)
        .order_by(col(LoginAttempt.attempted_at).desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


def _extract_and_train(attempts: list[LoginAttempt]) -> int:
    """CPU-bound: extract features and fit the Isolation Forest.

    Returns the number of samples used.
    """
    features_list = []
    for attempt in attempts:
        features = fraud_detector.extract_features(
            email=attempt.email,
            ip_address=attempt.ip_address,
            user_agent=attempt.user_agent,
            timestamp=attempt.attempted_at,
        )
        features_list.append(list(features.values()))

    X = np.array(features_list)
    fraud_detector.train(X)
    return len(features_list)


async def run_training_job(db: AsyncSession, min_samples: int = 100) -> None:
    """Full training pipeline — designed to be called as a BackgroundTask.

    1. Sets status to 'running' in Redis.
    2. Fetches data (async I/O).
    3. Trains model in a thread pool (CPU-bound).
    4. Updates status to 'completed' or 'failed'.
    """
    redis_client.set(_STATUS_KEY, "running")
    redis_client.delete(_ERROR_KEY)

    try:
        attempts = await _fetch_training_data(db)

        if len(attempts) < min_samples:
            raise ValueError(
                f"Not enough data for training. Have {len(attempts)}, "
                f"need at least {min_samples}."
            )

        # Offload CPU-bound training to a thread pool
        loop = asyncio.get_running_loop()
        samples_used = await loop.run_in_executor(
            None, _extract_and_train, attempts
        )

        redis_client.set(_STATUS_KEY, "completed")
        redis_client.set(_LAST_RUN_KEY, datetime.now(UTC).isoformat())
        redis_client.set(_SAMPLES_KEY, str(samples_used))
        logger.info("Training completed with %d samples", samples_used)

    except Exception as exc:
        redis_client.set(_STATUS_KEY, "failed")
        redis_client.set(_ERROR_KEY, str(exc))
        logger.exception("Training job failed: %s", exc)

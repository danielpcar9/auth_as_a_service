from datetime import datetime, UTC
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, col

from src.fraud.models import LoginAttempt
from src.ml.fraud_detector import fraud_detector


class FraudService:
    """Domain service for handling fraud operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        # Inject the underlying ML model (could also be properly injected, but it's CPU bound and singleton)
        self.detector = fraud_detector

    def predict_fraud(self, email: str, ip_address: str, user_agent: str | None = None) -> float:
        """Run ML inference directly"""
        prediction = self.detector.predict(email, ip_address, user_agent)
        return prediction.get("fraud_score", 0.0)

    async def log_attempt(
        self,
        email: str,
        ip_address: str,
        success: bool,
        fraud_score: float,
        user_agent: str | None = None,
        user_id: int | None = None,
    ) -> LoginAttempt:
        """Log a login attempt for future ML training and audit"""
        now = datetime.now(UTC)
        attempt = LoginAttempt(
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            fraud_score=fraud_score,
            hour_of_day=now.hour,
            day_of_week=now.weekday()
        )
        self.db.add(attempt)
        await self.db.commit()
        await self.db.refresh(attempt)
        return attempt

    async def get_all_for_training(self, limit: int = 10000) -> list[LoginAttempt]:
        """Fetch historical records for retraining the isolation forest"""
        stmt = (
            select(LoginAttempt)
            .order_by(col(LoginAttempt.attempted_at).desc())
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    def retrain_model(self, features_list: list[list[float | int]]) -> None:
        """Retrain the ML model"""
        import numpy as np
        X = np.array(features_list)
        self.detector.train(X)

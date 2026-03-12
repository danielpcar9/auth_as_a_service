from datetime import datetime, timedelta
from typing import Sequence
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from src.crud.base import CRUDBase
from src.models.login_attempt import LoginAttempt
from src.schemas.fraud import LoginAttemptCreate, LoginAttemptResponse


class CRUDLoginAttempt(CRUDBase[LoginAttempt, LoginAttemptCreate, LoginAttemptResponse]):
    """LoginAttempt-specific CRUD operations"""
    
    async def get_recent_attempts_by_email(
        self, 
        db: AsyncSession, 
        *, 
        email: str, 
        minutes: int = 60
    ) -> Sequence[LoginAttempt]:
        """Get recent login attempts for an email within time window"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        stmt = (
            select(LoginAttempt)
            .where(
                LoginAttempt.email == email,
                LoginAttempt.attempted_at >= cutoff_time
            )
            .order_by(LoginAttempt.attempted_at.desc())
        )
        result = await db.execute(stmt)
        return result.scalars().all()
    
    async def get_recent_attempts_by_ip(
        self, 
        db: AsyncSession, 
        *, 
        ip_address: str, 
        minutes: int = 60
    ) -> Sequence[LoginAttempt]:
        """Get recent login attempts from an IP within time window"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        stmt = (
            select(LoginAttempt)
            .where(
                LoginAttempt.ip_address == ip_address,
                LoginAttempt.attempted_at >= cutoff_time
            )
            .order_by(LoginAttempt.attempted_at.desc())
        )
        result = await db.execute(stmt)
        return result.scalars().all()
    
    async def count_failed_attempts(
        self, 
        db: AsyncSession, 
        *, 
        email: str, 
        minutes: int = 5
    ) -> int:
        """Count failed login attempts for email in time window"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        stmt = (
            select(func.count())
            .select_from(LoginAttempt)
            .where(
                LoginAttempt.email == email,
                LoginAttempt.success.is_(False),
                LoginAttempt.attempted_at >= cutoff_time
            )
        )
        result = await db.execute(stmt)
        return result.scalar_one()
    
    async def get_all_for_training(
        self, 
        db: AsyncSession, 
        limit: int = 10000
    ) -> Sequence[LoginAttempt]:
        """Get all login attempts for ML training"""
        stmt = (
            select(LoginAttempt)
            .order_by(LoginAttempt.attempted_at.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        return result.scalars().all()


# Singleton instance
login_attempt_crud = CRUDLoginAttempt(LoginAttempt)
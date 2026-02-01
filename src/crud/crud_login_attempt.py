from datetime import datetime, timedelta
from typing import Sequence
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from src.crud.base import CRUDBase
from src.models.login_attempt import LoginAttempt
from src.schemas.fraud import LoginAttemptCreate, LoginAttemptResponse


class CRUDLoginAttempt(CRUDBase[LoginAttempt, LoginAttemptCreate, LoginAttemptResponse]):
    """LoginAttempt-specific CRUD operations"""
    
    def get_recent_attempts_by_email(
        self, 
        db: Session, 
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
        return db.execute(stmt).scalars().all()
    
    def get_recent_attempts_by_ip(
        self, 
        db: Session, 
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
        return db.execute(stmt).scalars().all()
    
    def count_failed_attempts(
        self, 
        db: Session, 
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
                LoginAttempt.success == False,
                LoginAttempt.attempted_at >= cutoff_time
            )
        )
        return db.execute(stmt).scalar_one()
    
    def get_all_for_training(
        self, 
        db: Session, 
        limit: int = 10000
    ) -> Sequence[LoginAttempt]:
        """Get all login attempts for ML training"""
        stmt = (
            select(LoginAttempt)
            .order_by(LoginAttempt.attempted_at.desc())
            .limit(limit)
        )
        return db.execute(stmt).scalars().all()


# Singleton instance
login_attempt_crud = CRUDLoginAttempt(LoginAttempt)
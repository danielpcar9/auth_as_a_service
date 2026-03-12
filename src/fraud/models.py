from datetime import datetime, UTC
from typing import TYPE_CHECKING, Optional
from pydantic import EmailStr
from sqlmodel import SQLModel, Field, Relationship

if TYPE_CHECKING:
    from src.users.models import User


class LoginAttemptBase(SQLModel):
    """Shared properties for Login Attempts"""
    email: EmailStr = Field(index=True, max_length=255)
    ip_address: str = Field(max_length=45)
    user_agent: str | None = Field(default=None, max_length=500)
    success: bool
    hour_of_day: int
    day_of_week: int
    fraud_score: float | None = None


class LoginAttempt(LoginAttemptBase, table=True):
    """Database model tracking login attempts"""
    __tablename__ = "login_attempts"

    id: int | None = Field(default=None, primary_key=True, index=True)
    user_id: int | None = Field(default=None, foreign_key="users.id", index=True)

    attempted_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)

    # Relationship
    user: Optional["User"] = Relationship(back_populates="login_attempts")


class FraudPredictionRequest(SQLModel):
    """Input for fraud prediction"""
    email: EmailStr
    ip_address: str
    user_agent: str | None = None


class FraudPredictionResponse(SQLModel):
    """Output for fraud prediction"""
    fraud_score: float
    is_suspicious: bool
    risk_level: str
    features_used: dict[str, float | int]

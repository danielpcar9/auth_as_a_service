from pydantic import BaseModel, Field
from datetime import datetime


class LoginAttemptCreate(BaseModel):
    """Schema for creating login attempt record"""
    email: str
    ip_address: str
    user_agent: str | None = None
    success: bool
    hour_of_day: int
    day_of_week: int


class LoginAttemptResponse(BaseModel):
    """Schema for login attempt response"""
    id: int
    email: str
    ip_address: str
    success: bool
    fraud_score: float | None
    attempted_at: datetime
    
    model_config = {"from_attributes": True}


class FraudPredictionRequest(BaseModel):
    """Schema for fraud prediction request"""
    email: str = Field(..., examples=["user@example.com"])
    ip_address: str = Field(..., examples=["192.168.1.1"])
    user_agent: str | None = Field(None, examples=["Mozilla/5.0..."])


class FraudPredictionResponse(BaseModel):
    """Schema for fraud prediction response"""
    fraud_score: float = Field(..., description="Fraud probability (0-1)", ge=0, le=1)
    is_suspicious: bool = Field(..., description="Whether the attempt is flagged as suspicious")
    risk_level: str = Field(..., description="Risk level: low, medium, high")
    features_used: dict = Field(..., description="Features used for prediction")
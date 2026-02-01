from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float, Index
from sqlalchemy.orm import relationship
from src.db.base import Base


class LoginAttempt(Base):
    """Track login attempts for fraud detection"""
    __tablename__ = "login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Foreign key to user (nullable for failed attempts with non-existent email)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    
    # Attempt details
    email = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)  # IPv6 max length
    user_agent = Column(String(500), nullable=True)
    success = Column(Boolean, nullable=False)
    
    # Fraud detection features
    hour_of_day = Column(Integer, nullable=False)  # 0-23
    day_of_week = Column(Integer, nullable=False)  # 0-6
    fraud_score = Column(Float, nullable=True)  # ML prediction score
    
    # Timestamps
    attempted_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationship
    user = relationship("User", back_populates="login_attempts")
    
    # Composite indexes for queries
    __table_args__ = (
        Index('idx_email_attempted', 'email', 'attempted_at'),
        Index('idx_user_attempted', 'user_id', 'attempted_at'),
    )
    
    def __repr__(self) -> str:
        return f"<LoginAttempt(id={self.id}, email={self.email}, success={self.success})>"
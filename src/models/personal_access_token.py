from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Index
from sqlalchemy.orm import relationship
from src.db.base import Base


class PersonalAccessToken(Base):
    """Personal access token for Sanctum-style multi-device auth"""
    __tablename__ = "personal_access_tokens"

    # Primary Key
    id = Column(Integer, primary_key=True, index=True)

    # Foreign key to user
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # Device/token name (e.g. "MacBook Pro", "iPhone 15", "default")
    name = Column(String(255), nullable=False, default="default")

    # SHA-256 hash of the raw token — raw token is NEVER stored
    token = Column(String(64), unique=True, nullable=False, index=True)

    # Scoped abilities (e.g. ["*"], ["read", "write"])
    abilities = Column(JSON, nullable=False, default=lambda: ["*"])

    # Tracking
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="tokens")

    # Indexes
    __table_args__ = (
        Index("idx_token_hash", "token"),
        Index("idx_pat_user_id", "user_id"),
    )

    @property
    def is_expired(self) -> bool:
        """Check if token has expired"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def can(self, ability: str) -> bool:
        """Check if token has given ability/scope"""
        if "*" in (self.abilities or []):
            return True
        return ability in (self.abilities or [])

    def __repr__(self) -> str:
        return f"<PersonalAccessToken(id={self.id}, name={self.name}, user_id={self.user_id})>"

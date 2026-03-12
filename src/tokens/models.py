from datetime import datetime, UTC
from typing import TYPE_CHECKING
from sqlalchemy import Column, JSON
from sqlmodel import SQLModel, Field, Relationship

if TYPE_CHECKING:
    from src.users.models import User


class TokenBase(SQLModel):
    """Shared properties for Tokens"""
    name: str = Field(default="default", max_length=255)
    abilities: list[str] = Field(default=["*"], sa_column=Column(JSON))


class PersonalAccessToken(TokenBase, table=True):
    """Database model for personal access tokens"""
    __tablename__ = "personal_access_tokens"

    id: int | None = Field(default=None, primary_key=True, index=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    
    # Store hash, never raw token
    token: str = Field(unique=True, index=True, max_length=64)
    
    last_used_at: datetime | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Relationship
    user: "User" = Relationship(back_populates="tokens")

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        # Remove naive UTC dt usage, use aware UTC
        return datetime.now(UTC).replace(tzinfo=None) > self.expires_at.replace(tzinfo=None)

    def can(self, ability: str) -> bool:
        if "*" in (self.abilities or []):
            return True
        return ability in (self.abilities or [])


class TokenResponse(TokenBase):
    """Schema for API returning a new token (includes raw access_token)"""
    access_token: str
    token_type: str = "bearer"
    device_name: str = Field(alias="name")
    expires_at: datetime | None


class TokenListItem(SQLModel):
    """Schema for listing tokens"""
    id: int
    name: str
    abilities: list[str]
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None

from datetime import datetime, UTC
from typing import TYPE_CHECKING
from pydantic import EmailStr
from sqlmodel import SQLModel, Field, Relationship

if TYPE_CHECKING:
    from src.tokens.models import PersonalAccessToken
    from src.fraud.models import LoginAttempt


class UserBase(SQLModel):
    """Shared properties across all User variants"""
    email: EmailStr = Field(unique=True, index=True, max_length=255)
    full_name: str | None = Field(default=None, max_length=255)


class User(UserBase, table=True):
    """Database model for users table"""
    __tablename__ = "users"

    id: int | None = Field(default=None, primary_key=True, index=True)
    hashed_password: str = Field(exclude=True)
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    
    # Using datetime.now(UTC) directly since default_factory accepts a callable
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    deleted_at: datetime | None = Field(default=None)

    # Relationships (type hints via strings prevent circular imports at runtime)
    tokens: list["PersonalAccessToken"] = Relationship(
        back_populates="user", sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    login_attempts: list["LoginAttempt"] = Relationship(
        back_populates="user", sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class UserCreate(UserBase):
    """Schema for creating a new user (input validation)"""
    password: str = Field(min_length=8)


class UserResponse(UserBase):
    """Schema for API responses (output validation)"""
    id: int
    is_active: bool
    created_at: datetime


class UserUpdate(SQLModel):
    """Schema for updating a user (PATCH)"""
    full_name: str | None = Field(default=None, max_length=255)
    email: EmailStr | None = None
    password: str | None = Field(default=None, min_length=8)

from pydantic import BaseModel, EmailStr, Field
from datetime import datetime


class LoginRequest(BaseModel):
    """Schema for login request with device and abilities support"""
    email: EmailStr = Field(..., description="User email", examples=["user@example.com"])
    password: str = Field(..., description="User password", examples=["SecureP@ss123"])
    device_name: str = Field(
        default="default",
        max_length=255,
        description="Name of the device/client",
        examples=["MacBook Pro", "iPhone 15"],
    )
    abilities: list[str] = Field(
        default=["*"],
        description='Token abilities/scopes (e.g. ["read", "write"] or ["*"] for all)',
        examples=[["*"], ["read", "write"]],
    )


class TokenResponse(BaseModel):
    """Schema for token response after login"""
    access_token: str = Field(..., description="Opaque bearer token (only shown once)")
    token_type: str = Field(default="bearer", description="Token type")
    device_name: str = Field(..., description="Device name associated with this token")
    abilities: list[str] = Field(..., description="Token abilities/scopes")
    expires_at: datetime | None = Field(None, description="Token expiration timestamp")


class TokenListItem(BaseModel):
    """Schema for listing active tokens/devices"""
    id: int
    name: str = Field(..., description="Device name")
    abilities: list[str]
    last_used_at: datetime | None
    expires_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenPayload(BaseModel):
    """Schema for JWT token payload (kept for backward compatibility)"""
    sub: str | None = None
    exp: int | None = None
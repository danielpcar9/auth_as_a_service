from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """Schema for login request"""
    email: EmailStr = Field(..., description="User email", examples=["user@example.com"])
    password: str = Field(..., description="User password", examples=["SecureP@ss123"])


class Token(BaseModel):
    """Schema for JWT token response"""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")


class TokenPayload(BaseModel):
    """Schema for JWT token payload"""
    sub: str | None = None  # Subject (user email)
    exp: int | None = None  # Expiration timestamp
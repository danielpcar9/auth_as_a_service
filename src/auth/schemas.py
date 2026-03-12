from sqlmodel import SQLModel, Field
from pydantic import EmailStr

class LoginRequest(SQLModel):
    """Input schema for login endpoint"""
    email: EmailStr
    password: str = Field(min_length=1)
    device_name: str = Field(default="default", max_length=255)
    abilities: list[str] | None = None

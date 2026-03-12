from typing import Annotated
from fastapi import APIRouter, Depends
from src.auth.dependencies import get_current_user
from src.users.models import UserResponse, User

router = APIRouter(tags=["users"])

@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user",
    description="Get currently authenticated user information",
)
async def get_me(
    current_user: Annotated[User, Depends(get_current_user)]
) -> UserResponse:
    """Get current authenticated user"""
    return UserResponse.model_validate(current_user)

from typing import Annotated
from fastapi import APIRouter, Depends
from src.api.deps import get_current_user
from src.schemas.user import UserResponse
from src.models.user import User

router = APIRouter()


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user",
    description="Get currently authenticated user information",
    responses={
        200: {"description": "User information retrieved"},
        401: {"description": "Not authenticated"},
    }
)
def get_me(
    current_user: Annotated[User, Depends(get_current_user)]
) -> UserResponse:
    """Get current authenticated user"""
    return UserResponse.model_validate(current_user)

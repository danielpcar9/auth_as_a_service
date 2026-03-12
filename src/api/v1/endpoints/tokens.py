from typing import Annotated
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db, get_current_user
from src.schemas.auth import TokenListItem
from src.services.auth_service import auth_service
from src.models.user import User

router = APIRouter()


@router.get(
    "/",
    response_model=list[TokenListItem],
    summary="List all active tokens",
    description="Returns all personal access tokens for the current user (all devices)",
    responses={
        200: {"description": "List of active tokens"},
        401: {"description": "Not authenticated"},
    },
)
async def list_tokens(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[TokenListItem]:
    """List all tokens/devices for the authenticated user"""
    tokens = await auth_service.list_tokens(db, current_user)
    return [TokenListItem.model_validate(t) for t in tokens]


@router.delete(
    "/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a specific token",
    description="Delete a specific token by ID (single device logout)",
    responses={
        204: {"description": "Token revoked successfully"},
        401: {"description": "Not authenticated"},
        404: {"description": "Token not found"},
    },
)
async def revoke_token(
    token_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> None:
    """Revoke a single token (logout from one device)"""
    await auth_service.logout(db, token_id=token_id, current_user=current_user)


@router.delete(
    "/",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke all tokens",
    description="Delete all tokens for the current user (logout from all devices)",
    responses={
        204: {"description": "All tokens revoked"},
        401: {"description": "Not authenticated"},
    },
)
async def revoke_all_tokens(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> None:
    """Revoke all tokens (logout everywhere)"""
    await auth_service.logout_all(db, current_user=current_user)

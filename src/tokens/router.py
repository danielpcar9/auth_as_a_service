from typing import Annotated
from fastapi import APIRouter, Depends, status

from src.auth.dependencies import get_current_user
from src.tokens.models import TokenListItem
from src.tokens.service import TokenService
from src.tokens.dependencies import get_token_service
from src.users.models import User

router = APIRouter(tags=["tokens"])

@router.get(
    "/",
    response_model=list[TokenListItem],
    summary="List all active tokens",
    description="Returns all personal access tokens for the current user (all devices)",
)
async def list_tokens(
    current_user: Annotated[User, Depends(get_current_user)],
    service: Annotated[TokenService, Depends(get_token_service)],
) -> list[TokenListItem]:
    """List all tokens/devices for the authenticated user"""
    tokens = await service.list_tokens(current_user.id)
    return [TokenListItem.model_validate(t) for t in tokens]


@router.delete(
    "/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a specific token",
    description="Delete a specific token by ID (single device logout)",
)
async def revoke_token(
    token_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    service: Annotated[TokenService, Depends(get_token_service)],
) -> None:
    """Revoke a single token (logout from one device)"""
    await service.revoke_token(token_id=token_id, user_id=current_user.id)


@router.delete(
    "/",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke all tokens",
    description="Delete all tokens for the current user (logout from all devices)",
)
async def revoke_all_tokens(
    current_user: Annotated[User, Depends(get_current_user)],
    service: Annotated[TokenService, Depends(get_token_service)],
) -> None:
    """Revoke all tokens (logout everywhere)"""
    await service.revoke_all_tokens(user_id=current_user.id)

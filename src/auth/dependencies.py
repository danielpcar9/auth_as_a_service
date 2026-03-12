from typing import Annotated, Callable
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer

from src.users.service import UserService
from src.users.dependencies import get_user_service
from src.tokens.service import TokenService
from src.tokens.dependencies import get_token_service
from src.fraud.service import FraudService
from src.fraud.dependencies import get_fraud_service

from src.auth.service import AuthService
from src.users.models import User
from src.tokens.models import PersonalAccessToken

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_auth_service(
    user_service: Annotated[UserService, Depends(get_user_service)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
    fraud_service: Annotated[FraudService, Depends(get_fraud_service)],
) -> AuthService:
    """Dependency injection factory for AuthService"""
    return AuthService(
        user_service=user_service,
        token_service=token_service,
        fraud_service=fraud_service,
    )


async def _get_token_model(
    token: str,
    token_service: TokenService,
) -> PersonalAccessToken:
    """Internal helper to validate bearer token against DB via TokenService"""
    db_token = await token_service.get_db_token(token)

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if db_token.is_expired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return db_token


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
) -> User:
    """
    Dependency: resolve bearer token → user.
    Uses token_service to look up the token and update last_used_at.
    """
    db_token = await _get_token_model(token, token_service)

    # Note: user is already populated on db_token.user since SQLModel relationship is configured
    # but we need to ensure the user relationship is loaded (or we could fetch the user manually)
    user = db_token.user
    if not user:
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )

    # Update last_used_at
    await token_service.update_last_used(db_token)

    return user


def require_ability(ability: str) -> Callable:
    """
    Factory: returns a dependency that checks if the token has the given ability.
    Usage: @router.get("/admin", dependencies=[Depends(require_ability("admin"))])
    """
    async def dependency(
        token: Annotated[str, Depends(oauth2_scheme)],
        token_service: Annotated[TokenService, Depends(get_token_service)],
    ) -> User:
        db_token = await _get_token_model(token, token_service)

        if not db_token.can(ability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token missing ability: {ability}",
            )

        await token_service.update_last_used(db_token)
        return db_token.user

    return dependency


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str | None:
    """Extract user agent from request"""
    return request.headers.get("User-Agent")

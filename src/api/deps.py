import hashlib
from typing import Annotated, Callable

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from src.db.session import get_db
from src.models.user import User
from src.models.personal_access_token import PersonalAccessToken
from datetime import datetime

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_current_user(
    db: Annotated[Session, Depends(get_db)],
    token: Annotated[str, Depends(oauth2_scheme)]
) -> User:
    """
    Dependency: resolve bearer token → user.
    Hashes the raw token with SHA-256 and looks it up in the DB.
    Updates last_used_at on every authenticated request.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Hash the raw token to look up in DB
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    # Query token + eager-load user
    stmt = (
        select(PersonalAccessToken)
        .options(joinedload(PersonalAccessToken.user))
        .where(PersonalAccessToken.token == token_hash)
    )
    db_token = db.execute(stmt).scalar_one_or_none()

    if db_token is None:
        raise credentials_exception

    # Check expiry
    if db_token.is_expired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check user is active
    if not db_token.user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )

    # Update last_used_at
    db_token.last_used_at = datetime.utcnow()
    db.commit()

    return db_token.user


def _get_token_from_db(
    db: Session,
    token: str,
) -> PersonalAccessToken:
    """Internal helper: resolve raw bearer token → PersonalAccessToken."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    stmt = (
        select(PersonalAccessToken)
        .options(joinedload(PersonalAccessToken.user))
        .where(PersonalAccessToken.token == token_hash)
    )
    db_token = db.execute(stmt).scalar_one_or_none()

    if db_token is None:
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


def require_ability(ability: str) -> Callable:
    """
    Factory: returns a dependency that checks if the token has the given ability.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_ability("admin"))])
    """
    def dependency(
        db: Annotated[Session, Depends(get_db)],
        token: Annotated[str, Depends(oauth2_scheme)],
    ) -> User:
        db_token = _get_token_from_db(db, token)

        if not db_token.can(ability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token missing ability: {ability}",
            )

        # Update last_used_at
        db_token.last_used_at = datetime.utcnow()
        db.commit()

        return db_token.user

    return dependency


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    # Check for forwarded IP (behind proxy/load balancer)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fallback to direct connection
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str | None:
    """Extract user agent from request"""
    return request.headers.get("User-Agent")
import hashlib
import secrets
from datetime import datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from src.crud.crud_user import user_crud
from src.crud.crud_login_attempt import login_attempt_crud
from src.schemas.user import UserCreate, UserResponse
from src.schemas.auth import TokenResponse
from src.core.security import verify_password
from src.core.config import settings
from src.services.rate_limit_service import rate_limit_service
from src.ml.fraud_detector import fraud_detector
from src.models.personal_access_token import PersonalAccessToken
from src.models.user import User

# Token expiry: 30 days
TOKEN_EXPIRY_DAYS = 30


class AuthService:
    """
    AuthService handles authentication business logic including rate limiting,
    fraud detection, and Sanctum-style token management.
    """

    async def register(
        self,
        db: AsyncSession,
        user_in: UserCreate
    ) -> UserResponse:
        """Register a new user."""
        if await user_crud.get_by_email(db, email=user_in.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        user = await user_crud.create(db, obj_in=user_in)
        return UserResponse.model_validate(user)

    async def login(
        self,
        db: AsyncSession,
        email: str,
        password: str,
        ip_address: str,
        user_agent: str | None = None,
        device_name: str = "default",
        abilities: list[str] | None = None,
    ) -> TokenResponse:
        """
        Authenticate user, check rate limits and fraud scores,
        then create an opaque bearer token (Sanctum-style).
        """
        if abilities is None:
            abilities = ["*"]

        # 1. Check Rate Limiting (IP)
        if rate_limit_service.is_rate_limited(ip_address, settings.MAX_LOGIN_ATTEMPTS, settings.RATE_LIMIT_WINDOW):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts from this IP. Please try again later."
            )

        # 2. Check Rate Limiting (Email)
        if rate_limit_service.is_rate_limited(email, settings.MAX_LOGIN_ATTEMPTS, settings.RATE_LIMIT_WINDOW):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts for this account. Please try again later."
            )

        # 3. Predict Fraud
        prediction = fraud_detector.predict(email, ip_address, user_agent)
        fraud_score = prediction.get("fraud_score", 0.0)

        if fraud_score > settings.FRAUD_THRESHOLD:
            # Log suspicious attempt
            now = datetime.utcnow()
            await login_attempt_crud.create(db, obj_in={
                "email": email,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "success": False,
                "fraud_score": fraud_score,
                "hour_of_day": now.hour,
                "day_of_week": now.weekday()
            })
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Suspicious activity detected. Please contact support."
            )

        # 4. Authenticate User
        user = await user_crud.get_by_email(db, email=email)
        if not user or not verify_password(password, user.hashed_password):
            # Increment rate limit attempts
            rate_limit_service.increment_attempts(ip_address, settings.RATE_LIMIT_WINDOW)
            rate_limit_service.increment_attempts(email, settings.RATE_LIMIT_WINDOW)

            # Log failed attempt
            now = datetime.utcnow()
            await login_attempt_crud.create(db, obj_in={
                "user_id": user.id if user else None,
                "email": email,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "success": False,
                "fraud_score": fraud_score,
                "hour_of_day": now.hour,
                "day_of_week": now.weekday()
            })
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # 5. Success — Reset rate limits
        rate_limit_service.reset_attempts(ip_address)
        rate_limit_service.reset_attempts(email)

        # Log successful attempt
        now = datetime.utcnow()
        await login_attempt_crud.create(db, obj_in={
            "user_id": user.id,
            "email": email,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "success": True,
            "fraud_score": fraud_score,
            "hour_of_day": now.hour,
            "day_of_week": now.weekday()
        })

        # 6. Generate opaque token (Sanctum-style)
        raw_token = secrets.token_hex(32)  # 64-char hex string
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        expires_at = datetime.utcnow() + timedelta(days=TOKEN_EXPIRY_DAYS)

        db_token = PersonalAccessToken(
            user_id=user.id,
            name=device_name,
            token=token_hash,
            abilities=abilities,
            expires_at=expires_at,
        )
        db.add(db_token)
        await db.commit()

        # Return raw token — the ONLY time the client sees it
        return TokenResponse(
            access_token=raw_token,
            token_type="bearer",
            device_name=device_name,
            abilities=abilities,
            expires_at=expires_at,
        )

    async def logout(
        self,
        db: AsyncSession,
        token_id: int,
        current_user: User,
    ) -> None:
        """Revoke a specific token by ID (single device logout)."""
        stmt = select(PersonalAccessToken).where(PersonalAccessToken.id == token_id)
        result = await db.execute(stmt)
        db_token = result.scalar_one_or_none()

        if not db_token or db_token.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Token not found"
            )

        await db.delete(db_token)
        await db.commit()

    async def logout_all(
        self,
        db: AsyncSession,
        current_user: User,
    ) -> None:
        """Revoke all tokens for the current user (logout everywhere)."""
        stmt = delete(PersonalAccessToken).where(
            PersonalAccessToken.user_id == current_user.id
        )
        await db.execute(stmt)
        await db.commit()

    async def list_tokens(
        self,
        db: AsyncSession,
        current_user: User,
    ) -> list[PersonalAccessToken]:
        """List all active tokens for the current user."""
        stmt = (
            select(PersonalAccessToken)
            .where(PersonalAccessToken.user_id == current_user.id)
            .order_by(PersonalAccessToken.created_at.desc())
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())


auth_service = AuthService()

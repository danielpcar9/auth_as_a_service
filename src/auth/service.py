from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import HTTPException, status
from fastapi.concurrency import run_in_threadpool

from src.users.service import UserService
from src.tokens.service import TokenService
from src.fraud.service import FraudService
from src.users.models import UserCreate, UserResponse
from src.tokens.models import TokenResponse
from src.core.security import verify_password, get_password_hash
from src.core.config import settings
from src.core.rate_limit import rate_limit_service
from src.core.metrics import metrics_service

# Type alias for a deferred background task
BackgroundCallback = Callable[[], Coroutine[Any, Any, None]]


class AuthService:
    """Orchestrator domain service for authentication"""

    def __init__(
        self,
        user_service: UserService,
        token_service: TokenService,
        fraud_service: FraudService,
    ):
        self.user_service = user_service
        self.token_service = token_service
        self.fraud_service = fraud_service

    async def register(self, user_in: UserCreate) -> UserResponse:
        """Register a new user."""
        if await self.user_service.get_by_email(email=user_in.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        hashed_password = get_password_hash(user_in.password)
        user = await self.user_service.create(data=user_in, hashed_password=hashed_password)
        return UserResponse.model_validate(user)

    async def login(
        self,
        email: str,
        password: str,
        ip_address: str,
        user_agent: str | None = None,
        device_name: str = "default",
        abilities: list[str] | None = None,
    ) -> tuple[TokenResponse, BackgroundCallback]:
        """Authenticate user, check rate limits, fraud scores, generate token.

        Returns:
            A tuple of (TokenResponse, background_callback).
            The router should schedule the callback via BackgroundTasks
            so the user gets their token without waiting for the audit INSERT.
        """

        # 1. Rate Limiting (sync, in-memory — fast enough to stay inline)
        if rate_limit_service.is_rate_limited(ip_address, settings.MAX_LOGIN_ATTEMPTS, settings.RATE_LIMIT_WINDOW):
            metrics_service.record_event("rate_limited")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts from this IP. Please try again later."
            )
        if rate_limit_service.is_rate_limited(email, settings.MAX_LOGIN_ATTEMPTS, settings.RATE_LIMIT_WINDOW):
            metrics_service.record_event("rate_limited")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts for this account. Please try again later."
            )

        # 2. Fraud Prediction — CPU-bound ML inference offloaded to threadpool
        fraud_score = await run_in_threadpool(
            self.fraud_service.predict_fraud, email, ip_address, user_agent
        )
        if fraud_score > settings.FRAUD_THRESHOLD:
            # Suspicious — log immediately (critical audit path) and reject
            await self.fraud_service.log_attempt(
                email=email, ip_address=ip_address, user_agent=user_agent,
                success=False, fraud_score=fraud_score
            )
            metrics_service.record_event("fraud_blocked")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Suspicious activity detected. Please contact support."
            )

        # 3. Authenticate User
        user = await self.user_service.get_by_email(email)
        if not user or not verify_password(password, user.hashed_password):
            rate_limit_service.increment_attempts(ip_address, settings.RATE_LIMIT_WINDOW)
            rate_limit_service.increment_attempts(email, settings.RATE_LIMIT_WINDOW)
            # Failed login — log immediately (security-critical) and reject
            await self.fraud_service.log_attempt(
                email=email, ip_address=ip_address, user_agent=user_agent,
                success=False, fraud_score=fraud_score, user_id=user.id if user else None
            )
            metrics_service.record_event("login_failure")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # 4. Success — Reset rate limits
        rate_limit_service.reset_attempts(ip_address)
        rate_limit_service.reset_attempts(email)

        # 5. Generate token
        token_response = await self.token_service.create_token(
            user=user, device_name=device_name, abilities=abilities
        )

        # 6. Record success metric
        metrics_service.record_event("login_success")

        # 7. Build deferred callback for non-critical audit log
        async def _log_success() -> None:
            await self.fraud_service.log_attempt(
                email=email, ip_address=ip_address, user_agent=user_agent,
                success=True, fraud_score=fraud_score, user_id=user.id
            )

        return token_response, _log_success

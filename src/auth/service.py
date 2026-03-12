from fastapi import HTTPException, status
from src.users.service import UserService
from src.tokens.service import TokenService
from src.fraud.service import FraudService
from src.users.models import UserCreate, UserResponse
from src.tokens.models import TokenResponse
from src.core.security import verify_password, get_password_hash
from src.core.config import settings
from src.core.rate_limit import rate_limit_service

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
    ) -> TokenResponse:
        """Authenticate user, check rate limits, fraud scores, generate token"""
        
        # 1. Rate Limiting
        if rate_limit_service.is_rate_limited(ip_address, settings.MAX_LOGIN_ATTEMPTS, settings.RATE_LIMIT_WINDOW):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts from this IP. Please try again later."
            )
        if rate_limit_service.is_rate_limited(email, settings.MAX_LOGIN_ATTEMPTS, settings.RATE_LIMIT_WINDOW):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts for this account. Please try again later."
            )

        # 2. Fraud Prediction
        fraud_score = self.fraud_service.predict_fraud(email, ip_address, user_agent)
        if fraud_score > settings.FRAUD_THRESHOLD:
            await self.fraud_service.log_attempt(
                email=email, ip_address=ip_address, user_agent=user_agent, 
                success=False, fraud_score=fraud_score
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Suspicious activity detected. Please contact support."
            )

        # 3. Authenticate User
        user = await self.user_service.get_by_email(email)
        if not user or not verify_password(password, user.hashed_password):
            rate_limit_service.increment_attempts(ip_address, settings.RATE_LIMIT_WINDOW)
            rate_limit_service.increment_attempts(email, settings.RATE_LIMIT_WINDOW)
            await self.fraud_service.log_attempt(
                email=email, ip_address=ip_address, user_agent=user_agent, 
                success=False, fraud_score=fraud_score, user_id=user.id if user else None
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # 4. Success — Reset rate limits & log success
        rate_limit_service.reset_attempts(ip_address)
        rate_limit_service.reset_attempts(email)
        await self.fraud_service.log_attempt(
            email=email, ip_address=ip_address, user_agent=user_agent, 
            success=True, fraud_score=fraud_score, user_id=user.id
        )

        # 5. Generate token via token service
        token_response = await self.token_service.create_token(
            user=user, device_name=device_name, abilities=abilities
        )
        return token_response

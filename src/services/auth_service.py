from fastapi import HTTPException, status
from src.crud.crud_user import user_crud
from src.crud.crud_login_attempt import login_attempt_crud
from src.schemas.user import UserCreate, UserResponse
from src.schemas.auth import Token
from src.core.security import verify_password, create_access_token
from src.core.config import settings
from src.services.rate_limit_service import rate_limit_service
from src.ml.fraud_detector import fraud_detector
from sqlalchemy.orm import Session
from datetime import datetime

class AuthService:
    """
    AuthService handles authentication business logic including rate limiting and fraud detection.
    """
    
    def register(
        self,
        db: Session,
        user_in: UserCreate
    ) -> UserResponse:
        """
        Register a new user.
        """
        if user_crud.get_by_email(db, email=user_in.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Email already registered"
            )

        user = user_crud.create(db, obj_in=user_in)
        return UserResponse.model_validate(user)

    def login(
        self,
        db: Session,
        email: str,
        password: str,
        ip_address: str,
        user_agent: str | None = None
    ) -> Token:
        """
        Authenticate user, check rate limits and fraud scores.
        """
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
            login_attempt_crud.create(db, obj_in={
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
        user = user_crud.get_by_email(db, email=email)
        if not user or not verify_password(password, user.hashed_password):
            # Increment rate limit attempts
            rate_limit_service.increment_attempts(ip_address, settings.RATE_LIMIT_WINDOW)
            rate_limit_service.increment_attempts(email, settings.RATE_LIMIT_WINDOW)
            
            # Log failed attempt
            now = datetime.utcnow()
            login_attempt_crud.create(db, obj_in={
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

        # 5. Success
        # Reset rate limits
        rate_limit_service.reset_attempts(ip_address)
        rate_limit_service.reset_attempts(email)

        # Log successful attempt
        now = datetime.utcnow()
        login_attempt_crud.create(db, obj_in={
            "user_id": user.id,
            "email": email,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "success": True,
            "fraud_score": fraud_score,
            "hour_of_day": now.hour,
            "day_of_week": now.weekday()
        })

        # Generate token
        access_token = create_access_token(data={"sub": user.email})
        return Token(access_token=access_token, token_type="bearer")

auth_service = AuthService()

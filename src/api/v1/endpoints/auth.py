from typing import Annotated
from fastapi import APIRouter, Depends, status, Request
from sqlalchemy.orm import Session
from src.api.deps import get_db, get_current_user, get_client_ip, get_user_agent
from src.schemas.user import UserCreate, UserResponse
from src.schemas.auth import Token, LoginRequest
from src.services.auth_service import auth_service
from src.models.user import User

router = APIRouter()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
    description="Create a new user account with email and password",
    responses={
        201: {"description": "User successfully created"},
        400: {"description": "Email already registered"},
    }
)
def register(
    user_in: UserCreate,
    db: Annotated[Session, Depends(get_db)]
) -> UserResponse:
    """Register a new user account"""
    return auth_service.register(db, user_in=user_in)


@router.post(
    "/login",
    response_model=Token,
    summary="Login user",
    description="Authenticate user and return JWT access token with fraud detection",
    responses={
        200: {"description": "Login successful"},
        401: {"description": "Invalid credentials"},
        403: {"description": "User inactive or suspicious activity detected"},
        429: {"description": "Too many failed attempts"},
    }
)
def login(
    credentials: LoginRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)]
) -> Token:
    """Authenticate user and obtain access token"""
    ip_address = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    return auth_service.login(
        db,
        email=credentials.email,
        password=credentials.password,
        ip_address=ip_address,
        user_agent=user_agent
    )


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
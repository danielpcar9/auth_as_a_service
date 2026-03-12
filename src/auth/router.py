from typing import Annotated
from fastapi import APIRouter, BackgroundTasks, Depends, status, Request
from src.auth.dependencies import get_auth_service, get_client_ip, get_user_agent
from src.auth.service import AuthService
from src.auth.schemas import LoginRequest
from src.users.models import UserCreate, UserResponse
from src.tokens.models import TokenResponse

router = APIRouter(tags=["auth"])

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
    description="Create a new user account with email and password",
)
async def register(
    user_in: UserCreate,
    service: Annotated[AuthService, Depends(get_auth_service)]
) -> UserResponse:
    """Register a new user account"""
    return await service.register(user_in=user_in)

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login user",
    description="Authenticate user and return opaque bearer token with fraud detection",
)
async def login(
    credentials: LoginRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    service: Annotated[AuthService, Depends(get_auth_service)]
) -> TokenResponse:
    """Authenticate user and obtain access token"""
    ip_address = get_client_ip(request)
    user_agent = get_user_agent(request)

    token_response, log_callback = await service.login(
        email=credentials.email,
        password=credentials.password,
        ip_address=ip_address,
        user_agent=user_agent,
        device_name=credentials.device_name,
        abilities=credentials.abilities,
    )

    # Schedule success audit log as a background task — user gets token immediately
    background_tasks.add_task(log_callback)

    return token_response

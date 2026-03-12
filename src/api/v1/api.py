from fastapi import APIRouter
from src.api.v1.endpoints import auth, fraud, users, tokens

api_router = APIRouter()


api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"]
)

api_router.include_router(
    users.router,
    prefix="/users",
    tags=["Users"]
)

api_router.include_router(
    fraud.router,
    prefix="/fraud",
    tags=["Fraud Detection"]
)

api_router.include_router(
    tokens.router,
    prefix="/tokens",
    tags=["Tokens"]
)
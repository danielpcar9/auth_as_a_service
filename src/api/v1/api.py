from fastapi import APIRouter

from src.auth.router import router as auth_router
from src.users.router import router as users_router
from src.tokens.router import router as tokens_router
from src.fraud.router import router as fraud_router

api_router = APIRouter()

# Grouping all domain routers under the v1 API prefix
api_router.include_router(auth_router, prefix="/auth")
api_router.include_router(users_router, prefix="/users")
api_router.include_router(tokens_router, prefix="/tokens")
api_router.include_router(fraud_router, prefix="/fraud")
from fastapi import APIRouter
from src.api.v1.endpoints.auth import router as auth_router

api_router = APIRouter(prefix="/v1")

api_router.include_router(auth_router)

from fastapi import APIRouter, Depends, HTTPException
from src.schemas.user import UserCreate, UserRead
from src.services.auth_service import AuthService
from src.db.session import get_db
from sqlalchemy.orm import Session
from typing import Annotated

router = APIRouter(prefix="/auth", tags=["auth"])

auth_service = AuthService()

@router.post("/register", response_model=UserRead)
def register(
    user_in: UserCreate,
    db: Annotated[Session, Depends(get_db)]
):
    return auth_service.register(db, user_in)

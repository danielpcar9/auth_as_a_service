from fastapi import HTTPException, status
from src.crud.user import CRUDUser
from src.schemas.user import UserCreate, UserRead
from src.db.session import get_db
from sqlalchemy.orm import Session
from typing import Annotated
from fastapi import Depends

crud_user = CRUDUser()

class AuthService:
    def register(
        self,
        db: Session,
        user_in: UserCreate
    ) -> UserRead:
        if crud_user.get_by_email(db, user_in.email):
            raise HTTPException(status_code=400, detail="Email already registered")

        user = crud_user.create(db, user_in.email, user_in.password, user_in.full_name)
        return UserRead.from_orm(user)

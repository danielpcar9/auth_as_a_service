from fastapi import HTTPException
from src.crud import user_crud
from src.schemas import UserCreate, UserRead
from sqlalchemy.orm import Session

class AuthService:
    """
    AuthService handles authentication business logic.
    """
    def register(
        self,
        db: Session,
        user_in: UserCreate
    ) -> UserRead:
        """
        Register a new user.
        """
        if user_crud.get_by_email(db, user_in.email):
            raise HTTPException(status_code=400, detail="Email already registered")

        user = user_crud.create(db, obj_in=user_in)
        return UserRead.model_validate(user)

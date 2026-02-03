from sqlalchemy.orm import Session
from sqlalchemy import select
from src.models import User
from src.schemas import UserCreate
from src.crud.base import CRUDBase
from src.core.security import hash_password

class CRUDUser(CRUDBase[User, UserCreate, UserCreate]):
    def __init__(self):
        super().__init__(User)

    def get_by_email(self, db: Session, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        result = db.execute(stmt)
        return result.scalar_one_or_none()

    def create(self, db: Session, *, obj_in: UserCreate) -> User:
        db_obj = User(
            email=obj_in.email,
            hashed_password=hash_password(obj_in.password),
            full_name=obj_in.full_name,
        )
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

# Singleton instance
user_crud = CRUDUser()

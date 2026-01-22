from sqlalchemy.orm import Session
from sqlalchemy import select
from src.models.user import User
from src.core.security import hash_password

class CRUDUser:
    def get_by_email(self, db: Session, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        result = db.execute(stmt)
        return result.scalar_one_or_none()

    def create(self, db: Session, email: str, password: str, full_name: str | None = None) -> User:
        hashed = hash_password(password)
        user = User(email=email, hashed_password=hashed, full_name=full_name)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from src.models import User
from src.schemas import UserCreate
from src.crud.base import CRUDBase
from src.core.security import hash_password

class CRUDUser(CRUDBase[User, UserCreate, UserCreate]):
    def __init__(self):
        super().__init__(User)

    async def get_by_email(self, db: AsyncSession, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def create(self, db: AsyncSession, *, obj_in: UserCreate) -> User:
        db_obj = User(
            email=obj_in.email,
            hashed_password=hash_password(obj_in.password),
            full_name=obj_in.full_name,
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

# Singleton instance
user_crud = CRUDUser()

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from src.users.models import User, UserCreate, UserUpdate

class UserService:
    """Domain service for user operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, user_id: int) -> User | None:
        return await self.db.get(User, user_id)

    async def get_by_email(self, email: str) -> User | None:
        result = await self.db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def create(self, data: UserCreate, hashed_password: str) -> User:
        user = User(
            email=data.email,
            full_name=data.full_name,
            hashed_password=hashed_password,
        )
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def update(self, user_id: int, data: UserUpdate, hashed_password: str | None = None) -> User | None:
        user = await self.get_by_id(user_id)
        if not user:
            return None
            
        update_data = data.model_dump(exclude_unset=True)
        if "password" in update_data:
            del update_data["password"]
            
        for key, value in update_data.items():
            setattr(user, key, value)
            
        if hashed_password:
            user.hashed_password = hashed_password
            
        await self.db.commit()
        await self.db.refresh(user)
        return user

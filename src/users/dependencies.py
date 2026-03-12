from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from src.db.session import get_db
from src.users.service import UserService

def get_user_service(db: AsyncSession = Depends(get_db)) -> UserService:
    """Dependency injection factory for UserService"""
    return UserService(db)

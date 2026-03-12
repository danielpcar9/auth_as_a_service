from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from src.db.session import get_db
from src.tokens.service import TokenService

def get_token_service(db: AsyncSession = Depends(get_db)) -> TokenService:
    """Dependency injection factory for TokenService"""
    return TokenService(db)

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from src.db.session import get_db
from src.fraud.service import FraudService

def get_fraud_service(db: AsyncSession = Depends(get_db)) -> FraudService:
    """Dependency injection factory for FraudService"""
    return FraudService(db)

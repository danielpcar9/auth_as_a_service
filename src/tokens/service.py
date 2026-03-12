import hashlib
import secrets
from datetime import datetime, UTC, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, delete

from src.tokens.models import PersonalAccessToken, TokenResponse
from src.users.models import User

# Token expiry: 30 days
TOKEN_EXPIRY_DAYS = 30

class TokenService:
    """Domain service for managing personal access tokens"""
    
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_token(
        self, 
        user: User, 
        device_name: str = "default", 
        abilities: list[str] | None = None
    ) -> TokenResponse:
        """Create a new bearer token for a given user"""
        if abilities is None:
            abilities = ["*"]
            
        raw_token = secrets.token_hex(32)  # 64-char hex string
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        expires_at = datetime.now(UTC) + timedelta(days=TOKEN_EXPIRY_DAYS)
        
        db_token = PersonalAccessToken(
            user_id=user.id,
            name=device_name,
            token=token_hash,
            abilities=abilities,
            expires_at=expires_at,
        )
        self.db.add(db_token)
        await self.db.commit()
        await self.db.refresh(db_token)
        
        return TokenResponse(
            access_token=raw_token,
            name=device_name,
            abilities=abilities,
            expires_at=expires_at,
        )

    async def revoke_token(self, token_id: int, user_id: int) -> bool:
        """Revoke a specific token directly by ID, ensuring ownership"""
        stmt = select(PersonalAccessToken).where(
            PersonalAccessToken.id == token_id, 
            PersonalAccessToken.user_id == user_id
        )
        result = await self.db.execute(stmt)
        db_token = result.scalar_one_or_none()

        if not db_token:
            return False

        await self.db.delete(db_token)
        await self.db.commit()
        return True

    async def revoke_all_tokens(self, user_id: int) -> None:
        """Revoke all tokens for a given user"""
        stmt = delete(PersonalAccessToken).where(
            PersonalAccessToken.user_id == user_id
        )
        await self.db.execute(stmt)
        await self.db.commit()

    async def list_tokens(self, user_id: int) -> list[PersonalAccessToken]:
        """List all active tokens for a user"""
        stmt = (
            select(PersonalAccessToken)
            .where(PersonalAccessToken.user_id == user_id)
            .order_by(PersonalAccessToken.created_at.desc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_db_token(self, raw_token: str) -> PersonalAccessToken | None:
        """Verify raw token and return database model"""
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        stmt = select(PersonalAccessToken).where(PersonalAccessToken.token == token_hash)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def update_last_used(self, db_token: PersonalAccessToken) -> None:
        """Update last_used_at timestamp"""
        db_token.last_used_at = datetime.now(UTC)
        await self.db.commit()

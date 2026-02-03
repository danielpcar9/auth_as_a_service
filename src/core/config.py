from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    """Application settings from environment variables"""

    # API
    PROJECT_NAME: str = "Auth Service with Fraud Detection"
    API_V1_STR: str = "/api/v1"

    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Database
    DATABASE_URL: str = "postgresql+psycopg://postgres:postgres@localhost:5432/auth_db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]

    # Fraud Detection
    FRAUD_THRESHOLD: float = 0.7
    MAX_LOGIN_ATTEMPTS: int = 5
    RATE_LIMIT_WINDOW: int = 300  # 5 minutes in seconds

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True
    )


settings = Settings()
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from src.core.config import settings

engine = create_engine(
    settings.DATABASE_URL.replace("sqlite+aiosqlite", "sqlite"),
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

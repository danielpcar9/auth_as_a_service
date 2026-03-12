import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from sqlmodel import SQLModel
import src.models_registry  # ensure all models are registered

from src.db.session import get_db
from src.main import app


# Async SQLite for tests
TEST_DATABASE_URL = "sqlite+aiosqlite:////tmp/test_auth.db"
engine = create_async_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingAsyncSession = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


@pytest.fixture(autouse=True)
async def setup_db():
    """Create tables before each test, drop after."""
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)


@pytest.fixture
async def db():
    """Provide a clean async DB session for each test."""
    async with TestingAsyncSession() as session:
        yield session


@pytest.fixture
async def client(db: AsyncSession):
    """FastAPI async test client with overridden DB dependency."""
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()

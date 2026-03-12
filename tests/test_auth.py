import hashlib
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from unittest.mock import patch, MagicMock

from src.db.base import Base
from src.db.session import get_db
from src.main import app
from src.models.user import User
from src.models.personal_access_token import PersonalAccessToken

import bcrypt

def _hash_password(password: str) -> str:
    """Hash password directly with bcrypt (avoids passlib compatibility issues)."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


# In-memory SQLite for tests
TEST_DATABASE_URL = "sqlite:////tmp/test_auth.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def setup_db():
    """Create tables before each test, drop after."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    """Provide a clean DB session for each test."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db: Session):
    """FastAPI test client with overridden DB dependency."""
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(db: Session) -> User:
    """Create a test user in the DB."""
    user = User(
        email="test@example.com",
        hashed_password=_hash_password("SecureP@ss123"),
        is_active=True,
        is_verified=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _mock_rate_limit_and_fraud():
    """Context manager patches for rate limiting, fraud detection, and password verification."""
    rate_limit_mock = MagicMock()
    rate_limit_mock.is_rate_limited.return_value = False
    rate_limit_mock.increment_attempts.return_value = None
    rate_limit_mock.reset_attempts.return_value = None

    fraud_mock = MagicMock()
    fraud_mock.predict.return_value = {
        "fraud_score": 0.0,
        "is_suspicious": False,
        "risk_level": "low",
        "features_used": {},
    }

    def _verify_password(plain: str, hashed: str) -> bool:
        """Verify using bcrypt directly (bypasses passlib bug)."""
        return bcrypt.checkpw(plain.encode(), hashed.encode())

    return (
        patch("src.services.auth_service.rate_limit_service", rate_limit_mock),
        patch("src.services.auth_service.fraud_detector", fraud_mock),
        patch("src.services.auth_service.verify_password", _verify_password),
    )


# ──────────────────────────────────────────────────────
# Test: Login creates token in DB
# ──────────────────────────────────────────────────────

def test_login_creates_token_in_db(client: TestClient, db: Session, test_user: User):
    """POST /login should return a raw token and store the SHA-256 hash in DB."""
    rl_patch, fd_patch, vp_patch = _mock_rate_limit_and_fraud()
    with rl_patch, fd_patch, vp_patch:
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "test@example.com",
                "password": "SecureP@ss123",
                "device_name": "Test Device",
                "abilities": ["read", "write"],
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert data["device_name"] == "Test Device"
    assert data["abilities"] == ["read", "write"]
    assert data["expires_at"] is not None

    raw_token = data["access_token"]
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    # Verify: hash exists in DB, raw token does NOT
    db_token = db.query(PersonalAccessToken).filter_by(token=token_hash).first()
    assert db_token is not None
    assert db_token.user_id == test_user.id
    assert db_token.name == "Test Device"
    assert db_token.abilities == ["read", "write"]

    # Raw token must NEVER be stored
    raw_in_db = db.query(PersonalAccessToken).filter_by(token=raw_token).first()
    assert raw_in_db is None


# ──────────────────────────────────────────────────────
# Test: Login multiple devices
# ──────────────────────────────────────────────────────

def test_login_multiple_devices(client: TestClient, db: Session, test_user: User):
    """Two logins to different devices should create two separate tokens."""
    rl_patch, fd_patch, vp_patch = _mock_rate_limit_and_fraud()
    with rl_patch, fd_patch, vp_patch:
        r1 = client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "SecureP@ss123",
            "device_name": "MacBook Pro",
        })
        r2 = client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "SecureP@ss123",
            "device_name": "iPhone 15",
        })

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["access_token"] != r2.json()["access_token"]

    count = db.query(PersonalAccessToken).filter_by(user_id=test_user.id).count()
    assert count == 2


# ──────────────────────────────────────────────────────
# Test: Logout deletes specific token
# ──────────────────────────────────────────────────────

def test_logout_deletes_specific_token(client: TestClient, db: Session, test_user: User):
    """DELETE /tokens/{id} should remove only that token."""
    rl_patch, fd_patch, vp_patch = _mock_rate_limit_and_fraud()
    with rl_patch, fd_patch, vp_patch:
        r1 = client.post("/api/v1/auth/login", json={
            "email": "test@example.com", "password": "SecureP@ss123", "device_name": "Device A",
        })
        r2 = client.post("/api/v1/auth/login", json={
            "email": "test@example.com", "password": "SecureP@ss123", "device_name": "Device B",
        })

    token_a = r1.json()["access_token"]
    token_b = r2.json()["access_token"]

    # Find the DB id for token A
    hash_a = hashlib.sha256(token_a.encode()).hexdigest()
    db_token_a = db.query(PersonalAccessToken).filter_by(token=hash_a).first()

    # Delete token A using token B as auth
    response = client.delete(
        f"/api/v1/tokens/{db_token_a.id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert response.status_code == 204

    # Token A should be gone
    assert db.query(PersonalAccessToken).filter_by(token=hash_a).first() is None

    # Token B should still exist
    hash_b = hashlib.sha256(token_b.encode()).hexdigest()
    assert db.query(PersonalAccessToken).filter_by(token=hash_b).first() is not None


# ──────────────────────────────────────────────────────
# Test: Logout all deletes all tokens for user
# ──────────────────────────────────────────────────────

def test_logout_all_deletes_all_tokens(client: TestClient, db: Session, test_user: User):
    """DELETE /tokens/ should remove all tokens for the user."""
    rl_patch, fd_patch, vp_patch = _mock_rate_limit_and_fraud()
    with rl_patch, fd_patch, vp_patch:
        r1 = client.post("/api/v1/auth/login", json={
            "email": "test@example.com", "password": "SecureP@ss123", "device_name": "D1",
        })
        client.post("/api/v1/auth/login", json={
            "email": "test@example.com", "password": "SecureP@ss123", "device_name": "D2",
        })
        client.post("/api/v1/auth/login", json={
            "email": "test@example.com", "password": "SecureP@ss123", "device_name": "D3",
        })

    assert db.query(PersonalAccessToken).filter_by(user_id=test_user.id).count() == 3

    token = r1.json()["access_token"]
    response = client.delete(
        "/api/v1/tokens/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 204
    assert db.query(PersonalAccessToken).filter_by(user_id=test_user.id).count() == 0


# ──────────────────────────────────────────────────────
# Test: Expired token returns 401
# ──────────────────────────────────────────────────────

def test_expired_token_returns_401(client: TestClient, db: Session, test_user: User):
    """Using an expired token should return 401."""
    rl_patch, fd_patch, vp_patch = _mock_rate_limit_and_fraud()
    with rl_patch, fd_patch, vp_patch:
        resp = client.post("/api/v1/auth/login", json={
            "email": "test@example.com", "password": "SecureP@ss123",
        })

    raw_token = resp.json()["access_token"]
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    # Force-expire the token in the DB
    db_token = db.query(PersonalAccessToken).filter_by(token=token_hash).first()
    db_token.expires_at = datetime.utcnow() - timedelta(hours=1)
    db.commit()

    # Try to use the expired token
    response = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


# ──────────────────────────────────────────────────────
# Test: Invalid token returns 401
# ──────────────────────────────────────────────────────

def test_invalid_token_returns_401(client: TestClient):
    """A random bearer token should return 401."""
    response = client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer totally_invalid_token_here"},
    )
    assert response.status_code == 401


# ──────────────────────────────────────────────────────
# Test: Wrong ability returns 403
# ──────────────────────────────────────────────────────

def test_wrong_ability_returns_403(client: TestClient, db: Session, test_user: User):
    """Token with limited abilities should get 403 on restricted route."""
    from src.api.deps import require_ability
    from fastapi import Depends, APIRouter

    # Create a temporary test route requiring "admin" ability
    test_router = APIRouter()

    @test_router.get("/test-ability", dependencies=[Depends(require_ability("admin"))])
    def test_ability_endpoint():
        return {"ok": True}

    app.include_router(test_router, prefix="/api/v1")

    # Login with only "read" ability
    rl_patch, fd_patch, vp_patch = _mock_rate_limit_and_fraud()
    with rl_patch, fd_patch, vp_patch:
        resp = client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "SecureP@ss123",
            "abilities": ["read"],
        })

    token = resp.json()["access_token"]

    response = client.get(
        "/api/v1/test-ability",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert "admin" in response.json()["detail"]


# ──────────────────────────────────────────────────────
# Test: Wildcard ability passes all checks
# ──────────────────────────────────────────────────────

def test_wildcard_ability_passes(client: TestClient, db: Session, test_user: User):
    """Token with ["*"] should pass any ability check."""
    from src.api.deps import require_ability
    from fastapi import Depends, APIRouter

    test_router = APIRouter()

    @test_router.get("/test-wildcard", dependencies=[Depends(require_ability("super-admin"))])
    def test_wildcard_endpoint():
        return {"ok": True}

    app.include_router(test_router, prefix="/api/v1")

    # Login with wildcard abilities (default)
    rl_patch, fd_patch, vp_patch = _mock_rate_limit_and_fraud()
    with rl_patch, fd_patch, vp_patch:
        resp = client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "SecureP@ss123",
            "abilities": ["*"],
        })

    token = resp.json()["access_token"]

    response = client.get(
        "/api/v1/test-wildcard",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True}

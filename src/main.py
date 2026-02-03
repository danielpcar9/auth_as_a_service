from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.v1.api import api_router
from src.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    print("=" * 50)
    print("🚀 Auth Service Starting...")
    print(f"📦 Project: {settings.PROJECT_NAME}")
    print(f"🔐 Fraud Threshold: {settings.FRAUD_THRESHOLD}")
    print("=" * 50)
    yield
    # Shutdown
    print("🛑 Auth Service Shutting Down...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Authentication service with ML-powered fraud detection",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/")
def root():
    """Root endpoint"""
    return {
        "message": "Auth Service with Fraud Detection",
        "docs": "/docs",
        "version": "1.0.0"
    }


@app.get("/health")
def health_check():
    """Health check for load balancers"""
    return {"status": "healthy", "service": "auth-service"}
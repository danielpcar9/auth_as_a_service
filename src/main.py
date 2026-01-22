from fastapi import FastAPI
from src.api.v1.api import api_router

app = FastAPI(title="Auth Service")

app.include_router(api_router)

@app.get("/")
def root():
    return {"message": "Auth Service running"}
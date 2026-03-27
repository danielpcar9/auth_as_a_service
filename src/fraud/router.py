from typing import Annotated
from fastapi import APIRouter, BackgroundTasks, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.session import get_db
from src.fraud.dependencies import get_fraud_service
from src.fraud.service import FraudService
from src.fraud.models import FraudPredictionRequest, FraudPredictionResponse
from src.ml.training import run_training_job, _get_training_status

router = APIRouter(tags=["fraud-detection"])

@router.post(
    "/predict",
    response_model=FraudPredictionResponse,
    summary="Predict fraud probability",
    description="Analyze login attempt and return fraud probability",
)
def predict_fraud(
    request: FraudPredictionRequest,
    service: Annotated[FraudService, Depends(get_fraud_service)]
) -> FraudPredictionResponse:
    """Predict if a login attempt is fraudulent"""
    # ml prediction is CPU-bound so it runs sync
    fraud_score = service.predict_fraud(
        email=request.email,
        ip_address=request.ip_address,
        user_agent=request.user_agent
    )
    
    is_suspicious = fraud_score > 0.8
    risk_level = "high" if is_suspicious else "low"
    
    return FraudPredictionResponse(
        fraud_score=fraud_score,
        is_suspicious=is_suspicious,
        risk_level=risk_level,
        features_used=service.detector.extract_features(request.email, request.ip_address, request.user_agent)
    )

@router.post(
    "/train",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Dispatch model training job",
    description="Dispatches fraud model retraining as a background task. "
                "Check progress via GET /train/status.",
)
async def train_model(
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Dispatch fraud detection model training as a background job."""
    background_tasks.add_task(run_training_job, db)
    return {
        "message": "Training job dispatched",
        "status": "pending",
        "check_status_at": "/api/v1/fraud/train/status",
    }

@router.get(
    "/train/status",
    summary="Get training job status",
    description="Check the current status of the background training job",
)
def get_training_status():
    """Get the current training job status from Redis."""
    return _get_training_status()

@router.get(
    "/status",
    summary="Get model status",
    description="Check if fraud detection model is trained and ready"
)
def get_model_status(
    service: Annotated[FraudService, Depends(get_fraud_service)]
):
    """Get fraud detection model status"""
    return {
        "is_trained": service.detector.is_trained,
        "model_type": "IsolationForest",
        "model_path": str(service.detector.model_path),
        "features": list(service.detector.extract_features("test@test.com", "0.0.0.0", None).keys())
    }

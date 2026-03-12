from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from src.fraud.dependencies import get_fraud_service
from src.fraud.service import FraudService
from src.fraud.models import FraudPredictionRequest, FraudPredictionResponse

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
    
    # We could reconstruct the dict, but here logic is embedded
    is_suspicious = fraud_score > 0.8  # Could read from settings
    risk_level = "high" if is_suspicious else "low"
    
    return FraudPredictionResponse(
        fraud_score=fraud_score,
        is_suspicious=is_suspicious,
        risk_level=risk_level,
        features_used=service.detector.extract_features(request.email, request.ip_address, request.user_agent)
    )

@router.post(
    "/train",
    summary="Train fraud detection model",
    description="Retrain the fraud detection model with historical data",
)
async def train_model(
    service: Annotated[FraudService, Depends(get_fraud_service)]
):
    """Train fraud detection model with historical login attempts"""
    attempts = await service.get_all_for_training(limit=10000)
    
    if len(attempts) < 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Not enough data for training. Have {len(attempts)}, need at least 100."
        )
    
    features_list = []
    for attempt in attempts:
        features = service.detector.extract_features(
            email=attempt.email,
            ip_address=attempt.ip_address,
            user_agent=attempt.user_agent,
            timestamp=attempt.attempted_at
        )
        features_list.append(list(features.values()))
    
    service.retrain_model(features_list)
    
    return {
        "message": "Model trained successfully",
        "samples_used": len(attempts),
        "features": list(service.detector.extract_features("test@test.com", "0.0.0.0", None).keys())
    }

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

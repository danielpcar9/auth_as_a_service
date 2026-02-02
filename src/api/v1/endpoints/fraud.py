from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import numpy as np
from src.api.deps import get_db
from src.schemas.fraud import FraudPredictionRequest, FraudPredictionResponse
from src.ml.fraud_detector import fraud_detector
from src.crud.crud_login_attempt import login_attempt_crud

router = APIRouter()


@router.post(
    "/predict",
    response_model=FraudPredictionResponse,
    summary="Predict fraud probability",
    description="Analyze login attempt and return fraud probability",
    responses={
        200: {"description": "Fraud prediction successful"},
    }
)
def predict_fraud(
    request: FraudPredictionRequest
) -> FraudPredictionResponse:
    """Predict if a login attempt is fraudulent"""
    prediction = fraud_detector.predict(
        email=request.email,
        ip_address=request.ip_address,
        user_agent=request.user_agent
    )
    
    return FraudPredictionResponse(**prediction)


@router.post(
    "/train",
    summary="Train fraud detection model",
    description="Retrain the fraud detection model with historical data",
    responses={
        200: {"description": "Model trained successfully"},
        400: {"description": "Not enough data for training"},
    }
)
def train_model(
    db: Annotated[Session, Depends(get_db)]
):
    """Train fraud detection model with historical login attempts"""
    # Get all historical attempts
    attempts = login_attempt_crud.get_all_for_training(db, limit=10000)
    
    if len(attempts) < 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Not enough data for training. Have {len(attempts)}, need at least 100."
        )
    
    # Extract features
    features_list = []
    for attempt in attempts:
        features = fraud_detector.extract_features(
            email=attempt.email,
            ip_address=attempt.ip_address,
            user_agent=attempt.user_agent,
            timestamp=attempt.attempted_at
        )
        features_list.append(list(features.values()))
    
    X = np.array(features_list)
    
    # Train model
    fraud_detector.train(X)
    
    return {
        "message": "Model trained successfully",
        "samples_used": len(attempts),
        "features": list(fraud_detector.extract_features("test@test.com", "0.0.0.0", None).keys())
    }


@router.get(
    "/status",
    summary="Get model status",
    description="Check if fraud detection model is trained and ready"
)
def get_model_status():
    """Get fraud detection model status"""
    return {
        "is_trained": fraud_detector.is_trained,
        "model_type": "IsolationForest",
        "model_path": str(fraud_detector.model_path),
        "features": list(fraud_detector.extract_features("test@test.com", "0.0.0.0", None).keys())
    }
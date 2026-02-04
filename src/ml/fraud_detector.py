import pickle
from pathlib import Path
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict

class FraudDetector:
    """Fraud detection using Isolation Forest"""
    
    def __init__(self):
        self.model = None
        self.model_path = Path("src/ml/models/fraud_model.pkl")
        self.is_trained = False
        self._load_model()
    
    def _load_model(self):
        """Load pre-trained model if exists"""
        if self.model_path.exists():
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                self.is_trained = True
                print("✅ Fraud detection model loaded")
            except Exception as e:
                print(f"⚠️ Could not load model: {e}")
                self._initialize_model()
        else:
            self._initialize_model()
    
    def _initialize_model(self):
        """Initialize new Isolation Forest model"""
        self.model = IsolationForest(
            contamination=0.1,  # Assume 10% of data is fraudulent
            random_state=42,
            n_estimators=100
        )
        print("🆕 New fraud detection model initialized")
    
    def extract_features(
        self, 
        email: str, 
        ip_address: str, 
        user_agent: str | None,
        timestamp: datetime | None = None
    ) -> Dict[str, float]:
        """Extract features from login attempt"""
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        features = {
            'hour': timestamp.hour,
            'day_of_week': timestamp.weekday(),
            'is_weekend': 1.0 if timestamp.weekday() >= 5 else 0.0,
            'is_night': 1.0 if timestamp.hour < 6 or timestamp.hour > 22 else 0.0,
            'email_length': len(email),
            'ip_numeric': self._ip_to_numeric(ip_address),
            'has_user_agent': 1.0 if user_agent else 0.0,
        }
        
        return features
    
    def _ip_to_numeric(self, ip: str) -> float:
        """Convert IP to numeric value (simple hash)"""
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return sum(int(part) * (256 ** (3 - i)) for i, part in enumerate(parts))
        except Exception:
            pass
        return hash(ip) % 1000000
    
    def predict(
        self, 
        email: str, 
        ip_address: str, 
        user_agent: str | None = None
    ) -> Dict[str, any]:
        """Predict if login attempt is fraudulent"""
        features = self.extract_features(email, ip_address, user_agent)
        
        if not self.is_trained:
            # Return conservative prediction if model not trained
            return {
                'fraud_score': 0.5,
                'is_suspicious': False,
                'risk_level': 'unknown',
                'features_used': features
            }
        
        # Convert features to array
        feature_vector = np.array(list(features.values())).reshape(1, -1)
        
        # Get prediction (-1 = outlier/fraud, 1 = normal)
        prediction = self.model.predict(feature_vector)[0]
        
        # Get anomaly score (more negative = more anomalous)
        score = self.model.score_samples(feature_vector)[0]
        
        # Normalize score to 0-1 range (fraud probability)
        fraud_score = self._normalize_score(score)
        
        # Determine risk level
        if fraud_score > 0.8:
            risk_level = 'high'
        elif fraud_score > 0.6:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'fraud_score': round(fraud_score, 3),
            'is_suspicious': prediction == -1,
            'risk_level': risk_level,
            'features_used': features
        }
    
    def _normalize_score(self, score: float) -> float:
        """Normalize anomaly score to 0-1 probability"""
        # Isolation Forest scores are typically between -0.5 and 0.5
        # More negative = more anomalous
        normalized = 1 / (1 + np.exp(score * 10))  # Sigmoid transformation
        return min(max(normalized, 0), 1)
    
    def train(self, X: np.ndarray):
        """Train model with feature matrix"""
        self.model.fit(X)
        self.is_trained = True
        self._save_model()
        print(f"✅ Model trained with {len(X)} samples")
    
    def _save_model(self):
        """Save model to disk"""
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"💾 Model saved to {self.model_path}")


# Singleton instance
fraud_detector = FraudDetector()
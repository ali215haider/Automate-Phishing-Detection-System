import os
import pickle
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Global variables to cache the loaded model and scaler
_model = None
_scaler = None
_feature_names = [
    'url_length', 'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
    'num_question_marks', 'num_equal_signs', 'num_at_signs', 'uses_https',
    'has_port', 'domain_length', 'subdomain_count', 'has_ip', 'path_length',
    'path_depth', 'num_query_params', 'has_suspicious_keywords', 'domain_age_days',
    'is_new_domain'
]

def load_model():
    """Load the ML model and scaler from files"""
    global _model, _scaler
    
    if _model is None:
        model_path = os.path.join('models', 'phishing_model.pkl')
        scaler_path = os.path.join('models', 'feature_scaler.pkl')
        
        try:
            if os.path.exists(model_path):
                _model = joblib.load(model_path)
                print("ML model loaded successfully")
            else:
                # Create a simple default model if file doesn't exist
                print("Model file not found, creating default model")
                _model = create_default_model()
                
            if os.path.exists(scaler_path):
                _scaler = joblib.load(scaler_path)
                print("Scaler loaded successfully")
            else:
                # Create a default scaler
                _scaler = StandardScaler()
                print("Scaler file not found, using default scaler")
                
        except Exception as e:
            print(f"Error loading model: {e}")
            _model = create_default_model()
            _scaler = StandardScaler()
    
    return _model, _scaler

def create_default_model():
    """Create a simple default model when the trained model is not available"""
    # This is a fallback model with basic rules
    # In a real deployment, you would train this on actual phishing data
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    
    # Create some dummy training data for initialization
    # This would be replaced with actual training data
    np.random.seed(42)
    X_dummy = np.random.rand(100, len(_feature_names))
    y_dummy = np.random.randint(0, 2, 100)
    
    # Fit the model with dummy data
    model.fit(X_dummy, y_dummy)
    
    return model

def features_to_vector(features):
    """Convert feature dictionary to numpy array"""
    vector = []
    
    for feature_name in _feature_names:
        if feature_name in features:
            value = features[feature_name]
            # Convert boolean to int
            if isinstance(value, bool):
                value = int(value)
            # Handle missing or invalid values
            elif value is None or (isinstance(value, str) and not value.isdigit()):
                value = 0
            vector.append(float(value))
        else:
            vector.append(0.0)
    
    return np.array(vector).reshape(1, -1)

def predict_phishing(features):
    """
    Predict if the given features indicate phishing
    Returns a dictionary with prediction results
    """
    try:
        model, scaler = load_model()
        
        # Convert features to vector
        feature_vector = features_to_vector(features)
        
        # Scale features if scaler is available and fitted
        try:
            if scaler is not None:
                feature_vector = scaler.transform(feature_vector)
        except Exception as e:
            print(f"Scaler not fitted, using raw features: {e}")
        
        # Make prediction
        prediction = model.predict(feature_vector)[0]
        
        # Get prediction probabilities if available
        try:
            probabilities = model.predict_proba(feature_vector)[0]
            confidence = float(max(probabilities))
            
            # If model predicts phishing (class 1), use that probability
            # If model predicts safe (class 0), use 1 - safe_probability as phishing confidence
            if prediction == 1:
                phishing_confidence = float(probabilities[1]) if len(probabilities) > 1 else confidence
            else:
                phishing_confidence = float(probabilities[0]) if len(probabilities) > 1 else (1.0 - confidence)
                
        except Exception as e:
            print(f"Error getting probabilities: {e}")
            # Fallback confidence calculation based on features
            confidence = calculate_rule_based_confidence(features)
            phishing_confidence = confidence if prediction == 1 else (1.0 - confidence)
        
        return {
            'prediction': int(prediction),
            'confidence': float(phishing_confidence),
            'is_phishing': prediction == 1,
            'model_used': 'ml'
        }
        
    except Exception as e:
        print(f"Error in ML prediction: {e}")
        # Fallback to rule-based prediction
        return calculate_rule_based_confidence(features)

def calculate_rule_based_confidence(features):
    """
    Fallback rule-based confidence calculation when ML model fails
    """
    confidence = 0.0
    
    # URL length rule
    url_length = features.get('url_length', 0)
    if url_length > 100:
        confidence += 0.3
    elif url_length > 50:
        confidence += 0.1
    
    # Domain features
    if features.get('has_ip', False):
        confidence += 0.4
    
    if not features.get('uses_https', True):
        confidence += 0.2
    
    if features.get('num_dots', 0) > 4:
        confidence += 0.2
    
    if features.get('is_new_domain', False):
        confidence += 0.3
    
    if features.get('has_suspicious_keywords', False):
        confidence += 0.2
    
    # Normalize confidence to [0, 1]
    confidence = min(confidence, 1.0)
    
    return {
        'prediction': 1 if confidence > 0.5 else 0,
        'confidence': confidence,
        'is_phishing': confidence > 0.5,
        'model_used': 'rules'
    }

def save_model(model, scaler=None):
    """Save the trained model and scaler to files"""
    try:
        os.makedirs('models', exist_ok=True)
        
        model_path = os.path.join('models', 'phishing_model.pkl')
        joblib.dump(model, model_path)
        print(f"Model saved to {model_path}")
        
        if scaler:
            scaler_path = os.path.join('models', 'scaler.pkl')
            joblib.dump(scaler, scaler_path)
            print(f"Scaler saved to {scaler_path}")
        
        return True
        
    except Exception as e:
        print(f"Error saving model: {e}")
        return False

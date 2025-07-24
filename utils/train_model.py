#!/usr/bin/env python3
"""
Script to train a simple phishing detection model
This creates a basic RandomForest model for demonstration purposes
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score

def create_synthetic_training_data():
    """
    Create synthetic training data for demonstration
    In production, this would use real phishing/legitimate datasets
    """
    np.random.seed(42)
    
    # Feature names matching our extraction functions
    feature_names = [
        'url_length', 'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
        'num_question_marks', 'num_equal_signs', 'num_at_signs', 'uses_https',
        'has_port', 'domain_length', 'subdomain_count', 'has_ip', 'path_length',
        'path_depth', 'num_query_params', 'has_suspicious_keywords', 'domain_age_days',
        'is_new_domain'
    ]
    
    # Generate 1000 samples
    n_samples = 1000
    n_features = len(feature_names)
    
    # Create legitimate website features (class 0)
    legitimate_samples = n_samples // 2
    legitimate_features = np.random.normal(
        loc=[30, 2, 1, 0, 3, 0, 0, 0, 1, 0, 15, 1, 0, 10, 2, 0, 0, 365, 0],
        scale=[10, 1, 1, 1, 1, 1, 1, 1, 0.2, 0.3, 5, 1, 0.1, 5, 1, 1, 0.2, 200, 0.2],
        size=(legitimate_samples, n_features)
    )
    legitimate_labels = np.zeros(legitimate_samples)
    
    # Create phishing website features (class 1)
    phishing_samples = n_samples - legitimate_samples
    phishing_features = np.random.normal(
        loc=[80, 5, 8, 3, 6, 3, 5, 1, 0, 1, 25, 3, 1, 25, 4, 8, 1, 30, 1],
        scale=[20, 2, 3, 2, 2, 2, 3, 1, 0.3, 0.4, 10, 2, 0.3, 10, 2, 5, 0.3, 50, 0.3],
        size=(phishing_samples, n_features)
    )
    phishing_labels = np.ones(phishing_samples)
    
    # Combine data
    X = np.vstack([legitimate_features, phishing_features])
    y = np.hstack([legitimate_labels, phishing_labels])
    
    # Ensure boolean features are 0 or 1
    boolean_indices = [8, 9, 12, 16, 18]  # uses_https, has_port, has_ip, has_suspicious_keywords, is_new_domain
    for idx in boolean_indices:
        X[:, idx] = (X[:, idx] > 0.5).astype(int)
    
    # Ensure non-negative values for count features
    X = np.abs(X)
    
    return X, y, feature_names

def train_model():
    """Train and save the phishing detection model"""
    print("Creating training data...")
    X, y, feature_names = create_synthetic_training_data()
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    
    # Create and train the model
    print("Training RandomForest model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)
    
    # Create and fit scaler
    scaler = StandardScaler()
    scaler.fit(X_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    
    print(f"Model Performance:")
    print(f"Accuracy: {accuracy:.3f}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall: {recall:.3f}")
    
    # Save the model and scaler
    model_dir = 'models'
    os.makedirs(model_dir, exist_ok=True)
    
    model_path = os.path.join(model_dir, 'phishing_model.pkl')
    scaler_path = os.path.join(model_dir, 'feature_scaler.pkl')
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    print(f"Model saved to: {model_path}")
    print(f"Scaler saved to: {scaler_path}")
    
    # Save feature names for reference
    feature_names_path = os.path.join(model_dir, 'feature_names.txt')
    with open(feature_names_path, 'w') as f:
        for name in feature_names:
            f.write(f"{name}\n")
    
    print(f"Feature names saved to: {feature_names_path}")
    
    return model, scaler, feature_names

if __name__ == "__main__":
    train_model()
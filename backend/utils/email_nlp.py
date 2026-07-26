import os
import sys
import math
import joblib
import logging

# Set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Ensure utils preprocessing can be found
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if BACKEND_DIR not in sys.path:
    sys.path.append(BACKEND_DIR)

from preprocessing.email_preprocessor import preprocess_email
from utils.scoring import get_threat_classification

class EmailNLPScanner:
    def __init__(self):
        model_path = os.path.join(BACKEND_DIR, "model", "best_email_model.pkl")
        vectorizer_path = os.path.join(BACKEND_DIR, "model", "tfidf_vectorizer.pkl")
        
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            try:
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vectorizer_path)
                logger.info(f"Successfully loaded email model of type {type(self.model)} and TF-IDF vectorizer")
            except Exception as e:
                logger.error(f"Error loading email model or vectorizer: {e}")
                self.model = None
                self.vectorizer = None
        else:
            logger.warning(f"Email model or vectorizer files not found at {model_path} or {vectorizer_path}")
            self.model = None
            self.vectorizer = None

    def analyze(self, text):
        if not self.model or not self.vectorizer:
            return {
                "risk_score": 0,
                "classification": "Error: Model not trained",
                "confidence": 0.0,
                "top_features": []
            }
        
        cleaned = preprocess_email(text)
        if not cleaned.strip():
            return {
                "risk_score": 0,
                "classification": "Safe",
                "confidence": 1.0,
                "top_features": []
            }

        try:
            tfidf_vec = self.vectorizer.transform([cleaned])
            
            # Predict the class (0 for Safe, 1 for Threat)
            prediction = int(self.model.predict(tfidf_vec)[0])
            
            # Calculate probability & risk score dynamically based on model capabilities
            if hasattr(self.model, "predict_proba"):
                prob_array = self.model.predict_proba(tfidf_vec)[0]
                prob_threat = float(prob_array[1])
            elif hasattr(self.model, "decision_function"):
                decision_val = float(self.model.decision_function(tfidf_vec)[0])
                prob_threat = 1.0 / (1.0 + math.exp(-decision_val))
            else:
                prob_threat = 0.95 if prediction == 1 else 0.05
                
            risk_score = int(prob_threat * 100)
            classification = get_threat_classification(risk_score)
            
            # Confidence is the probability of the predicted class
            confidence = prob_threat if prediction == 1 else (1.0 - prob_threat)
            
            # Explainable AI: calculate contributions of each word
            feature_names = self.vectorizer.get_feature_names_out()
            contributions = []
            
            if hasattr(self.model, "coef_"):
                try:
                    coefs = self.model.coef_[0]
                    row = tfidf_vec.tocoo()
                    for col_idx, tfidf_val in zip(row.col, row.data):
                        word = feature_names[col_idx]
                        weight = coefs[col_idx]
                        contribution = tfidf_val * weight
                        if contribution > 0:
                            contributions.append({
                                "word": word,
                                "weight": float(weight),
                                "contribution": float(contribution)
                            })
                    contributions.sort(key=lambda x: x["contribution"], reverse=True)
                except Exception as e:
                    logger.error(f"Error computing word contributions: {e}")
            
            return {
                "risk_score": risk_score,
                "classification": classification,
                "confidence": float(confidence),
                "top_features": contributions[:8]  # return top 8 words
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze email content: {e}")
            return {
                "risk_score": 0,
                "classification": "Error during analysis",
                "confidence": 0.0,
                "top_features": []
            }

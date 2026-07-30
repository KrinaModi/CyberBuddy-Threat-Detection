import os
import sys
import joblib

# Ensure utils preprocessing can be found
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if BACKEND_DIR not in sys.path:
    sys.path.append(BACKEND_DIR)

from utils.preprocessing import clean_text
from utils.scoring import get_threat_classification

class EmailNLPScanner:
    def __init__(self):
        model_path = os.path.join(BACKEND_DIR, "model", "threat_model.pkl")
        vectorizer_path = os.path.join(BACKEND_DIR, "model", "vectorizer.pkl")
        
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            self.model = joblib.load(model_path)
            self.vectorizer = joblib.load(vectorizer_path)
        else:
            self.model = None
            self.vectorizer = None

    def analyze(self, text):
        if not self.model or not self.vectorizer:
            return {
                "risk_score": 0,
                "classification": "Error: Model not trained",
                "top_features": []
            }
        
        cleaned = clean_text(text)
        if not cleaned.strip():
            return {
                "risk_score": 0,
                "classification": "Safe",
                "top_features": []
            }

        tfidf_vec = self.vectorizer.transform([cleaned])
        
        # Handle case where model only supports single prediction
        try:
            prob = self.model.predict_proba(tfidf_vec)[0][1]
        except AttributeError:
            # Fallback if standard model doesn't support predict_proba
            pred = self.model.predict(tfidf_vec)[0]
            prob = 0.95 if pred == 1 else 0.05
            
        risk_score = int(prob * 100)
        
        classification = get_threat_classification(risk_score)
            
        # Explainable AI: calculate contributions of each word
        feature_names = self.vectorizer.get_feature_names_out()
        
        contributions = []
        try:
            coefs = self.model.coef_[0]
            # Get TF-IDF values for this document
            row = tfidf_vec.tocoo()
            for col_idx, tfidf_val in zip(row.col, row.data):
                word = feature_names[col_idx]
                weight = coefs[col_idx]
                contribution = tfidf_val * weight
                # We only flag words that contribute positively to the "spam" (class 1) prediction
                if contribution > 0:
                    contributions.append({
                        "word": word,
                        "weight": float(weight),
                        "contribution": float(contribution)
                    })
            # Sort by contribution descending
            contributions.sort(key=lambda x: x["contribution"], reverse=True)
        except Exception as e:
            print("Error computing feature importances:", e)
        
        return {
            "risk_score": risk_score,
            "classification": classification,
            "top_features": contributions[:8]  # return top 8 words
        }

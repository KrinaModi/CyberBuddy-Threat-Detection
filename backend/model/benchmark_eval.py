import sys
import os
import json
import warnings
warnings.filterwarnings('ignore')

CURRENT_DIR = os.path.dirname(__file__)
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, '..'))
sys.path.append(BACKEND_DIR)

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
try:
    from xgboost import XGBClassifier
    xgboost_available = True
except ImportError:
    xgboost_available = False

from utils.preprocessing import clean_text

def main():
    dataset_path = os.path.join(BACKEND_DIR, "..", "datasets", "email_dataset.csv")
    data = pd.read_csv(dataset_path)
    data = data.dropna(subset=['email'])

    # Using same preprocessing as train_enhanced.py
    data['cleaned_text'] = data['email'].apply(clean_text)
    
    X = data['cleaned_text']
    y = data['label']

    # Using same train test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    vectorizer = TfidfVectorizer(max_features=3000, min_df=2)
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    # Also evaluate the saved model if it exists, but we can also just retrain the logistic regression.
    # We will retrain to get clean metrics.

    models = {
        "Logistic Regression": LogisticRegression(class_weight="balanced", random_state=42, max_iter=1000),
        "Random Forest": RandomForestClassifier(random_state=42),
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "SVM": SVC(probability=True, random_state=42)
    }
    
    if xgboost_available:
        models["XGBoost"] = XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
    else:
        print(json.dumps({"error": "XGBoost not installed"}))
        # Proceed with others
        
    results = {}
    
    for name, model in models.items():
        model.fit(X_train_tfidf, y_train)
        y_pred = model.predict(X_test_tfidf)
        y_prob = model.predict_proba(X_test_tfidf)[:, 1] if hasattr(model, "predict_proba") else None
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc = roc_auc_score(y_test, y_prob) if y_prob is not None else "N/A"
        
        results[name] = {
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1-Score": f1,
            "ROC-AUC": roc
        }
        
        if name == "Logistic Regression":
            cm = confusion_matrix(y_test, y_pred)
            results[name]["Confusion_Matrix"] = cm.tolist()
            
    # Output results as JSON
    print("---RESULTS_START---")
    print(json.dumps(results, indent=4))
    print("---RESULTS_END---")
    
if __name__ == "__main__":
    main()

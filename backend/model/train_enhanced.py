import sys
import os
import joblib

CURRENT_DIR = os.path.dirname(__file__)
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, '..'))
sys.path.append(BACKEND_DIR)

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

from utils.preprocessing import clean_text

# Dataset path
dataset_path = os.path.join(BACKEND_DIR, "..", "datasets", "email_dataset.csv")
data = pd.read_csv(dataset_path)

print("Dataset path:", dataset_path)

# Drop missing
data = data.dropna(subset=['email'])

# Preprocessing
data['cleaned_text'] = data['email'].apply(clean_text)

X = data['cleaned_text']
y = data['label']

# Train test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Vectorizing text using TF-IDF...")
vectorizer = TfidfVectorizer(max_features=3000, min_df=2)
X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

from sklearn.linear_model import LogisticRegression

# Model
model = LogisticRegression(
    class_weight="balanced",
    random_state=42,
    max_iter=1000
)

# Train
model.fit(X_train_tfidf, y_train)

# Predict
y_pred = model.predict(X_test_tfidf)

print("Enhanced Model Accuracy:", accuracy_score(y_test, y_pred))
print("\nEnhanced Classification Report:\n", classification_report(y_test, y_pred))

# Save Model
model_dir = os.path.join(BACKEND_DIR, "model")
os.makedirs(model_dir, exist_ok=True)
model_path = os.path.join(model_dir, "threat_model.pkl")
vectorizer_path = os.path.join(model_dir, "vectorizer.pkl")

# Save standard model and vectorizer
joblib.dump(model, model_path)
joblib.dump(vectorizer, vectorizer_path)
print("[SUCCESS] Model saved at:", model_path)
print("[SUCCESS] Vectorizer saved at:", vectorizer_path)



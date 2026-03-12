import sys
import os

# Fix imports from utils
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(BASE_DIR)

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

from utils.preprocessing import clean_text
from utils.features import extract_features

# Dataset path
dataset_path = os.path.join(BASE_DIR, "..", "datasets", "email_dataset.csv")

data = pd.read_csv(dataset_path)

# Preprocessing
data['cleaned_text'] = data['text_or_url'].apply(clean_text)

# Feature extraction
feature_data = data['cleaned_text'].apply(extract_features)
feature_df = pd.DataFrame(list(feature_data))

X = feature_df
y = data['label']

# Train test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Model
model = LogisticRegression(
    max_iter=1000,
    class_weight={0:1, 1:2}
)

# Train
model.fit(X_train, y_train)

# Predict
y_pred = model.predict(X_test)

print("Enhanced Model Accuracy:", accuracy_score(y_test, y_pred))
print("\nEnhanced Classification Report:\n", classification_report(y_test, y_pred))


# -------------------------
# Save Model
# -------------------------

import pickle

model_dir = os.path.join(BASE_DIR, "model")
os.makedirs(model_dir, exist_ok=True)

model_path = os.path.join(model_dir, "threat_model.pkl")

with open(model_path, "wb") as f:
    pickle.dump(model, f)

print("Enhanced model saved at:", model_path)
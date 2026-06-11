import sys
import os

CURRENT_DIR = os.path.dirname(__file__)
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, '..'))

sys.path.append(BACKEND_DIR)


import pandas as pd
from sklearn.model_selection import train_test_split

from sklearn.metrics import classification_report, accuracy_score

from imblearn.over_sampling import SMOTE



# Dataset path
CURRENT_DIR = os.path.dirname(__file__)
dataset_path = os.path.join(CURRENT_DIR, "..", "datasets", "email_dataset.csv")
data = pd.read_csv(dataset_path)

print("Dataset path:", dataset_path)
print("Exists:", os.path.exists(dataset_path))
print(data.columns)

# Preprocessing
X = data.drop(columns=['label'])
y = data['label']

feature_columns = X.columns.tolist()

# Train test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Model
from sklearn.ensemble import RandomForestClassifier

model = RandomForestClassifier(
    n_estimators=30,
    max_depth=10,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_train, y_train)


# Train
model.fit(X_resampled, y_resampled)

# Predict
# 🔹 Get probabilities
y_probs = model.predict_proba(X_test)[:, 1]

# 🔹 Find best threshold
from sklearn.metrics import precision_recall_curve
import numpy as np

prec, rec, thr = precision_recall_curve(y_test, y_probs)

f1 = 2 * (prec * rec) / (prec + rec + 1e-9)
best_idx = np.argmax(f1)
best_threshold = thr[best_idx]
best_threshold = min(best_threshold, 0.7)
best_threshold = max(best_threshold, 0.4)   

print("Best threshold:", best_threshold)

# 🔹 Apply threshold
y_pred = (y_probs > best_threshold).astype(int)

print("Enhanced Model Accuracy:", accuracy_score(y_test, y_pred))

from sklearn.metrics import classification_report

print(classification_report(y_test, y_pred))

from sklearn.metrics import confusion_matrix
print(confusion_matrix(y_test, y_pred))

# -------------------------
# Save Model
# -------------------------

import joblib
import os

CURRENT_DIR = os.path.dirname(__file__)

model_path = os.path.join(CURRENT_DIR, "threat_model.pkl")

joblib.dump({
    "model": model,
    "features": feature_columns
}, model_path)

print("✅ Model saved at:", model_path)
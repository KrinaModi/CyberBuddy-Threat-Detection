import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

from utils.preprocessing import clean_text
from utils.features import extract_features

# Load dataset
base_dir = os.path.dirname(os.path.abspath(__file__))
dataset_path = os.path.abspath(os.path.join(base_dir, '..', '..', 'datasets', 'email_dataset.csv'))
data = pd.read_csv(dataset_path)
data = data.dropna(subset=['email'])
data['cleaned_text'] = data['email'].apply(clean_text)

# Extract features
feature_data = data['cleaned_text'].apply(lambda x: extract_features(x))
X = pd.DataFrame(list(feature_data))
y = data['label']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# Predictions
y_pred = model.predict(X_test)

# Report
print("FINAL CLASSIFICATION REPORT:\n")
print(classification_report(y_test, y_pred))

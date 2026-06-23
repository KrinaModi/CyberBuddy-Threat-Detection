import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

from utils.preprocessing import clean_text
from utils.features import extract_features

# 1. Load dataset (EMAIL dataset for now)
base_dir = os.path.dirname(os.path.abspath(__file__))
dataset_path = os.path.abspath(os.path.join(base_dir, '..', '..', 'datasets', 'email_dataset.csv'))
data = pd.read_csv(dataset_path)
data = data.dropna(subset=['email'])

# 2. Preprocess text
data['cleaned_text'] = data['email'].apply(clean_text)

# 3. Extract features
feature_data = data['cleaned_text'].apply(lambda x: extract_features(x))
feature_df = pd.DataFrame(list(feature_data))

# 4. Labels
X = feature_df
y = data['label']

# 5. Split dataset (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# 6. Train baseline model
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# 7. Predict on test data
y_pred = model.predict(X_test)

# 8. Evaluate performance
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

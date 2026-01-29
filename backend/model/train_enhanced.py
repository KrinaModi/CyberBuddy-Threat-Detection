import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

from utils.preprocessing import clean_text
from utils.features import extract_features

data = pd.read_csv('datasets/email_dataset.csv')

data['cleaned_text'] = data['text_or_url'].apply(clean_text)
feature_data = data['cleaned_text'].apply(extract_features)
feature_df = pd.DataFrame(list(feature_data))

X = feature_df
y = data['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = LogisticRegression(
    max_iter=1000,
    class_weight={0:1, 1:2}
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("Enhanced Model Accuracy:", accuracy_score(y_test, y_pred))
print("\nEnhanced Classification Report:\n", classification_report(y_test, y_pred))

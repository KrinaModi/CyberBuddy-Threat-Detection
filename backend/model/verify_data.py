import sys
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.preprocessing import clean_text

def main():
    print("--- RAW EXECUTION LOG START ---")
    dataset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'datasets', 'email_dataset.csv'))
    print(f"Loading dataset from: {dataset_path}")
    
    data = pd.read_csv(dataset_path)
    print(f"\nRaw Dataset Shape: {data.shape}")
    
    data = data.dropna(subset=['email'])
    print(f"Dataset Shape after dropping NA emails: {data.shape}")
    
    print("\nClass Distribution (Total):")
    print(data['label'].value_counts().to_string())
    
    print("\nApplying text cleaning...")
    data['cleaned_text'] = data['email'].apply(clean_text)
    
    X = data['cleaned_text']
    y = data['label']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTrain set size: {X_train.shape[0]}")
    print(f"Test set size: {X_test.shape[0]}")
    
    print("\nTrain Class Distribution:")
    print(y_train.value_counts().to_string())
    
    print("\nTest Class Distribution:")
    print(y_test.value_counts().to_string())
    
    print("\nVectorizing text...")
    vectorizer = TfidfVectorizer(max_features=3000, min_df=2)
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    print("\nTraining Logistic Regression (class_weight='balanced')...")
    model = LogisticRegression(class_weight="balanced", random_state=42, max_iter=1000)
    model.fit(X_train_tfidf, y_train)
    
    y_pred = model.predict(X_test_tfidf)
    
    print("\n--- CONFUSION MATRIX ---")
    print(confusion_matrix(y_test, y_pred))
    
    print("\n--- CLASSIFICATION REPORT ---")
    print(classification_report(y_test, y_pred, digits=4))
    
    print("--- RAW EXECUTION LOG END ---")

if __name__ == "__main__":
    main()

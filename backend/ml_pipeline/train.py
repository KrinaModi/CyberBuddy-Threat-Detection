import os
import sys
import urllib.request
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

# Setup system path to import from backend
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
sys.path.append(BACKEND_DIR)

from utils.preprocessing import clean_text

def download_dataset():
    dataset_dir = os.path.join(BACKEND_DIR, "..", "datasets")
    os.makedirs(dataset_dir, exist_ok=True)
    dataset_path = os.path.join(dataset_dir, "email_dataset.csv")
    
    url = "https://raw.githubusercontent.com/RimAmarat/email_spam_detection/master/spam_or_not_spam.csv"
    
    print(f"Checking for dataset at {dataset_path}...")
    if os.path.exists(dataset_path) and os.path.getsize(dataset_path) < 10000:
        print("Old dataset file is too small/invalid. Overwriting...")
        try:
            os.remove(dataset_path)
        except Exception as e:
            print("Failed to remove old file:", e)

    if not os.path.exists(dataset_path):
        print(f"Downloading dataset from {url}...")
        try:
            urllib.request.urlretrieve(url, dataset_path)
            print("Download complete!")
        except Exception as e:
            print(f"Error downloading dataset: {e}")
            sys.exit(1)
    else:
        print("Dataset already exists and has valid size.")
    return dataset_path


def main():
    dataset_path = download_dataset()
    
    print("Loading dataset...")
    df = pd.read_csv(dataset_path)
    
    # The dataset columns are 'email' and 'label'
    # Rename 'email' to 'text' for consistency if needed, but we'll refer to it directly
    df = df.dropna(subset=['email'])
    
    print(f"Pre-processing {len(df)} texts...")
    df['cleaned_email'] = df['email'].apply(clean_text)
    
    X = df['cleaned_email']
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("Vectorizing text using TF-IDF...")
    vectorizer = TfidfVectorizer(max_features=3000, min_df=2)
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    print("Training Logistic Regression classifier...")
    model = LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42)
    model.fit(X_train_tfidf, y_train)
    
    y_pred = model.predict(X_test_tfidf)
    acc = accuracy_score(y_test, y_pred)
    print(f"Model accuracy: {acc:.4f}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    
    # Save model files
    model_dir = os.path.join(BACKEND_DIR, "model")
    os.makedirs(model_dir, exist_ok=True)
    
    model_path = os.path.join(model_dir, "threat_model.pkl")
    vectorizer_path = os.path.join(model_dir, "vectorizer.pkl")
    
    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vectorizer_path)
    
    print(f"[OK] Model successfully saved to: {model_path}")
    print(f"[OK] Vectorizer successfully saved to: {vectorizer_path}")


if __name__ == "__main__":
    main()

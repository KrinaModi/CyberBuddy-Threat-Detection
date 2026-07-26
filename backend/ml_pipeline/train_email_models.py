import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)

# --------------------------------------------------

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "cleaned",
    "emails",
    "master_email_processed.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "backend",
    "model"
)

os.makedirs(MODEL_DIR, exist_ok=True)

# --------------------------------------------------

print("\nLoading dataset...\n")

df = pd.read_csv(DATASET_PATH)

text_column = "processed_text"
label_column = "label"

df = df.dropna(subset=[text_column])

X = df[text_column]
y = df[label_column]

print("Rows:", len(df))

# --------------------------------------------------

print("\nCreating TF-IDF features...\n")

vectorizer = TfidfVectorizer(
    max_features=10000,
    ngram_range=(1,2),
    min_df=2
)

X = vectorizer.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# --------------------------------------------------

models = {

    "Logistic Regression":
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        ),

    "Linear SVM":
        LinearSVC(),

    "Naive Bayes":
        MultinomialNB(),

    "Random Forest":
        RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            n_jobs=-1
        )
}

results = []

best_model = None
best_name = ""
best_score = 0

# --------------------------------------------------

for name, model in models.items():

    print("=" * 70)
    print(name)

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    print(classification_report(y_test, predictions))

    results.append([
        name,
        accuracy,
        precision,
        recall,
        f1
    ])

    if f1 > best_score:

        best_score = f1
        best_model = model
        best_name = name

# --------------------------------------------------

results_df = pd.DataFrame(
    results,
    columns=[
        "Model",
        "Accuracy",
        "Precision",
        "Recall",
        "F1"
    ]
)

results_df = results_df.sort_values(
    "F1",
    ascending=False
)

print("\n")
print("=" * 70)
print("FINAL MODEL COMPARISON")
print("=" * 70)
print(results_df)

results_df.to_csv(
    os.path.join(
        MODEL_DIR,
        "email_model_comparison.csv"
    ),
    index=False
)

joblib.dump(
    best_model,
    os.path.join(
        MODEL_DIR,
        "best_email_model.pkl"
    )
)

joblib.dump(
    vectorizer,
    os.path.join(
        MODEL_DIR,
        "tfidf_vectorizer.pkl"
    )
)

print("\nBest Model:", best_name)
print("Best F1:", round(best_score,4))

print("\nSaved:")
print("best_email_model.pkl")
print("tfidf_vectorizer.pkl")
print("email_model_comparison.csv")
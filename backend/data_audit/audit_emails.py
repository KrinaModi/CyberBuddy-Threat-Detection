import os
import pandas as pd

# -----------------------------
# Project Paths
# -----------------------------

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

EMAIL_DATASET_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "raw",
    "emails"
)

REPORT_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "reports"
)

os.makedirs(REPORT_PATH, exist_ok=True)
# -----------------------------
# Find all email datasets
# -----------------------------

dataset_files = []

for file in os.listdir(EMAIL_DATASET_PATH):

    if file.endswith(".csv") or file.endswith(".xlsx"):

        dataset_files.append(
            os.path.join(EMAIL_DATASET_PATH, file)
        )

print(f"\nFound {len(dataset_files)} datasets.\n")
# -----------------------------
# Read datasets
# -----------------------------

for dataset in dataset_files:

    print("=" * 60)

    print("Dataset :", os.path.basename(dataset))

    try:

        if dataset.endswith(".csv"):
            df = pd.read_csv(dataset)

        else:
            df = pd.read_excel(dataset)

        print("Rows :", len(df))
        print("Columns :", list(df.columns))

    except Exception as e:

        print("Could not read dataset.")
        print(e)
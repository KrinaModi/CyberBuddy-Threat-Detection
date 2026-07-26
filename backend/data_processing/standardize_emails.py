import os
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

MASTER_DATASET = os.path.join(
    BASE_DIR,
    "datasets",
    "cleaned",
    "emails",
    "master_email_dataset.csv"
)

OUTPUT = os.path.join(
    BASE_DIR,
    "datasets",
    "processed",
    "emails"
)

os.makedirs(OUTPUT, exist_ok=True)

df = pd.read_csv(MASTER_DATASET)

print("Rows :", len(df))

print("\nOriginal Labels")

print(df["label"].value_counts(dropna=False))
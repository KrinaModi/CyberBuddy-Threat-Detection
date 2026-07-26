import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

sys.path.append(BASE_DIR)

import pandas as pd

from backend.preprocessing.email_preprocessor import preprocess_email

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

master_path = os.path.join(
    BASE_DIR,
    "datasets",
    "cleaned",
    "emails",
    "master_email_dataset.csv"
)

df = pd.read_csv(master_path)

print("Rows:", len(df))

email_column = None

for col in df.columns:

    if col.lower() in ["body", "email", "text", "message"]:

        email_column = col
        break

if email_column is None:

    raise Exception("Email column not found")

print("Using:", email_column)

df["processed_text"] = df[email_column].apply(
    preprocess_email
)

output = os.path.join(
    BASE_DIR,
    "datasets",
    "cleaned",
    "emails",
    "master_email_processed.csv"
)

df.to_csv(output, index=False)

print("Saved:")
print(output)
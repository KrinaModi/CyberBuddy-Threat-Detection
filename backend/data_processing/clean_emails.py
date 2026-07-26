import os
import pandas as pd

# =====================================================
# Paths
# =====================================================

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

RAW_EMAIL_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "raw",
    "emails"
)

CLEAN_EMAIL_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "cleaned",
    "emails"
)

os.makedirs(CLEAN_EMAIL_PATH, exist_ok=True)


# =====================================================
# Detect Email Column
# =====================================================

def detect_email_column(df):

    possible = [
        "email",
        "body",
        "text",
        "content",
        "message"
    ]

    cols = [c.lower() for c in df.columns]

    for p in possible:
        if p in cols:
            return df.columns[cols.index(p)]

    return None


# =====================================================
# Detect Label Column
# =====================================================

def detect_label_column(df):

    possible = [
        "label",
        "class",
        "spam",
        "target",
        "category"
    ]

    cols = [c.lower() for c in df.columns]

    for p in possible:
        if p in cols:
            return df.columns[cols.index(p)]

    return None

# =====================================================
# Find all datasets
# =====================================================

def find_datasets():

    datasets = []

    for folder in os.listdir(RAW_EMAIL_PATH):

        folder_path = os.path.join(RAW_EMAIL_PATH, folder)

        if os.path.isdir(folder_path):

            for file in os.listdir(folder_path):

                if file.endswith(".csv") or file.endswith(".xlsx"):

                    datasets.append(
                        os.path.join(folder_path, file)
                    )

    return datasets


# =====================================================
# Load dataset
# =====================================================

def load_dataset(path):

    if path.endswith(".csv"):
        return pd.read_csv(path)

    return pd.read_excel(path)

# =====================================================
# Clean Dataset
# =====================================================

def clean_dataset(df):

    email_column = detect_email_column(df)
    label_column = detect_label_column(df)

    if email_column is None:

        print("❌ Email column not found.")
        return None

    if label_column is None:

        print("❌ Label column not found.")
        return None

    # Keep only required columns
    df = df[[email_column, label_column]].copy()

    # Rename columns
    df.columns = ["email", "label"]

    # Remove empty emails
    df["email"] = df["email"].fillna("").astype(str)

    df = df[df["email"].str.strip() != ""]

    # Remove duplicate emails
    df = df.drop_duplicates(subset=["email"])

    return df

# =====================================================
# Save Dataset
# =====================================================

def save_dataset(df, original_path):

    dataset_name = os.path.splitext(
        os.path.basename(original_path)
    )[0]

    output_file = os.path.join(
        CLEAN_EMAIL_PATH,
        dataset_name + "_clean.csv"
    )

    df.to_csv(output_file, index=False)

    print(f"✅ Saved : {output_file}")
    
    # =====================================================
# Main
# =====================================================

def main():

    datasets = find_datasets()

    print(f"\nFound {len(datasets)} datasets\n")

    for dataset in datasets:

        print("=" * 60)
        print("Processing:", os.path.basename(dataset))

        try:

            df = load_dataset(dataset)

            cleaned = clean_dataset(df)

            if cleaned is not None:

                print(f"Original Rows : {len(df)}")
                print(f"Clean Rows    : {len(cleaned)}")

                save_dataset(cleaned, dataset)

        except Exception as e:

            print("Error:", e)


if __name__ == "__main__":
    main()
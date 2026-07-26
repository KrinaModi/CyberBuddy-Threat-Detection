import os
import pandas as pd

# ============================================================
# Project Paths
# ============================================================

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


# ============================================================
# Find all datasets
# ============================================================

def find_email_datasets():

    dataset_files = []

    # Look inside every dataset folder
    for folder in os.listdir(EMAIL_DATASET_PATH):

        folder_path = os.path.join(EMAIL_DATASET_PATH, folder)

        if os.path.isdir(folder_path):

            for file in os.listdir(folder_path):

                if file.endswith(".csv") or file.endswith(".xlsx"):

                    dataset_files.append(
                        os.path.join(folder_path, file)
                    )
                    
                    
    print("BASE_DIR:", BASE_DIR)
    print("EMAIL_DATASET_PATH:", EMAIL_DATASET_PATH)
    print("Does path exist?", os.path.exists(EMAIL_DATASET_PATH))

    return dataset_files

# ============================================================
# Load Dataset
# ============================================================

def load_dataset(path):

    if path.endswith(".csv"):
        return pd.read_csv(path)

    return pd.read_excel(path)


# ============================================================
# Detect Email Column
# ============================================================

def detect_email_column(df):

    possible_columns = [
        "email",
        "body",
        "text",
        "content",
        "message"
    ]

    columns = [col.lower() for col in df.columns]

    for col in possible_columns:

        if col in columns:
            return df.columns[columns.index(col)]

    return "Not Found"


# ============================================================
# Detect Label Column
# ============================================================

def detect_label_column(df):

    possible_columns = [
        "label",
        "class",
        "spam",
        "target",
        "category"
    ]

    columns = [col.lower() for col in df.columns]

    for col in possible_columns:

        if col in columns:
            return df.columns[columns.index(col)]

    return "Not Found"


# ============================================================
# Dataset Statistics
# ============================================================

def dataset_statistics(df, email_column, label_column):

    stats = {}

    stats["Rows"] = len(df)
    stats["Columns"] = len(df.columns)

    stats["Missing Values"] = df.isnull().sum().sum()
    stats["Duplicate Rows"] = df.duplicated().sum()

    # ----------------------------
    # Email statistics
    # ----------------------------

    if email_column != "Not Found":

        email_series = df[email_column].fillna("").astype(str)

        stats["Duplicate Emails"] = email_series.duplicated().sum()

        stats["Empty Emails"] = (
            email_series.str.strip() == ""
        ).sum()

        lengths = email_series.str.len()

        stats["Average Length"] = round(lengths.mean(), 2)
        stats["Shortest Email"] = lengths.min()
        stats["Longest Email"] = lengths.max()

    else:

        stats["Duplicate Emails"] = "N/A"
        stats["Empty Emails"] = "N/A"
        stats["Average Length"] = "N/A"
        stats["Shortest Email"] = "N/A"
        stats["Longest Email"] = "N/A"

    # ----------------------------
    # Label Distribution
    # ----------------------------

    if label_column != "Not Found":

        stats["Label Distribution"] = (
            df[label_column]
            .value_counts(dropna=False)
            .to_dict()
        )

    else:

        stats["Label Distribution"] = {}

    return stats


# ============================================================
# Main
# ============================================================

def main():

    datasets = find_email_datasets()

    print("\n")
    print("=" * 70)
    print("EMAIL DATASET AUDIT")
    print("=" * 70)

    print(f"\nDatasets Found : {len(datasets)}\n")

    for dataset in datasets:

        print("=" * 70)

        print("Dataset :", os.path.basename(dataset))

        try:

            df = load_dataset(dataset)

            email_column = detect_email_column(df)
            label_column = detect_label_column(df)

            stats = dataset_statistics(
                df,
                email_column,
                label_column
            )

            print(f"Rows              : {stats['Rows']}")
            print(f"Columns           : {stats['Columns']}")
            print(f"Email Column      : {email_column}")
            print(f"Label Column      : {label_column}")
            print(f"Missing Values    : {stats['Missing Values']}")
            print(f"Duplicate Rows    : {stats['Duplicate Rows']}")
            print(f"Duplicate Emails  : {stats['Duplicate Emails']}")
            print(f"Empty Emails      : {stats['Empty Emails']}")
            print(f"Average Length    : {stats['Average Length']}")
            print(f"Shortest Email    : {stats['Shortest Email']}")
            print(f"Longest Email     : {stats['Longest Email']}")

            print("\nLabel Distribution")

            for label, count in stats["Label Distribution"].items():
                print(f"   {label} : {count}")

        except Exception as e:

            print("Could not read dataset.")
            print(e)

    print("\n")
    print("=" * 70)
    print("Audit Completed")
    print("=" * 70)


if __name__ == "__main__":
    main()
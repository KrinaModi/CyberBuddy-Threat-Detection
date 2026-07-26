import os
import pandas as pd
from urllib.parse import urlparse

# ============================================================
# Project Paths
# ============================================================

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

URL_DATASET_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "raw",
    "urls"
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

def find_url_datasets():

    dataset_files = []

    for folder in os.listdir(URL_DATASET_PATH):

        folder_path = os.path.join(URL_DATASET_PATH, folder)

        if os.path.isdir(folder_path):

            for file in os.listdir(folder_path):

                if file.endswith(".csv") or file.endswith(".xlsx"):

                    dataset_files.append(
                        os.path.join(folder_path, file)
                    )

    return dataset_files


# ============================================================
# Load Dataset
# ============================================================

def load_dataset(path):

    if path.endswith(".csv"):
        return pd.read_csv(path)

    return pd.read_excel(path)


# ============================================================
# Detect URL Column
# ============================================================

def detect_url_column(df):

    possible_columns = [
        "url",
        "link",
        "website",
        "domain",
        "uri"
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
        "target",
        "category",
        "type"
    ]

    columns = [col.lower() for col in df.columns]

    for col in possible_columns:

        if col in columns:
            return df.columns[columns.index(col)]

    return "Not Found"


# ============================================================
# URL Validation
# ============================================================

def valid_url(url):

    try:
        parsed = urlparse(str(url))
        return bool(parsed.netloc)
    except:
        return False


# ============================================================
# Dataset Statistics
# ============================================================

def dataset_statistics(df, url_column, label_column):

    stats = {}

    stats["Rows"] = len(df)
    stats["Columns"] = len(df.columns)

    stats["Missing Values"] = df.isnull().sum().sum()
    stats["Duplicate Rows"] = df.duplicated().sum()

    if url_column != "Not Found":

        urls = df[url_column].fillna("").astype(str)

        stats["Duplicate URLs"] = urls.duplicated().sum()

        stats["Empty URLs"] = (
            urls.str.strip() == ""
        ).sum()

        lengths = urls.str.len()

        stats["Average Length"] = round(lengths.mean(), 2)
        stats["Shortest URL"] = lengths.min()
        stats["Longest URL"] = lengths.max()

        invalid = 0

        for url in urls:

            if not valid_url(url):
                invalid += 1

        stats["Invalid URLs"] = invalid

        domains = []

        for url in urls:

            try:
                parsed = urlparse(
                    url if url.startswith(("http://", "https://"))
                    else "http://" + url
                )

                domains.append(parsed.netloc)

            except:
                pass

        stats["Unique Domains"] = len(set(domains))

    else:

        stats["Duplicate URLs"] = "N/A"
        stats["Empty URLs"] = "N/A"
        stats["Average Length"] = "N/A"
        stats["Shortest URL"] = "N/A"
        stats["Longest URL"] = "N/A"
        stats["Invalid URLs"] = "N/A"
        stats["Unique Domains"] = "N/A"

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

    datasets = find_url_datasets()

    print("\n")
    print("=" * 70)
    print("URL DATASET AUDIT")
    print("=" * 70)

    print(f"\nDatasets Found : {len(datasets)}\n")

    for dataset in datasets:

        print("=" * 70)

        print("Dataset :", os.path.basename(dataset))

        try:

            df = load_dataset(dataset)

            url_column = detect_url_column(df)
            label_column = detect_label_column(df)

            stats = dataset_statistics(
                df,
                url_column,
                label_column
            )

            print(f"Rows              : {stats['Rows']}")
            print(f"Columns           : {stats['Columns']}")
            print(f"URL Column        : {url_column}")
            print(f"Label Column      : {label_column}")
            print(f"Missing Values    : {stats['Missing Values']}")
            print(f"Duplicate Rows    : {stats['Duplicate Rows']}")
            print(f"Duplicate URLs    : {stats['Duplicate URLs']}")
            print(f"Empty URLs        : {stats['Empty URLs']}")
            print(f"Average Length    : {stats['Average Length']}")
            print(f"Shortest URL      : {stats['Shortest URL']}")
            print(f"Longest URL       : {stats['Longest URL']}")
            print(f"Invalid URLs      : {stats['Invalid URLs']}")
            print(f"Unique Domains    : {stats['Unique Domains']}")

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
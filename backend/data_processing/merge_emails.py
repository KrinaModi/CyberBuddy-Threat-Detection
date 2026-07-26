import os
import pandas as pd

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

CLEAN_EMAIL_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "cleaned",
    "emails"
)

OUTPUT_PATH = os.path.join(
    CLEAN_EMAIL_PATH,
    "master_email_dataset.csv"
)

def load_clean_datasets():

    dfs = []

    for file in os.listdir(CLEAN_EMAIL_PATH):

        if not file.endswith(".csv"):
            continue

        if file == "master_email_dataset.csv":
            continue

        path = os.path.join(CLEAN_EMAIL_PATH, file)

        df = pd.read_csv(path)

        print(f"Loaded {file} ({len(df)} rows)")

        dfs.append(df)

    return dfs

def merge_datasets(datasets):

    master = pd.concat(
        datasets,
        ignore_index=True
    )

    print("\nBefore removing duplicates:")
    print(len(master))

    master = master.drop_duplicates(
        subset=["email"]
    )

    print("\nAfter removing duplicates:")
    print(len(master))

    return master

def main():

    datasets = load_clean_datasets()

    master = merge_datasets(datasets)

    master.to_csv(
        OUTPUT_PATH,
        index=False
    )

    print("\nSaved master dataset.")
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()
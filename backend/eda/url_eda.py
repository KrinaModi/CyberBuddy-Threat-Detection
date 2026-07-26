import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

DATASET = "../datasets/clean_urls.csv"


def url_eda():
    df = pd.read_csv(DATASET)

    print("=" * 60)
    print("URL DATASET EXPLORATORY DATA ANALYSIS")
    print("=" * 60)

    print("\nDataset Shape:")
    print(df.shape)

    print("\nColumns:")
    print(df.columns.tolist())

    print("\nMissing Values:")
    print(df.isnull().sum())

    print("\nDuplicate URLs:")
    print(df.duplicated(subset=["url"]).sum())

    print("\nLabel Distribution:")
    print(df["label"].value_counts())

    df["url_length"] = df["url"].astype(str).apply(len)

    print("\nURL Length Statistics:")
    print(df["url_length"].describe())

    df["domain"] = (
        df["url"]
        .str.replace("http://", "", regex=False)
        .str.replace("https://", "", regex=False)
        .str.split("/")
        .str[0]
    )

    print("\nTop 10 Domains:")
    print(df["domain"].value_counts().head(10))

    plt.figure(figsize=(6,4))
    sns.countplot(data=df, x="label")
    plt.title("Safe vs Malicious URLs")
    plt.xlabel("Label")
    plt.ylabel("Count")
    plt.show()

    plt.figure(figsize=(8,4))
    plt.hist(df["url_length"], bins=30)
    plt.title("URL Length Distribution")
    plt.xlabel("Length")
    plt.ylabel("Frequency")
    plt.show()

    plt.figure(figsize=(10,5))
    df["domain"].value_counts().head(10).plot(kind="bar")
    plt.title("Top 10 Domains")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    url_eda()
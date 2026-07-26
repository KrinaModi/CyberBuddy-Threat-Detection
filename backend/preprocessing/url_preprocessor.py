import re
import pandas as pd
from urllib.parse import urlparse


class URLPreprocessor:

    def __init__(self):
        pass

    def normalize_url(self, url):
        if pd.isna(url):
            return ""

        url = str(url).strip().lower()

        if not url:
            return ""

        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        url = re.sub(r"/+$", "", url)

        return url

    def is_valid_url(self, url):
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc)
        except:
            return False

    def preprocess(self, url):
        url = self.normalize_url(url)

        if not self.is_valid_url(url):
            return None

        return url

    def preprocess_dataframe(self, df, column="url"):
        df = df.copy()

        df[column] = df[column].apply(self.preprocess)

        df = df.dropna(subset=[column])

        df = df.drop_duplicates(subset=[column])

        df = df.reset_index(drop=True)

        return df


if __name__ == "__main__":

    sample = pd.DataFrame({
        "url": [
            " GOOGLE.COM ",
            "paypal-login.xyz",
            "https://github.com/",
            None
        ]
    })

    processor = URLPreprocessor()

    print(processor.preprocess_dataframe(sample))
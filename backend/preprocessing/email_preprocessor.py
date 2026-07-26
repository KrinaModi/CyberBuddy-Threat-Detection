import re
import string
import nltk

from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

nltk.download("stopwords")
nltk.download("wordnet")

stop_words = set(stopwords.words("english"))
lemmatizer = WordNetLemmatizer()


def preprocess_email(text):

    if not isinstance(text, str):
        return ""

    text = text.lower()

    # Replace URLs
    text = re.sub(r'https?://\S+|www\.\S+', ' URL_TOKEN ', text)

    # Replace email addresses
    text = re.sub(
        r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        ' EMAIL_TOKEN ',
        text
    )

    # Replace IP addresses
    text = re.sub(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        ' IP_TOKEN ',
        text
    )

    # Replace numbers
    text = re.sub(r'\d+', ' NUMBER_TOKEN ', text)

    # Remove punctuation
    text = text.translate(
        str.maketrans('', '', string.punctuation)
    )

    # Remove extra spaces
    text = re.sub(r'\s+', ' ', text)

    words = []

    for word in text.split():

        if word not in stop_words:

            words.append(
                lemmatizer.lemmatize(word)
            )

    return " ".join(words)
import nltk
import re
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

stop_words = set(stopwords.words('english'))

def clean_text(text):
    # 1. Convert to lowercase
    text = text.lower()
    
    # 2. Remove URLs
    text = re.sub(r'http\S+', '', text)
    
    # 3. Remove special characters and numbers
    text = re.sub(r'[^a-z\s]', '', text)
    
    # 4. Tokenize (split sentence into words)
    words = word_tokenize(text)
    
    # 5. Remove stopwords (common useless words)
    words = [word for word in words if word not in stop_words]
    
    # 6. Join words back
    return ' '.join(words)

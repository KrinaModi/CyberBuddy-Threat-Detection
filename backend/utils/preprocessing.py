import nltk
import re
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

stop_words = set(stopwords.words('english'))
additional_stopwords = {
    'please', 'information', 'business', 'company', 'receive', 'email', 'mail', 
    'name', 'subject', 'next', 'steps', 'notes', 'project', 'sync', 'would', 'get',
    'dear', 'hello', 'hi', 'regards', 'thanks', 'thank', 'best', 'sincerely',
    'internet', 'per', 'price', 'domain', 'risk', 'reply', 'us', 'we', 'our', 'you',
    'your', 'attachment', 'meeting', 'team', 'date', 'time', 'week', 'day', 'month',
    'year', 'work', 'office', 'schedule', 'update', 'status'
}
stop_words.update(additional_stopwords)

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

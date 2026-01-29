from utils.features import extract_features
from utils.preprocessing import clean_text

sample = "URGENT!!! Click here to win free money now"
cleaned = clean_text(sample)

features = extract_features(cleaned)
print(features)

import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils.features import extract_features
from utils.preprocessing import clean_text

def test_extract_features():
    sample = "URGENT!!! Click here to win free money now http://spam.com"
    cleaned = clean_text(sample)
    features = extract_features(cleaned, original_text=sample)

    assert features['text_length'] == len(cleaned)
    assert features['word_count'] > 0
    assert features['suspicious_word_count'] >= 3 # urgent, win, money, free
    assert features['has_url'] == 1

def test_extract_features_safe():
    sample = "hello john how are you doing today"
    cleaned = clean_text(sample)
    features = extract_features(cleaned, original_text=sample)
    
    assert features['has_url'] == 0
    assert features['suspicious_word_count'] == 0

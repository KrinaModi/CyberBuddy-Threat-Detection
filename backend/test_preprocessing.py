import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils.preprocessing import clean_text

def test_clean_text_removes_urls():
    sample = "URGENT!!! Your account is BLOCKED. Click here http://fake.com"
    result = clean_text(sample)
    assert "http" not in result
    assert "fake.com" not in result

def test_clean_text_lowercases_and_removes_symbols():
    sample = "Beautiful WORLD! 123"
    result = clean_text(sample)
    assert result == "beautiful world"

def test_clean_text_removes_stopwords():
    sample = "this is a very bad situation"
    result = clean_text(sample)
    words = result.split()
    assert "this" not in words
    assert "is" not in words
    assert "a" not in words
    assert "bad" in words
    assert "situation" in words

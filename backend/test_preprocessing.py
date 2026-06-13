import pytest
from utils.preprocessing import clean_text

def test_clean_text_removes_urls():
    sample = "URGENT!!! Your account is BLOCKED. Click here http://fake.com"
    result = clean_text(sample)
    assert "http" not in result
    assert "fake.com" not in result

def test_clean_text_lowercases_and_removes_symbols():
    sample = "Hello WORLD! 123"
    result = clean_text(sample)
    assert result == "hello world"

def test_clean_text_removes_stopwords():
    sample = "this is a very bad day"
    result = clean_text(sample)
    words = result.split()
    assert "this" not in words
    assert "is" not in words
    assert "a" not in words
    assert "bad" in words
    assert "day" in words

import re

def extract_features(text, original_text=None):
    features = {}

    if original_text is None:
        original_text = text

    # 1. Text length
    features['text_length'] = len(text)

    # 2. Word count
    words = text.split()
    word_count = len(words)
    features['word_count'] = word_count

    # 3. Suspicious keyword features (ENHANCED)
    suspicious_words = [
        'free', 'win', 'urgent', 'click', 'verify',
        'account', 'login', 'money', 'password', 'bank'
    ]

    suspicious_count = sum(1 for word in words if word in suspicious_words)
    features['suspicious_word_count'] = suspicious_count

    # 🔥 NEW STRONG FEATURE: keyword density
    features['suspicious_word_ratio'] = (
        suspicious_count / word_count if word_count > 0 else 0
    )

    # 4. Special character count
    features['special_char_count'] = sum(
        1 for char in text if not char.isalnum() and not char.isspace()
    )

    # 5. URL presence - Use original_text to avoid data leakage
    features['has_url'] = 1 if 'http' in original_text or 'www' in original_text else 0

    return features

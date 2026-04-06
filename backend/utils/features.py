import re

# ================================
# 🔹 COMMON SUSPICIOUS WORD LIST
# ================================
SUSPICIOUS_WORDS = list(set([
    "free", "win", "winner", "urgent", "click", "verify",
    "account", "login", "money", "password", "bank",
    "suspended", "lottery", "claim", "confirm",
    "limited", "prize", "offer", "bonus", "now", "asap"
]))


# ================================
# 🤖 ML FEATURE EXTRACTION
# ================================
def extract_features(text):
    features = {}

    text_lower = text.lower()
    words = text_lower.split()
    word_count = len(words)

    # 1. Text length
    features['text_length'] = len(text)

    # 2. Word count
    features['word_count'] = word_count

    # 3. Suspicious keyword count
    suspicious_count = sum(1 for word in words if word in SUSPICIOUS_WORDS)
    features['suspicious_word_count'] = suspicious_count

    # 4. Keyword density
    features['suspicious_word_ratio'] = (
        suspicious_count / word_count if word_count > 0 else 0
    )

    # 5. Special characters
    features['special_char_count'] = sum(
        1 for char in text if not char.isalnum() and not char.isspace()
    )

    # 6. URL presence
    features['has_url'] = 1 if re.search(r'https?://|www\.', text_lower) else 0

    return features


# ================================
# 🧠 RULE-BASED DETECTION
# ================================

def check_keywords(email):
    return sum(10 for word in SUSPICIOUS_WORDS if word in email.lower())


def check_links(email):
    links = re.findall(r'https?://\S+', email)
    score = 0

    for link in links:
        if "@" in link or "-" in link or "bit.ly" in link or "tinyurl" in link:
            score += 20

    return score


def check_sender(sender_email, content):
    score = 0
    domain = sender_email.split("@")[-1].lower()

    if domain not in content.lower():
        score += 25

    return score


def check_urgency(email):
    urgency_words = ["urgent", "immediately", "asap", "now"]
    return 15 if any(word in email.lower() for word in urgency_words) else 0


def analyze_email(email, sender):
    score = 0
    reasons = []

    k = check_keywords(email)
    if k:
        score += k
        reasons.append("Suspicious keywords detected")

    l = check_links(email)
    if l:
        score += l
        reasons.append("Suspicious links detected")

    s = check_sender(sender, email)
    if s:
        score += s
        reasons.append("Sender mismatch detected")

    u = check_urgency(email)
    if u:
        score += u
        reasons.append("Urgent language detected")

    return score, reasons


# ================================
# 🎯 FINAL CLASSIFICATION
# ================================
def get_status(score):
    if score < 30:
        return "SAFE"
    elif score < 70:
        return "SUSPICIOUS"
    else:
        return "PHISHING"
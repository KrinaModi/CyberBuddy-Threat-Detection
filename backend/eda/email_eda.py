import os
import re
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from wordcloud import WordCloud

# ===========================================
# Paths
# ===========================================

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

DATASET = os.path.join(
    BASE_DIR,
    "datasets",
    "cleaned",
    "emails",
    "master_email_dataset.csv"
)

REPORT_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "reports",
    "email"
)

CHART_PATH = os.path.join(
    REPORT_PATH,
    "charts"
)

os.makedirs(CHART_PATH, exist_ok=True)

# ===========================================
# Load Dataset
# ===========================================

df = pd.read_csv(DATASET)

print("=" * 60)
print("EMAIL DATASET SUMMARY")
print("=" * 60)

print(f"Total Emails : {len(df)}")
print(f"Phishing     : {(df['label']==1).sum()}")
print(f"Legitimate   : {(df['label']==0).sum()}")

# ===========================================
# Email Length
# ===========================================

df["email_length"] = df["email"].astype(str).apply(len)

print("\nEMAIL LENGTH")

print(f"Average : {df['email_length'].mean():.2f}")
print(f"Median  : {df['email_length'].median()}")
print(f"Min     : {df['email_length'].min()}")
print(f"Max     : {df['email_length'].max()}")

# ===========================================
# Word Count
# ===========================================

df["word_count"] = df["email"].astype(str).apply(
    lambda x: len(x.split())
)

print("\nWORD COUNT")

print(f"Average : {df['word_count'].mean():.2f}")
print(f"Median  : {df['word_count'].median()}")
print(f"Min     : {df['word_count'].min()}")
print(f"Max     : {df['word_count'].max()}")

# ===========================================
# Security Feature Analysis
# ===========================================

print("\n" + "=" * 60)
print("SECURITY FEATURE ANALYSIS")
print("=" * 60)

url_regex = r'https?://\S+|www\.\S+'
ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

df["has_url"] = df["email"].astype(str).str.contains(
    url_regex,
    regex=True,
    case=False
)

df["has_ip"] = df["email"].astype(str).str.contains(
    ip_regex,
    regex=True
)

df["has_html"] = df["email"].astype(str).str.contains(
    r"<html|<body|<a |<form|<script",
    regex=True,
    case=False
)

df["has_js"] = df["email"].astype(str).str.contains(
    r"javascript|onclick|onload",
    regex=True,
    case=False
)

urgent_words = [
    "urgent",
    "verify",
    "account",
    "login",
    "click",
    "password",
    "bank",
    "security",
    "confirm",
    "limited"
]

df["urgent_count"] = df["email"].astype(str).apply(
    lambda x: sum(word in x.lower() for word in urgent_words)
)

print(f"Emails with URLs          : {df['has_url'].sum()}")
print(f"Emails with IPs           : {df['has_ip'].sum()}")
print(f"Emails with HTML          : {df['has_html'].sum()}")
print(f"Emails with JavaScript    : {df['has_js'].sum()}")
print(f"Average urgent keywords   : {df['urgent_count'].mean():.2f}")
print("\nFEATURES IN PHISHING EMAILS")

phish = df[df["label"] == 1]

print(f"URLs          : {phish['has_url'].sum()}")
print(f"HTML          : {phish['has_html'].sum()}")
print(f"JavaScript    : {phish['has_js'].sum()}")
print(f"Average urgent words : {phish['urgent_count'].mean():.2f}")

print("\nFEATURES IN LEGITIMATE EMAILS")

legit = df[df["label"] == 0]

print(f"URLs          : {legit['has_url'].sum()}")
print(f"HTML          : {legit['has_html'].sum()}")
print(f"JavaScript    : {legit['has_js'].sum()}")
print(f"Average urgent words : {legit['urgent_count'].mean():.2f}")
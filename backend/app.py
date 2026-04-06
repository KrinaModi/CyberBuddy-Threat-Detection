import pickle
import pandas as pd
import csv
import os

from flask import jsonify
from flask import Flask, render_template, request, redirect, session
import sqlite3

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)
app.secret_key = "cyberbuddysecret"

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Create users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
email TEXT,
password TEXT
)
""")

# Create scans table
cursor.execute("""
CREATE TABLE IF NOT EXISTS scans(
id INTEGER PRIMARY KEY AUTOINCREMENT,
url TEXT,
result TEXT,
user TEXT,
date TEXT
)
""")

conn.commit()
conn.close()




from utils.preprocessing import clean_text
from utils.features import extract_features, analyze_email, get_status
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "threat_model.pkl")

model = joblib.load(MODEL_PATH)



BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.csv")


# ------------------- Load ML Model -------------------
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "threat_model.pkl")


with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)
    
    
import re

def rule_based_score(text, sender="unknown"):
    score = 0
    reasons = []

    text_lower = text.lower()

    # Extract links
    links = re.findall(r'https?://\S+', text)

    # Suspicious links
    for link in links:
        if "http://" in link:
            score += 25
            reasons.append("Unsecured HTTP link detected")

        if any(x in link for x in ["bit.ly", "tinyurl", "paypa1", "free-money"]):
            score += 25
            reasons.append("Suspicious or shortened link")

    # Too many links
    if len(links) > 2:
        score += 15
        reasons.append("Too many links in message")

    # Urgency words
    urgency_words = ["urgent", "immediately", "verify now", "act fast"]
    if any(word in text_lower for word in urgency_words):
        score += 15
        reasons.append("Urgent language detected")

    # Scam words
    scam_words = ["lottery", "free money", "winner", "claim now"]
    if any(word in text_lower for word in scam_words):
        score += 10
        reasons.append("Scam-related words detected")

    # Attachment bait
    if "attachment" in text_lower or "download" in text_lower:
        score += 10
        reasons.append("Suspicious attachment mention")

    # Sender mismatch (basic)
    if "@" in sender:
        domain = sender.split("@")[1]
        if domain not in text:
            score += 20
            reasons.append("Sender mismatch detected")

    return score, reasons


# ------------------- ROUTES -------------------

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/how-to-use")
def how_to_use():
    return render_template("how_to_use.html")


# 2️⃣ LOGIN HANDLER
@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()

        with open("backend/users.csv", mode="r", encoding="utf-8-sig") as file:
            reader = csv.DictReader(file)

            for row in reader:
                if row["username"].strip() == username and row["password"].strip() == password:
                    session["user"] = username
                    return redirect("/dashboard")

        return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # 1️⃣ Check password match
        if password != confirm_password:
            return render_template(
                "register.html",
                message="Passwords do not match"
            )

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        # 2️⃣ Check if username or email already exists
        cursor.execute(
            "SELECT * FROM users WHERE name=? OR email=?",
            (username, email)
        )

        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            return render_template(
                "register.html",
                message="Username or Email already exists"
            )

        # 3️⃣ Insert new user
        cursor.execute(
            "INSERT INTO users (name,email,password) VALUES (?,?,?)",
            (username, email, password)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":
        email = request.form["email"]
        new_password = request.form["new_password"]

        rows = []
        updated = False

        with open("backend/users.csv", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            for row in reader:
                if row["email"] == email:
                    row["password"] = new_password
                    updated = True
                rows.append(row)

        if not updated:
            return render_template(
                "forgot_password.html",
                message="Email not found"
            )

        with open("backend/users.csv", "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=["username", "email", "password"]
            )
            writer.writeheader()
            writer.writerows(rows)

        return redirect("/login")

    return render_template("forgot_password.html")


@app.route('/detect')
def detect():
    return render_template('index.html')  # your current file


@app.route('/check_url', methods=['POST'])
def check_url():

    url = request.form['url']

    if "login" in url or "bank" in url:
        result = "Malicious"
    else:
        result = "Safe"

    return render_template("home.html", result=result)

@app.route('/admin')
def admin():
    return render_template("admin_login.html")


@app.route('/admin/login', methods=['POST'])
def admin_login():
    username = request.form['username']
    password = request.form['password']

    if username == "admin" and password == "admin123":
        session['admin'] = True
        return redirect('/admin/dashboard')
    else:
        return "Invalid Admin Login"
    
    
@app.route('/admin/dashboard')
def admin_dashboard():

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    users = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    urls = cursor.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    malicious = cursor.execute("SELECT COUNT(*) FROM scans WHERE result='Malicious'").fetchone()[0]
    safe = cursor.execute("SELECT COUNT(*) FROM scans WHERE result='Safe'").fetchone()[0]

    conn.close()

    return render_template("admin_dashboard.html",
                           users=users,
                           urls=urls,
                           malicious=malicious,
                           safe=safe)
    
    
@app.route('/admin/users')
def admin_users():

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    users = cursor.execute("SELECT * FROM users").fetchall()

    conn.close()

    return render_template("admin_users.html", users=users)


@app.route('/admin/history')
def admin_history():

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    scans = cursor.execute("SELECT * FROM scans").fetchall()

    conn.close()

    return render_template("admin_history.html", scans=scans)
# 3️⃣ DASHBOARD (THREAT DETECTION PAGE)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    # =========================
    # 📥 GET INPUT
    # =========================
    user_input = request.form["input_data"]
    sender = request.form.get("sender", "test@example.com")

    # =========================
    # 🧹 CLEAN TEXT
    # =========================
    cleaned_email = clean_text(user_input)

    # =========================
    # 🤖 ML PREDICTION (UNCHANGED LOGIC)
    # =========================
    features = extract_features(cleaned_email)
    df = pd.DataFrame([features])

    prediction = model.predict(df)[0]

    # Old result (kept for DB compatibility)
    if prediction == 1:
        result = "Malicious"
    else:
        result = "Safe"

    # =========================
    # 🧠 RULE-BASED DETECTION (NEW)
    # =========================
    score, reasons = analyze_email(cleaned_email, sender)

    # =========================
    # 🔥 COMBINE ML + RULE
    # =========================
    if prediction == 1:
        score += 30
        reasons.append("ML model flagged as phishing")

    # =========================
    # 🎯 FINAL STATUS
    # =========================
    status = get_status(score)

    # =========================
    # 💾 SAVE TO DATABASE (UNCHANGED)
    # =========================
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO scans (url,result,user,date) VALUES (?,?,?,datetime('now'))",
        (user_input, result, "user")
    )

    conn.commit()
    conn.close()

    # =========================
    # 📤 SEND TO FRONTEND
    # =========================
    return render_template(
        "index.html",
        result=result,      # old (for safety)
        score=score,        # new
        status=status,      # new
        reasons=reasons     # new
    )


# 4️⃣ ML SCAN API (AJAX)
@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json(silent=True) or {}
        text = data.get("input", "")
        sender = data.get("sender", "unknown")

        # -------- RULE BASED --------
        rule_score, reasons = rule_based_score(text, sender)

        # -------- ML MODEL --------
        cleaned = clean_text(text)
        features = extract_features(cleaned)
        df = pd.DataFrame([features])

        prediction = model.predict(df)[0]
        probability = model.predict_proba(df)[0][1]

        ml_score = int(probability * 100)

        # -------- COMBINE --------
        final_score = int((rule_score + ml_score) / 2)

        if final_score >= 60:
            result = "PHISHING"
        elif final_score >= 30:
            result = "SUSPICIOUS"
        else:
            result = "SAFE"

        return jsonify({
            "result": result,
            "risk": final_score,
            "reasons": reasons
        })

    except Exception as e:
        print("ERROR IN /scan:", str(e))  # 👈 VERY IMPORTANT

        return jsonify({
            "result": "ERROR",
            "risk": 0,
            "reasons": [str(e)]
        })


# ------------------- RUN SERVER -------------------
if __name__ == "__main__":
    app.run(debug=True)

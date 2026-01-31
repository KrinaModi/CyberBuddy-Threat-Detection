import pickle
import pandas as pd
import csv
import os


from flask import Flask, render_template, request, jsonify, redirect

from utils.preprocessing import clean_text
from utils.features import extract_features


# ------------------- Flask App -------------------
app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend"
)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.csv")


# ------------------- Load ML Model -------------------
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "threat_model.pkl")


with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)


# ------------------- ROUTES -------------------

# 1️⃣ LOGIN PAGE (FIRST PAGE)
@app.route("/", methods=["GET"])
def login_page():
    return render_template("login.html")


# 2️⃣ LOGIN HANDLER
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    # Demo credentials
    if username.lower() == "krina" and password == "1234":
        return redirect("/dashboard")

    # On failure, go back to login page with message
    return render_template("login.html", error="Invalid username or password")



# 3️⃣ DASHBOARD (THREAT DETECTION PAGE)
@app.route("/dashboard")
def dashboard():
    return render_template("index.html")



# 4️⃣ ML SCAN API (AJAX)
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    text = data.get("input", "")

    # Preprocess
    cleaned = clean_text(text)
    features = extract_features(cleaned)

    # Convert to DataFrame
    df = pd.DataFrame([features])

    # Predict
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0][1]

    result = "PHISHING" if prediction == 1 else "SAFE"
    risk = int(probability * 100)

    return jsonify({
        "result": result,
        "risk": risk
    })


# ------------------- RUN SERVER -------------------
if __name__ == "__main__":
    app.run(debug=True)

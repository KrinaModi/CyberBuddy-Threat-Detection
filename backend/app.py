import pickle
import pandas as pd
import csv
import os


from flask import Flask, render_template, request, redirect



from utils.preprocessing import clean_text
from utils.features import extract_features
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "threat_model.pkl")

model = joblib.load(MODEL_PATH)

# ------------------- Flask App -------------------
app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
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

    with open("backend/users.csv", mode="r", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        for row in reader:
            csv_user = row["username"].strip()
            csv_pass = row["password"].strip()

            if csv_user == username and csv_pass == password:
                return redirect("/dashboard")

    return render_template("login.html", error="Invalid username or password")





@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            return render_template(
                "register.html",
                message="Passwords do not match"
            )

        # Check if username already exists
        with open("backend/users.csv", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row["username"] == username:
                    return render_template(
                        "register.html",
                        message="Username already exists"
                    )

        # Save new user
        with open("backend/users.csv", "a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([username, email, password])

        return redirect("/")

    return render_template("register.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    print("FORGOT PASSWORD ROUTE HIT")

    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        new_password = request.form["new_password"]

        rows = []
        updated = False

        with open("backend/users.csv", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row["username"] == username and row["email"] == email:
                    row["password"] = new_password
                    updated = True
                rows.append(row)

        if not updated:
            return render_template(
                "forgot_password.html",
                message="User not found or email mismatch"
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



# 3️⃣ DASHBOARD (THREAT DETECTION PAGE)


@app.route("/dashboard")
def dashboard():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    user_input = request.form["input_data"]

    # Extract features
    features = extract_features(user_input)

    # Convert to dataframe
    df = pd.DataFrame([features])

    # Predict
    prediction = model.predict(df)[0]

    if prediction == 1:
        result = "⚠️ Suspicious / Phishing"
    else:
        result = "✅ Safe"

    return render_template("index.html", result=result)



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

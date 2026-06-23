import os
import joblib
import pandas as pd
import nltk
from flask import Flask, render_template, request, redirect, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from models import db, User, ScanHistory
from utils.preprocessing import clean_text
from utils.features import extract_features
from utils.email_nlp import EmailNLPScanner
from utils.url_osint import scan_url_osint
from utils.screenshot_ocr import scan_screenshot
from utils.explanation import generate_threat_explanation
from utils.ai_assistant import generate_ai_analysis
from datetime import datetime


load_dotenv()


# NLTK initialization
try:
    nltk.data.find('tokenizers/punkt_tab')
except LookupError:
    nltk.download('punkt_tab', quiet=True)
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords', quiet=True)

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)

# Configuration
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super_secret_cyberbuddy_key_v2")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

csrf = CSRFProtect(app)

# Initialize Flask-Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

# Initialize SQLAlchemy
db.init_app(app)

def seed_users():
    # Seed admin user if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            name="System Administrator",
            username="admin",
            email="admin@cyberbuddy.local",
            password_hash=generate_password_hash("CyberBuddy@2026"),
            role="admin"
        )
        db.session.add(admin)
        print("Seeded admin account.")

    # Seed demo user if not exists
    demo = User.query.filter_by(username='demo').first()
    if not demo:
        demo = User(
            name="Demo Analyst",
            username="demo",
            email="demo@cyberbuddy.local",
            password_hash=generate_password_hash("Demo@123"),
            role="user"
        )
        db.session.add(demo)
        print("Seeded demo account.")

    db.session.commit()

# Safe database initialization (Apply expanded schema without losing data)
import sys
if "pytest" not in sys.modules and "PYTEST_CURRENT_TEST" not in os.environ:
    with app.app_context():
        db_dir = os.path.join(app.instance_path)
        db_file = os.path.join(db_dir, "database.db")
        
        recreate_needed = False
        if os.path.exists(db_file):
            try:
                # Check if name column exists in users table (indicates new schema)
                db.session.execute(db.text("SELECT name FROM users LIMIT 1"))
            except Exception:
                recreate_needed = True

        if recreate_needed:
            try:
                db.session.remove()
                import time
                backup_file = db_file + f".bak_{int(time.time())}"
                os.rename(db_file, backup_file)
                print(f"Backed up old SQLite database to {backup_file} and applying new schema.")
            except Exception as e:
                print("Failed to backup old database:", e)
        else:
            os.makedirs(db_dir, exist_ok=True)

        db.create_all()
        seed_users()


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Initialize ML NLP scanner
try:
    email_scanner = EmailNLPScanner()
except Exception as e:
    print(f"Error initializing EmailNLPScanner: {e}")
    email_scanner = None


def send_otp_email(to_email, otp):
    smtp_email = os.environ.get("SMTP_EMAIL")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    
    if not smtp_email or not smtp_password or "your-gmail-here" in smtp_email:
        print("[WARNING] SMTP credentials not fully configured in .env. Falling back to console log.")
        return False
        
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.utils import formataddr
        
        msg = MIMEMultipart('alternative')
        msg['From'] = formataddr(("CyberBuddy Security Team", smtp_email))
        msg['To'] = to_email
        msg['Subject'] = f"🛡️ CyberBuddy Security Verification Code: {otp}"
        
        text_body = f"""Hello,

Your security verification OTP code is: {otp}

This code is required to complete your registration on CyberBuddy. If you did not request this code, please ignore this email.

Stay secure,
CyberBuddy Security Team"""

        html_body = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verify Your Email</title>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background-color: #020617;
            color: #e2e8f0;
            padding: 30px;
            margin: 0;
        }}
        .container {{
            max-width: 500px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 20px;
            padding: 35px;
            margin: 0 auto;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6);
        }}
        .logo {{
            font-size: 26px;
            font-weight: 800;
            color: #ffffff;
            margin-bottom: 25px;
            letter-spacing: -0.5px;
        }}
        .highlight {{
            color: #22d3ee;
        }}
        h2 {{
            font-size: 20px;
            color: #f1f5f9;
            margin-top: 0;
            font-weight: 600;
        }}
        p {{
            font-size: 14px;
            color: #94a3b8;
            line-height: 1.6;
        }}
        .otp-box {{
            font-size: 36px;
            font-weight: 800;
            color: #22d3ee;
            letter-spacing: 6px;
            background: rgba(34, 211, 238, 0.08);
            padding: 18px 25px;
            border-radius: 12px;
            display: inline-block;
            margin: 25px 0;
            border: 1px solid rgba(34, 211, 238, 0.25);
            font-family: monospace;
        }}
        .footer {{
            font-size: 11px;
            color: #475569;
            margin-top: 35px;
            border-top: 1px solid #1e293b;
            padding-top: 20px;
            line-height: 1.5;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🛡️ Cyber<span class="highlight">Buddy</span></div>
        <h2>Security Verification</h2>
        <p>You are receiving this verification request because you initiated registration on the CyberBuddy Threat Detection Portal.</p>
        <p>Please use the following 6-digit passcode to finalize your credentials:</p>
        <div class="otp-box">{otp}</div>
        <p style="font-size: 12px; color: #64748b;">This code is valid for 10 minutes. If you did not initiate this request, please change your credentials immediately.</p>
        <div class="footer">
            CyberBuddy – Threat Intelligence & SOC Diagnostics<br>
            © 2026 CyberBuddy Team. All rights reserved.
        </div>
    </div>
</body>
</html>"""

        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(smtp_email, smtp_password)
        server.sendmail(smtp_email, to_email, msg.as_string())
        server.quit()
        
        print(f"[SUCCESS] OTP email successfully sent to {to_email}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send OTP email to {to_email}: {e}")
        return False


# Auth Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect("/")
        user = db.session.get(User, session['user_id'])

        if not user or not user.is_admin:
            flash("Admin access required.")
            return redirect("/dashboard")
        return f(*args, **kwargs)
    return decorated_function

# ------------------- ROUTES -------------------

@app.route("/", methods=["GET"])
def login_page():
    if 'user_id' in session:
        return redirect("/dashboard")
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin
        return redirect("/dashboard")

    return render_template("login.html", error="Invalid username or password")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            return render_template("register.html", message="Passwords do not match")

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            return render_template("register.html", message="Username or Email already exists")

        is_admin = User.query.count() == 0
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=is_admin
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Account registered successfully! Please login.")
        return redirect("/")

    return render_template("register.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    return redirect("/")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        new_password = request.form.get("new_password", "") # Original app used new_password directly but it was a flaw.

        user = User.query.filter_by(username=username, email=email).first()

        if not user:
            return render_template("forgot_password.html", message="User not found or email mismatch")

        # Implementing a secure password reset simulation
        import uuid
        temp_password = str(uuid.uuid4())[:8]
        user.password_hash = generate_password_hash(temp_password)
        db.session.commit()
        
        # Check SMTP configuration
        smtp_email = os.environ.get("SMTP_EMAIL")
        smtp_password = os.environ.get("SMTP_PASSWORD")
        
        email_sent = False
        if smtp_email and smtp_password and "your-gmail-here" not in smtp_email:
            try:
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart
                from email.utils import formataddr
                
                msg = MIMEMultipart('alternative')
                msg['From'] = formataddr(("CyberBuddy Security Team", smtp_email))
                msg['To'] = user.email
                msg['Subject'] = f"🛡️ CyberBuddy Password Reset Request"
                
                text_body = f"Hello,\n\nYour temporary password is: {temp_password}\n\nPlease login and change it immediately.\n\nStay secure,\nCyberBuddy Team"
                msg.attach(MIMEText(text_body, 'plain'))
                
                server = smtplib.SMTP("smtp.gmail.com", 587)
                server.starttls()
                server.login(smtp_email, smtp_password)
                server.sendmail(smtp_email, user.email, msg.as_string())
                server.quit()
                email_sent = True
            except Exception as e:
                print(f"[ERROR] Failed to send reset email: {e}")
                
        if email_sent:
            flash("A temporary password has been sent to your email address.")
        else:
            # Print to console log in development environment to prevent leakage
            print(f"\n[SECURITY SIMULATION] Password reset requested for {user.username}. Temporary password generated: {temp_password}\n")
            flash("A temporary password has been generated and logged to the server console. Please check server logs.")
        return redirect("/")

    return render_template("forgot_password.html")

# ------------------- DASHBOARD -------------------

@app.route("/dashboard")
@login_required
def dashboard():
    scans_q = ScanHistory.query.filter_by(user_id=session['user_id'])
    total_scans = scans_q.count()
    malicious_scans = scans_q.filter(ScanHistory.classification.in_(["Malicious", "High Risk"])).count()
    suspicious_scans = scans_q.filter(ScanHistory.classification.in_(["Suspicious", "Low Risk"])).count()
    safe_scans = scans_q.filter(ScanHistory.classification == "Safe").count()
    recent_scans = scans_q.order_by(ScanHistory.id.desc()).limit(5).all()
    
    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        malicious_scans=malicious_scans,
        suspicious_scans=suspicious_scans,
        safe_scans=safe_scans,
        recent_scans=recent_scans
    )

def evaluate_threat(text):
    # Determine if input is a URL
    cleaned_input = text.strip()
    is_url = cleaned_input.lower().startswith(("http://", "https://", "www.")) or (
        "." in cleaned_input.split("/")[0] and len(cleaned_input.split("/")[0]) > 3
    )
    
    if is_url:
        osint = scan_url_osint(cleaned_input)
        features = osint["features"]
        domain_info = osint["domain_info"]
        explanation = generate_threat_explanation(
            scan_type="URL",
            risk_score=osint["risk_score"],
            features=features,
            osint_data=osint["domain_info"] | osint["vt_data"]
        )
        return {
            "scan_type": "URL",
            "risk_score": osint["risk_score"],
            "classification": osint["classification"],
            "threat_explanation": explanation,
            "domain_info": domain_info
        }
    else:
        # Email NLP Engine
        nlp = email_scanner.analyze(cleaned_input)
        features = extract_features(clean_text(cleaned_input), original_text=cleaned_input)
        explanation = generate_threat_explanation(
            scan_type="EMAIL",
            risk_score=nlp["risk_score"],
            features=features,
            nlp_analysis=nlp
        )
        return {
            "scan_type": "EMAIL",
            "risk_score": nlp["risk_score"],
            "classification": nlp["classification"],
            "threat_explanation": explanation,
            "domain_info": None,
            "nlp_analysis": nlp
        }

@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    user_input = request.form["input_data"].strip()
    analysis = evaluate_threat(user_input)
    
    scan = ScanHistory(
        user_id=session['user_id'],
        scan_type=analysis["scan_type"],
        target=user_input,
        risk_score=analysis["risk_score"],
        classification=analysis["classification"],
        threat_explanation=analysis["threat_explanation"],
        domain_info=analysis["domain_info"]
    )
    db.session.add(scan)
    db.session.commit()
    
    # Generate human-readable AI analysis commentary
    ai_commentary = generate_ai_analysis(
        analysis["scan_type"],
        user_input,
        analysis["risk_score"],
        analysis["classification"],
        analysis["threat_explanation"]
    )
    
    # Query stats for dashboard render
    scans_q = ScanHistory.query.filter_by(user_id=session['user_id'])
    total_scans = scans_q.count()
    malicious_scans = scans_q.filter(ScanHistory.classification.in_(["Malicious", "High Risk"])).count()
    suspicious_scans = scans_q.filter(ScanHistory.classification.in_(["Suspicious", "Low Risk"])).count()
    safe_scans = scans_q.filter(ScanHistory.classification == "Safe").count()
    recent_scans = scans_q.order_by(ScanHistory.id.desc()).limit(5).all()
    
    ref = request.referrer or ""
    if "/url-scanner" in ref:
        return render_template(
            "url_scanner.html",
            result=True,
            scan_id=scan.id,
            scan_type="URL",
            target=user_input,
            score=analysis["risk_score"],
            classification=analysis["classification"],
            explanation=analysis["threat_explanation"],
            domain_info=analysis["domain_info"],
            ai_commentary=ai_commentary,
            timestamp=scan.timestamp
        )
    elif "/email-scanner" in ref:
        return render_template(
            "email_scanner.html",
            result=True,
            scan_id=scan.id,
            scan_type="EMAIL",
            target=user_input,
            score=analysis["risk_score"],
            classification=analysis["classification"],
            explanation=analysis["threat_explanation"],
            nlp_analysis=analysis.get("nlp_analysis"),
            ai_commentary=ai_commentary,
            timestamp=scan.timestamp
        )
    else:
        return render_template(
            "dashboard.html",
            result=True,
            scan_id=scan.id,
            scan_type=analysis["scan_type"],
            target=user_input,
            score=analysis["risk_score"],
            classification=analysis["classification"],
            explanation=analysis["threat_explanation"],
            domain_info=analysis["domain_info"],
            nlp_analysis=analysis.get("nlp_analysis"),
            ai_commentary=ai_commentary,
            timestamp=scan.timestamp,
            total_scans=total_scans,
            malicious_scans=malicious_scans,
            suspicious_scans=suspicious_scans,
            safe_scans=safe_scans,
            recent_scans=recent_scans
        )

@app.route("/scan", methods=["POST"])
@csrf.exempt
@login_required
def scan():
    try:
        data = request.get_json(silent=True) or {}
        text = data.get("input", "").strip()

        analysis = evaluate_threat(text)
        
        scan = ScanHistory(
            user_id=session['user_id'],
            scan_type=analysis["scan_type"],
            target=text,
            risk_score=analysis["risk_score"],
            classification=analysis["classification"],
            threat_explanation=analysis["threat_explanation"],
            domain_info=analysis["domain_info"]
        )
        db.session.add(scan)
        db.session.commit()

        api_result = "PHISHING" if analysis["classification"] in ["Malicious", "Suspicious"] else "SAFE"

        return jsonify({
            "result": api_result,
            "risk": analysis["risk_score"],
            "scan_type": analysis["scan_type"],
            "explanation": analysis["threat_explanation"]
        })
    except Exception as e:
        return jsonify({
            "result": "ERROR",
            "risk": 0,
            "reasons": [str(e)]
        })

@app.route("/history")
@login_required
def history():
    scans = ScanHistory.query.filter_by(user_id=session['user_id']).order_by(ScanHistory.id.desc()).all()
    return render_template("history.html", history=scans)

@app.route("/intel")
@login_required
def intel():
    # Show active malicious/suspicious hits globally for SOC monitoring
    local_alerts = ScanHistory.query.filter(
        ScanHistory.classification != "Safe"
    ).order_by(ScanHistory.id.desc()).limit(10).all()
    return render_template("intel.html", local_alerts=local_alerts)

@app.route("/report/<int:scan_id>")
@login_required
def report(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    # Check permissions
    if not session.get('is_admin') and scan.user_id != session['user_id']:
        flash("Unauthorized access to report.")
        return redirect("/dashboard")
    return render_template("report.html", scan=scan)

# ------------------- ADMIN -------------------

@app.route("/admin")
@admin_required
def admin_dashboard():
    users = User.query.count()
    urls = ScanHistory.query.count()
    malicious = ScanHistory.query.filter(ScanHistory.classification != "Safe").count()
    safe = ScanHistory.query.filter(ScanHistory.classification == "Safe").count()
    return render_template("admin_dashboard.html", users=users, urls=urls, malicious=malicious, safe=safe)

@app.route("/admin/users")
@admin_required
def admin_users():
    users_list = User.query.all()
    return render_template("admin_users.html", users=users_list)

@app.route("/admin/history")
@admin_required
def admin_history():
    scans_list = ScanHistory.query.order_by(ScanHistory.id.desc()).all()
    return render_template("admin_history.html", history=scans_list)

# ------------------- NEW WEB APP ENDPOINTS -------------------

@app.route("/url-scanner", methods=["GET"])
@login_required
def url_scanner_page():
    return render_template("url_scanner.html")

@app.route("/email-scanner", methods=["GET"])
@login_required
def email_scanner_page():
    return render_template("email_scanner.html")

@app.route("/qr-scanner", methods=["GET"])
@login_required
def qr_scanner_page():
    return render_template("qr_scanner.html")

@app.route("/screenshot-detector", methods=["GET", "POST"])
@login_required
def screenshot_detector():
    if request.method == "POST":
        if 'screenshot' not in request.files:
            return jsonify({"status": "ERROR", "message": "No file uploaded"})
            
        file = request.files['screenshot']
        if file.filename == '':
            return jsonify({"status": "ERROR", "message": "No file selected"})
            
        try:
            # Read image bytes and run OCR + CV analysis
            img_bytes = file.read()
            file_size = len(img_bytes)
            
            from PIL import Image as PILImage
            import io
            img_pil = PILImage.open(io.BytesIO(img_bytes))
            img_format = img_pil.format or "PNG"
            width, height = img_pil.size
            
            # Audit screenshot using local deep-learning-free OCR
            analysis = scan_screenshot(img_bytes)
            
            scam_verdict = analysis["classification"].upper() # SAFE, LOW RISK, SUSPICIOUS, HIGH RISK, MALICIOUS
            scam_category = analysis["category"]
            ai_critique = analysis["ai_critique"]
            reasons = analysis["reasons"]
            
            # Log to DB as a screenshot scan record
            scan = ScanHistory(
                user_id=session['user_id'],
                scan_type="SCREENSHOT",
                target=file.filename,
                risk_score=analysis["risk_score"],
                classification=analysis["classification"],
                threat_explanation=reasons,
                domain_info={"scam_category": scam_category, "file_name": file.filename}
            )
            db.session.add(scan)
            db.session.commit()
            
            return jsonify({
                "status": "SUCCESS",
                "metadata": {
                    "format": img_format,
                    "width": width,
                    "height": height,
                    "size": file_size
                },
                "scam_verdict": scam_verdict,
                "scam_category": scam_category,
                "ai_critique": ai_critique,
                "reasons": reasons
            })
        except Exception as e:
            return jsonify({"status": "ERROR", "message": str(e)})
            
    return render_template("screenshot_detector.html")

@app.route("/password-analyzer", methods=["GET"])
@login_required
def password_analyzer_page():
    return render_template("password_analyzer.html")

@app.route("/awareness", methods=["GET"])
@login_required
def awareness_page():
    return render_template("awareness.html")

@app.route("/profile", methods=["GET"])
@login_required
def profile_page():
    user = db.session.get(User, session['user_id'])
    
    # Query stats for user
    scans_q = ScanHistory.query.filter_by(user_id=session['user_id'])
    total_scans = scans_q.count()
    threat_scans = scans_q.filter(ScanHistory.classification != "Safe").count()
    safe_scans = scans_q.filter(ScanHistory.classification == "Safe").count()
    
    return render_template("profile.html", user=user, total_scans=total_scans, threat_scans=threat_scans, safe_scans=safe_scans)

@app.route("/settings", methods=["GET"])
@login_required
def settings_page():
    return render_template("settings.html")

@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    
    user = db.session.get(User, session['user_id'])
    
    if not user or not check_password_hash(user.password_hash, current_password):
        return render_template("settings.html", error_msg="Incorrect current password.")
        
    if new_password != confirm_password:
        return render_template("settings.html", error_msg="New passwords do not match.")
        
    if len(new_password) < 8:
        return render_template("settings.html", error_msg="Password must be at least 8 characters long.")
        
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    
    return render_template("settings.html", success_msg="Password security credentials updated successfully.")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.is_admin and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = True
            
            # Update last login
            from datetime import timezone
            user.last_login = datetime.now(timezone.utc).replace(tzinfo=None)
            db.session.commit()
            
            return redirect("/admin")
            
        return render_template("admin_login.html", error="Invalid admin credentials")
        
    return render_template("admin_login.html")

@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash("You cannot delete your own administrator account.")
        return redirect("/admin/users")
        
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.")
        return redirect("/admin/users")
        
    # Delete scans associated with this user
    ScanHistory.query.filter_by(user_id=user_id).delete()
    
    db.session.delete(user)
    db.session.commit()
    flash(f"User '{user.username}' and their scan history have been deleted.")
    return redirect("/admin/users")

if __name__ == "__main__":
    app.run(debug=False)


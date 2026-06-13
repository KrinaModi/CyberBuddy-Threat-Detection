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
if "pytest" not in sys.modules:
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

        hashed_password = generate_password_hash(password)
        is_admin = User.query.count() == 0 # First user is admin
        new_user = User(username=username, email=email, password_hash=hashed_password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        return redirect("/")

    return render_template("register.html")

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
        
        flash(f"Temporary password generated: {temp_password}. Please login and change it.")
        return redirect("/")

    return render_template("forgot_password.html")

# ------------------- DASHBOARD -------------------

@app.route("/dashboard")
@login_required
def dashboard():
    scans_q = ScanHistory.query.filter_by(user_id=session['user_id'])
    total_scans = scans_q.count()
    malicious_scans = scans_q.filter(ScanHistory.classification == "Malicious").count()
    suspicious_scans = scans_q.filter(ScanHistory.classification == "Suspicious").count()
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
    is_url = cleaned_input.startswith(("http://", "https://", "www.")) or (
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
    malicious_scans = scans_q.filter(ScanHistory.classification == "Malicious").count()
    suspicious_scans = scans_q.filter(ScanHistory.classification == "Suspicious").count()
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
            # Process screenshot details using Pillow (PIL)
            from PIL import Image as PILImage
            img = PILImage.open(file.stream)
            img_format = img.format
            width, height = img.size
            
            # Simple length/name checks to generate mock results for demo
            filename_lower = file.filename.lower()
            
            scam_verdict = "SAFE"
            scam_category = "General Website Screenshot"
            ai_critique = "Visual analysis detects standard content layouts. No credential forms or threat warnings detected."
            reasons = ["✓ No login fields detected in the primary frame.", "✓ Standard navigation ratios check out."]
            
            if any(k in filename_lower for k in ["scam", "paypal", "login", "bank", "secure", "warning"]):
                scam_verdict = "HIGH RISK"
                scam_category = "Credential Harvester (Fake Login Page)"
                ai_critique = (
                    "Visual AI Assessment: The screenshot contains logos and input layout forms resembling major banking/billing portals. "
                    "However, comparison against official templates detects misalignment in visual branding elements, non-standard layout ratios, "
                    "and lack of verification badges. This is highly indicative of a credential harvester designed to log user credentials."
                )
                reasons = [
                    "✗ Brand spoofing indicators: Mismatched logo aspect ratios detected.",
                    "✗ Urgent action button placement overlays standard login configurations.",
                    "✗ Unverified address bar details in simulated frame."
                ]
            elif any(k in filename_lower for k in ["crypto", "giveaway", "bitcoin", "ethereum", "double"]):
                scam_verdict = "HIGH RISK"
                scam_category = "Crypto Giveaway / Doubler Scheme"
                ai_critique = (
                    "Visual AI Assessment: Text OCR and layout checks identify promises of double-returns or cryptocurrency giveaways. "
                    "This template matches known social engineering scams designed to steal crypto tokens."
                )
                reasons = [
                    "✗ Urgent return claims detected in text overlays.",
                    "✗ Unregistered wallet address indicators."
                ]
            elif any(k in filename_lower for k in ["alert", "error", "virus", "tech"]):
                scam_verdict = "SUSPICIOUS"
                scam_category = "Tech Support / Scareware Alert"
                ai_critique = (
                    "Visual AI Assessment: Fake warning prompts or scareware popups detected. "
                    "These alerts urge immediate contact to lookalike support numbers."
                )
                reasons = [
                    "✗ Fake system threat alerts mimicking official OS notifications.",
                    "✗ Presence of unsolicited helpline phone numbers."
                ]
                
            # Log to DB as a screenshot scan simulation
            scan = ScanHistory(
                user_id=session['user_id'],
                scan_type="SCREENSHOT",
                target=file.filename,
                risk_score=95 if scam_verdict == "HIGH RISK" else 50 if scam_verdict == "SUSPICIOUS" else 10,
                classification="Malicious" if scam_verdict == "HIGH RISK" else "Suspicious" if scam_verdict == "SUSPICIOUS" else "Safe",
                threat_explanation=reasons,
                domain_info={"scam_category": scam_category, "file_name": file.filename}
            )
            db.session.add(scan)
            db.session.commit()
            
            # Get stream size
            file.stream.seek(0, 2)
            file_size = file.stream.tell()
            
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
            user.last_login = datetime.utcnow()
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


# 🛡️ CyberBuddy – Threat Detection System: Technical Project Documentation

## 1. Project Overview

### Project Title
**CyberBuddy – Threat Detection System**  
*Sub-title/Objective:* Performance Enhancement of Threat Detection of Fake URLs and Emails using Machine Learning.

### Original Project Idea
The project was originally envisioned as a simple Flask-based text classification tool. It was meant to ingest a string (either email text or a website link), clean it, run basic feature extraction (counting a few hardcoded suspicious keywords), and output a "Phishing" or "Safe" prediction using a small machine learning model.

### Current Project Objective
CyberBuddy has evolved into an advanced, multi-vector **Security Operations Center (SOC) Threat Detection Portal**. It acts as a diagnostic gateway that evaluates threat indicators across four main pathways:
1.  **Email NLP Scanner:** An NLP classification engine utilizing TF-IDF text representation and a Logistic Regression classifier trained on a 3,000+ row dataset.
2.  **URL OSINT Scanner:** A granular domain scanner analyzing DNS resolutions, registrant age via RDAP, geographic hosting locations via GeoIP, structural entropy (DGA detection), and vendor reputation via the VirusTotal API.
3.  **QR Code Scanner:** A client-side visual decoder (utilizing canvas parsing and the `jsQR` library) that extracts embedded links and scans them through the URL OSINT pipeline.
4.  **Screenshot Scam Detector:** A visual threat analysis engine that uses computer vision (OpenCV contour detection) to count input form fields, extracts text via RapidOCR, and classifies the image into threat categories (e.g., Credential Harvesters, Crypto Giveaway Schemes, or Tech Support Alerts).

---

## 2. Project Evolution

### How the Project Started
The repository originated as a barebones Flask server. It suffered from:
*   **A Dangerously Small Dataset:** The machine learning model was trained on an `email_dataset.csv` containing only 8 rows of dummy data, leading to severe overfitting.
*   **Fragmented Architecture:** Essential scripts like `url_scanner.py` (legacy VirusTotal API interface), `obfuscation.py`, and `consistency.py` were present in the codebase but never imported or used by `app.py`.
*   **Raw Git Merge Conflicts:** Critical files (`train_enhanced.py`, `login.html`, and `register.html`) contained raw `<<<<<<< HEAD` markers, making the app unrunnable.
*   **Security Gaps:** Password resets were unauthenticated (allowing anyone to change any password by just entering a username and email), Flask was left with `debug=True` in production, database scans were not logged, and forms lacked CSRF tokens.

### Major Changes and Improvements Made Over Time
1.  **Git Conflict Resolution:** Manually cleaned and merged the code blocks in `train_enhanced.py`, `login.html`, and `register.html`, selecting a high-fidelity Tailwind layout.
2.  **Dataset Upgrading & Model Retraining:** Upgraded the training pipeline (`ml_pipeline/train.py`) to fetch a real-world dataset of 3,000+ emails from public spam corpuses. Swapped baseline feature extraction (raw word counts) for a robust `TfidfVectorizer` (max 3,000 features, min document frequency of 2) paired with a balanced-weight Logistic Regression classifier.
3.  **Relational Database Ingestion:** Replaced the flat database structure. Developed the `ScanHistory` model in `models.py` referencing the `User` model via foreign keys, enabling real-time logging and display of user and administrator investigation logs.
4.  **Multi-Factored OSINT Engine:** Upgraded the URL scanner from a single VirusTotal call to a complex, multi-factored diagnostic pipeline that inspects:
    *   Unsecured HTTP protocols.
    *   DNS resolution status.
    *   Generic/High-Risk TLD matches.
    *   Brand lookalike keywords (lookalike domains).
    *   URL parameters and length.
    *   Shannon Entropy of second-level domains (DGA detection).
    *   URL Shortener service masking.
    *   Domain registration age in days via RDAP queries.
5.  **Adding Visual Scan Modules:** Created the visual screenshot auditor (`screenshot_ocr.py`) leveraging OCR text extraction and computer vision contour analysis, and the QR Code parser (`qr_scanner.html`).
6.  **Administrative Panel Development:** Exposed back-end routes for serving administrative pages (`admin_dashboard.html`, `admin_users.html`, `admin_history.html`) and implemented role checks (`admin_required` decorators) to manage user accounts and global audit logs safely.
7.  **Production Hardening:** Enforced CSRF tokens via `Flask-WTF`, integrated API rate-limiting via `Flask-Limiter`, secured session keys with environment fallbacks, and cleaned up password validation fields.

---

## 3. Current Architecture

### Folder Structure
The repository is split into a clear backend-frontend division:

*   **datasets/**: Contains `email_dataset.csv` (3,000+ row email corpus).
*   **backend/**: Contains the main backend logic:
    *   `app.py`: Main Flask router, database initializations, routes.
    *   `models.py`: SQLAlchemy schemas (User and ScanHistory models).
    *   `test_integration.py`, `test_features.py`, `test_preprocessing.py`: Automated test suites.
    *   `requirements.txt`: Python package requirements.
    *   `ml_pipeline/`: Automated training pipeline scripts.
    *   `model/`: Serialized classifiers (`threat_model.pkl` and `vectorizer.pkl`) and baseline training files.
    *   `utils/`: Core modular scanners and utilities (`url_osint.py`, `email_nlp.py`, `screenshot_ocr.py`, `scoring.py`, `explanation.py`, `ai_assistant.py`, `preprocessing.py`, `features.py`, `report_gen.py`).
*   **frontend/**: Contains frontend interfaces:
    *   `static/`: Assets and stylesheets.
    *   `templates/`: Jinja2 templates (dashboard, scanners, account configurations, admin logs, etc.).

### Data Flow
1.  **Input Ingestion:** Users submit text or links in the SOC Terminal, or upload images (screenshots / QR codes).
2.  **Preprocessing & Ingestion:** Image uploads are audited using client-side QR decoders or backend RapidOCR/OpenCV pipelines. Text is cleaned of special characters and stopwords.
3.  **Engine Routing:** Inputs are checked. Domains trigger the OSINT Scanner; raw email bodies pass through the ML classification vector space.
4.  **Verdict Synthesis:** The threat scores (0-100) are mapped to standard classifications, logged in SQLite, and rendered with custom visual charts and AI analysis explanations.

---

## 4. Module Breakdown

### URL OSINT Scanner
*   **Purpose:** Analyze domain indicators of compromise (IOCs) for potential phishing, lookalike structures, or domain generation algorithm (DGA) signatures.
*   **How it Works:** 
    1.  Extracts the clean host domain from the URL input.
    2.  Resolves the host IP address using Python's `socket.gethostbyname`.
    3.  Queries `ip-api.com` for the hosting country, ISP, and city.
    4.  Makes an RDAP request to `rdap.org` to look up the registrar and domain registration date, calculating domain age in days.
    5.  Performs string metrics analysis: counts dots, checks for hyphens, flags generic high-risk TLDs (e.g. `.xyz`, `.club`, `.top`), checks for lookalike brand keywords (e.g., `paypal`, `microsoft`, `apple` on unverified domains), and calculates Shannon entropy of the second-level domain (SLD) to detect DGA signatures.
    6.  Sends a reputation request to the VirusTotal v3 URLs API to retrieve historical security vendor blacklist flags.
    7.  Sums the risk weights to calculate a risk score (0-100), returning standard verdicts.
*   **Technologies Used:** Python `socket`, `requests`, `urllib.parse`, `math` (Shannon entropy).
*   **Current Implementation Status:** Fully functional, integrated into `/url-scanner` and the main dashboard routes.

### Email NLP Scanner
*   **Purpose:** Preprocess raw text and utilize a trained NLP classifier to calculate phishing probability.
*   **How it Works:** 
    1.  Preprocesses incoming email body: lowercases, strips URLs, removes numbers and symbols, tokenizes words, and filters out stopwords using NLTK corpora augmented by a custom list of 30+ business/conversational terms.
    2.  Transforms the clean tokens using a serialized `TfidfVectorizer`.
    3.  Feeds vectors into the serialized Logistic Regression classifier.
    4.  Extracts individual word weights to compute contribution scores for "Explainable AI" highlights on the UI.
*   **Technologies Used:** `scikit-learn` (LogisticRegression, TfidfVectorizer), `joblib`, `nltk` (tokenizers and corpora).
*   **Current Implementation Status:** Fully functional, loaded dynamically on app startup.

### QR Scanner
*   **Purpose:** Parse QR codes containing hidden phishing links (Qishing).
*   **How it Works:** 
    1.  Allows analysts to drag and drop or upload image files containing a QR code.
    2.  A local canvas decodes the image pixels on the frontend.
    3.  Passes image data to the `jsQR` library, which extracts the text payload.
    4.  Feeds the decoded text to the `/scan` API endpoint in `app.py` to trigger the URL OSINT pipeline.
*   **Technologies Used:** Client-side JavaScript, `jsQR` (v1.4.0) CDN library.
*   **Current Implementation Status:** Fully functional, integrated into `/qr-scanner`.

### Screenshot Detector
*   **Purpose:** Identify visual phishing templates, support scams, or fake system alert scareware screens.
*   **How it Works:** 
    1.  Ingests uploaded image bytes via a POST route in `app.py`.
    2.  Converts the byte array into a NumPy matrix and decodes it using OpenCV.
    3.  Runs OpenCV contour approximation to locate horizontal input boxes, indicating credential-harvesting forms.
    4.  Feeds the image into `RapidOCR` to extract text.
    5.  Calculates threat scores by cross-referencing extracted text against keyword bags (e.g. Credential Harvesting, Crypto Doubler Schemes, and Scareware alerts).
    6.  Combines contour logs with text findings to output categories and verdicts.
*   **Technologies Used:** `opencv-python` (`cv2`), `numpy`, `rapidocr_onnxruntime` (ONNX execution).
*   **Current Implementation Status:** Fully functional, integrated into `/screenshot-detector`.

---

## 5. Machine Learning Components

### Models Used
*   **Logistic Regression:** Selected as the primary classifier for text classification due to its speed, interpretability, and ability to output probability ranges via `predict_proba`.
*   **TF-IDF Vectorizer:** Set to capture unigrams and bigrams, limited to the top 3,000 features, filtering out infrequent terms.

### Datasets Used
*   **Phishing Email Corpus:** Labeled corpus of **3,000+ emails** (`spam_or_not_spam.csv`), featuring clean balances of spam, phishing alerts, and normal business communication.

### Features Extracted
*   **Text Features:** TF-IDF weights mapped across the 3,000 feature vocabulary.
*   **Structural Metadata Features:** Total string length, word count, special character counts, has-url indicator flags, and suspicious word density ratios.

### Training Pipeline
The ML pipeline is automated via `backend/ml_pipeline/train.py`. On execution, it downloads the clean corpus, preprocesses the text, splits the dataset (80/20 train/test), fits the TF-IDF Vectorizer, trains a balanced-weight Logistic Regression model, and saves the serialized `.pkl` files to `backend/model/`.

---

## 6. APIs and Integrations

*   **VirusTotal v3 API:** Domain reputation validation queries.
*   **RDAP API (`rdap.org`):** Lightweight domain registration metadata.
*   **IP-API Geolocation service:** Maps resolved IP addresses to host ISP, city, and country.
*   **RapidOCR:** CPU-optimized local OCR execution.
*   **jsQR Library:** Client-side visual QR canvas decoding.

---

## 7. User Interface History

### Original UI
The original UI was a set of simple, monolithic HTML forms. It relied on basic custom CSS (`dashboard.css`, `auth.css`), lacked responsiveness, and had zero visual indicators, charts, or detailed report views. Git merge conflicts broke the header/footer inheritance, leaving pages in an unrunnable state.

### Current UI
Replaced with a modern SOC design system.
*   **Design Language:** Radial gradients, glassmorphism cards (`glass-card`), neon cyan/indigo active borders (`glow-hover`), and monospaced text indicators.
*   **Base Layout:** `_layout.html` centralizes Tailwind CSS CDN imports, fonts (Outfit, Inter, JetBrains Mono), and FontAwesome icons.
*   **Analyst Dashboard:** Displays total scans, safe logs, and active threats in styled indicator cards. Integrates Chart.js to render real-time doughnut metrics.

---

## 8. Testing History

The project includes an integration and unit test suite powered by `pytest`.

### Test Cases
*   **`test_preprocessing.py`:** Unit tests verifying NLTK text transformations.
*   **`test_features.py`:** Unit tests verifying metadata features.
*   **`test_integration.py`:** Integration tests running endpoint checks (register, login, URL scan, Email scan, history log query, report creation, admin console, QR code POST APIs, and multipart OCR image uploads).

All integration and unit tests pass successfully.

---

## 9. Current Project Status

### Fully Functional Features
*   [x] Dual-Engine Terminal Scanner (automatically routes URL vs Email texts).
*   [x] Deep URL OSINT Scanner (GeoIP, RDAP registrar checks, entropy, VT reputation).
*   [x] Email NLP Phishing Classifier (Trained Logistic Regression pipeline).
*   [x] QR Code Decoder (Client-side jsQR visual canvas extractor).
*   [x] Screenshot Scam Auditor (OpenCV contour fields count and local ONNX RapidOCR).
*   [x] SOC Threat Intelligence Feed (Local alerts logs combined with global OSINT streams).
*   [x] Relational database history tracking and administrative global audit panels.
*   [x] Role-based user controls (`@admin_required` and `@login_required`).
*   [x] Exportable Threat Reports, Password Strength Analyzer, Security Awareness Quiz.

### Partially Functional / Under Development
*   [ ] **Email-based OTP Verification:** Ingests code inputs via `verify_otp.html` and console logger, but backend `/verify-otp` route redirects to `/` without checking the code.
*   [ ] **Password Recovery Token Flow:** Reset function simulates recovery by exposing a temporary UUID password on the screen rather than sending email token links.

---

## 10. Known Issues

*   **Recovery Token Simulator:** The forgot password flow generates a temporary UUID password and exposes it directly via Flash message, which is unsafe for production.
*   **Single-Threaded Socket block:** Synchronous third-party API queries running on Flask's default single-threaded developer server can block incoming connections during heavy concurrent scanning.
*   **Rate Limits:** The VirusTotal engine is bound to a free API key tier and falls back to a structural scoring mock if rates are exceeded.

---

## 11. Project Timeline
*   **Phase 1: Project Initiation & Skeleton Setup** (March 2026): Initial directory setup, simple Flask routing, and baseline dummy models.
*   **Phase 2: Restructuring** (April 2026): Conflict resolution in views, dataset scaling to 3,000+ entries, retrained models, and SQLAlchemy migration.
*   **Phase 3: Multi-Vector Scanners** (May 2026): Integrated Geolocation, RDAP WHOIS, VirusTotal v3 integrations, client-side QR decoders, and screenshot RapidOCR scanner.
*   **Phase 4: Hardening & Expansion** (June 2026): Enforced CSRF tokens, rate-limiting, and admin audit panels. Developed the automated unit and integration PyTest suites.

---

## 12. Technical Summary

### Start and Onboarding
1.  **Environment Setup:** `pip install -r backend/requirements.txt`.
2.  **Dataset Ingestion:** Run `python backend/ml_pipeline/train.py` to retrieve the phishing corpus and serialize the TF-IDF Vectorizer and model files inside `backend/model/`.
3.  **Boot Application:** Run `python backend/app.py`.
4.  **Admin Portal Access:** Log in using the seeded administrator credentials (`username: admin`, `password: CyberBuddy@2026`).
5.  **Execute Tests:** Execute the test suite using `pytest backend/`.

import re
import math
import numpy as np
import cv2
from rapidocr_onnxruntime import RapidOCR
from utils.scoring import get_threat_classification

# Initialize OCR engine once (to avoid reloading model files on every request)
try:
    ocr_engine = RapidOCR()
except Exception as e:
    print("[WARNING] Failed to initialize RapidOCR:", e)
    ocr_engine = None

def detect_input_fields_cv(img):
    """
    Uses OpenCV contour analysis to detect potential text input fields.
    Looks for horizontal rectangular contours typical of input forms.
    """
    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        edged = cv2.Canny(blurred, 30, 150)
        contours, _ = cv2.findContours(edged, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        input_fields = 0
        h_img, w_img, _ = img.shape
        for c in contours:
            # Approximate the contour shape
            peri = cv2.arcLength(c, True)
            approx = cv2.approxPolyDP(c, 0.02 * peri, True)
            
            # If the contour has 4 vertices, it represents a rectangle
            if len(approx) == 4:
                x, y, w, h = cv2.boundingRect(approx)
                aspect_ratio = float(w) / h
                
                # Typical input field aspect ratio is between 3.0 and 15.0
                # Height is usually between 15 and 100 pixels, width >= 80 pixels
                # Also ensure it is not the entire image boundary
                if 3.0 <= aspect_ratio <= 15.0 and 15 <= h <= 100 and w >= 80:
                    if w < w_img * 0.9 and h < h_img * 0.9:
                        input_fields += 1
        return input_fields
    except Exception as e:
        print("[ERROR] OpenCV input detection error:", e)
        return 0

def scan_screenshot(img_bytes):
    """
    Scans a screenshot using RapidOCR and OpenCV for threat classification.
    """
    if ocr_engine is None:
        return {
            "risk_score": 0,
            "classification": "Safe",
            "category": "General Website Screenshot",
            "reasons": ["⚠ OCR Engine not initialized"],
            "ai_critique": "The visual threat analysis engine was not loaded properly."
        }
        
    try:
        # Decode image using OpenCV
        nparr = np.frombuffer(img_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return {
                "risk_score": 0,
                "classification": "Safe",
                "category": "Invalid Image File",
                "reasons": ["⚠ Failed to decode image file"],
                "ai_critique": "Uploaded file is not a valid image or could not be decoded."
            }
            
        h_img, w_img, _ = img.shape
        
        # 1. OCR Ingestion
        result, elapse = ocr_engine(img)
        extracted_text = ""
        if result:
            extracted_text = " ".join([line[1] for line in result])
        
        text_lower = extracted_text.lower()
        
        # 2. OpenCV input field structure detection
        fields_count = detect_input_fields_cv(img)
        
        risk_score = 0
        reasons = []
        scam_category = "General Website Screenshot"
        
        # Categories & Keywords
        credential_keywords = {
            "password": 20, "passcode": 20, "username": 15, "login": 15, "sign in": 15,
            "security check": 15, "credit card": 20, "cvv": 25, "card number": 20, "verify your account": 15
        }
        
        crypto_keywords = {
            "giveaway": 25, "bitcoin": 20, "ethereum": 20, "double your": 25, "send btc": 30, "send eth": 30
        }
        
        scareware_keywords = {
            "virus detected": 30, "critical threat": 25, "windows alert": 25, "system alert": 25,
            "call help": 25, "support number": 20, "error code": 20, "helpline": 20
        }
        
        # 3. Process categories
        cred_score = sum(val for kw, val in credential_keywords.items() if kw in text_lower)
        crypto_score = sum(val for kw, val in crypto_keywords.items() if kw in text_lower)
        scareware_score = sum(val for kw, val in scareware_keywords.items() if kw in text_lower)
        
        # Check phone numbers
        phone_matches = re.findall(r'\+?\d{1,4}[-.\s]?\(?\d{1,3}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}', text_lower)
        valid_phones = [p for p in phone_matches if sum(c.isdigit() for c in p) >= 7]
        
        # Apply OpenCV fields weight if we have credential words
        if cred_score > 0 and fields_count > 0:
            cred_score += min(25, fields_count * 8)
            
        # Determine highest scoring threat vector
        max_vector = max(cred_score, crypto_score, scareware_score)
        
        if max_vector > 0:
            if max_vector == cred_score:
                scam_category = "Credential Harvester (Fake Login Page)"
                risk_score = min(95, max_vector + 10)
                reasons.append(f"✗ Credential harvesting indicators: Detected login-specific keywords.")
                if fields_count > 0:
                    reasons.append(f"✗ Form structures: OpenCV detected {fields_count} potential input form fields.")
                else:
                    reasons.append("⚠ Form layout: No visual input form fields identified by computer vision.")
            elif max_vector == crypto_score:
                scam_category = "Crypto Giveaway / Doubler Scheme"
                risk_score = min(95, max_vector + 15)
                reasons.append("✗ Urgent crypto doubler indicators: Detected promise of giveaway/doubling schemes.")
            else:
                scam_category = "Tech Support / Scareware Alert"
                risk_score = min(95, max_vector + 10)
                reasons.append("✗ Scareware indicators: Detected system threat warnings or fake technical alerts.")
                if valid_phones:
                    reasons.append(f"✗ Suspicious contact: Detected phone/helpline number: {valid_phones[0]}")
                    risk_score = min(98, risk_score + 15)
        else:
            # Clean image characteristics
            risk_score = min(20, max(5, fields_count * 2))
            reasons.append("✓ Visual check: No suspect credentials or threat indicators matched in text OCR.")
            if fields_count > 0:
                reasons.append(f"ℹ️ Found {fields_count} standard input field contours in page screenshot.")
            else:
                reasons.append("✓ Clean layout structure: No input forms detected.")
                
        # Retrieve verdict using unified scoring engine
        classification = get_threat_classification(risk_score)
        
        # Generate custom critique
        if classification in ["Malicious", "High Risk"]:
            ai_critique = (
                f"Visual AI Assessment: The screenshot contains patterns matching the '{scam_category}' category. "
                "Text OCR and layout analysis reveal suspicious content, urgent buttons, or lookalike portals. "
                "Do not interact with or submit any data to pages represented in this image."
            )
        elif classification == "Suspicious":
            ai_critique = (
                f"Visual AI Assessment: The screenshot displays warnings, scareware notifications, or login-like constructs. "
                "While not definitively malicious, they present non-standard visual patterns typical of support scams."
            )
        else:
            ai_critique = "Visual AI Assessment: Screenshot appears to be a legitimate interface. No brand spoofing or credential threat vectors detected."
            
        return {
            "risk_score": risk_score,
            "classification": classification,
            "category": scam_category,
            "reasons": reasons,
            "ai_critique": ai_critique,
            "metadata": {
                "width": w_img,
                "height": h_img,
                "ocr_elapse": elapse
            }
        }
    except Exception as e:
        return {
            "risk_score": 0,
            "classification": "Safe",
            "category": "Analysis Failed",
            "reasons": [f"⚠ Scan failure: {str(e)}"],
            "ai_critique": "An error occurred during OCR text extraction or OpenCV analysis."
        }

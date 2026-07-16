def classify_attack(scan_type, features, risk_score, classification, osint_data=None, nlp_analysis=None, screenshot_category=None):
    """
    Deterministically maps scan features to a specific attack type from the knowledge base.
    """
    if scan_type == "URL":
        if classification in ["Safe", "Low Risk"]:
            return "Clean / No Threat Detected"
            
        # Check VT malicious hits
        vt_malicious = 0
        if osint_data and "vt_data" in osint_data:
            vt_malicious = osint_data["vt_data"].get("malicious_hits", 0)
            
        if vt_malicious > 5:
            return "Malware Distribution"
            
        if features.get("is_ip_address"):
            return "Suspicious Newly Registered Domain"
            
        if features.get("high_entropy_sld"):
            return "DGA Generated Domain"
            
        if features.get("has_suspicious_kw"):
            if vt_malicious > 0:
                return "Brand Impersonation"
            if features.get("newly_registered_domain"):
                return "Credential Phishing"
            return "Domain Spoofing"
            
        if features.get("is_url_shortener"):
            return "Social Engineering"
            
        if features.get("newly_registered_domain"):
            return "Suspicious Newly Registered Domain"
            
        if classification in ["Malicious", "High Risk", "Suspicious"]:
            return "Credential Phishing" # default high risk
            
        return "Clean / No Threat Detected"

    elif scan_type == "EMAIL":
        if classification in ["Safe", "Low Risk"]:
            return "Clean / No Threat Detected"
            
        # Check NLP top features for specific themes
        has_financial = False
        has_urgency = False
        
        if nlp_analysis and "top_features" in nlp_analysis:
            financial_words = {"money", "bank", "invoice", "payment", "card", "billing", "wire", "transfer"}
            urgency_words = {"urgent", "verify", "immediate", "suspend", "action", "required", "login"}
            
            for item in nlp_analysis["top_features"]:
                word = item["word"].lower()
                if word in financial_words:
                    has_financial = True
                if word in urgency_words:
                    has_urgency = True
                    
        if has_financial:
            return "Business Email Compromise"
            
        if has_urgency or features.get("suspicious_word_count", 0) > 2:
            return "Credential Phishing"
            
        if features.get("has_url"):
            return "Social Engineering"
            
        return "Social Engineering"

    elif scan_type == "SCREENSHOT":
        if classification in ["Safe", "Low Risk"]:
            return "Clean / No Threat Detected"
            
        if screenshot_category:
            if "Credential Harvester" in screenshot_category:
                return "Fake Login Page"
            if "Crypto Giveaway" in screenshot_category:
                return "Scareware"
            if "Tech Support" in screenshot_category:
                return "Tech Support Scam"
                
        return "Fake Login Page"
        
    return "Unknown"

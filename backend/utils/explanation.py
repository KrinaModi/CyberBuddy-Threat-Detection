def generate_threat_explanation(scan_type, risk_score, features, nlp_analysis=None, osint_data=None):
    """
    Generates a structured list of human-readable reasons explaining the threat analysis score.
    """
    reasons = []
    
    if scan_type == "URL":
        # 1. VirusTotal/Vendor Blacklist hits
        if osint_data and osint_data.get("malicious_hits", 0) > 0:
            reasons.append(
                f"✗ Blacklist match: Flagged by {osint_data['malicious_hits']} security vendors on VirusTotal."
            )
            
        # 2. IP address vs Domain name
        if features.get("is_ip_address"):
            reasons.append("✗ Suspicious structure: Uses raw IP address instead of a domain name.")
            
        # 3. HTTPS connection presence
        if not features.get("has_https"):
            reasons.append("✗ Unsecured protocol: Connection is not secured via HTTPS (HTTP protocol detected).")
        else:
            reasons.append("✓ Secure protocol: HTTPS is active on this connection.")
            
        # 4. Domain Age/Registration issues (if registrar info available)
        if osint_data and osint_data.get("registrar") and osint_data.get("registrar") != "Unknown Registrar":
            registrar = osint_data.get("registrar")
            reasons.append(f"✓ Valid registration info: Registered via {registrar}.")
        elif osint_data and osint_data.get("ip") == "Not resolved":
            reasons.append("✗ Missing registration trace: Registrar RDAP record could not be resolved.")
            
        # 5. IP geolocation
        if osint_data and osint_data.get("ip") and osint_data.get("ip") != "Not resolved":
            country = osint_data.get("country", "Unknown")
            reasons.append(f"ℹ️ Network resolution: Resolves to IP {osint_data['ip']} located in {country}.")
            
        # 6. High-Risk TLD
        if features.get("has_bad_tld"):
            reasons.append("✗ Suspicious top-level domain: Uses a generic TLD commonly associated with spam/phishing campaigns.")
            
        # 7. Brand lookalikes
        if features.get("has_suspicious_kw"):
            reasons.append("✗ Brand imitation indicators: Domain name matches a major online service but lacks legitimate certificate authority.")

        # 8. Excessive subdomains
        if features.get("long_url"):
            reasons.append("✗ High URL length complexity: The indicator string contains excessive parameters or subdomains.")

    elif scan_type == "EMAIL":
        # 1. NLP ML Engine Results
        if nlp_analysis and nlp_analysis.get("top_features"):
            top_words = [item["word"] for item in nlp_analysis["top_features"] if item["contribution"] > 0.05]
            if top_words:
                reasons.append(
                    f"✗ ML Engine Flag: Content contains high-risk terms contributing to threat classification: {', '.join(top_words)}."
                )
        
        # 2. Suspicious word density
        if features.get("suspicious_word_ratio", 0) > 0.1:
            reasons.append(
                f"✗ High suspicious keyword density ({features['suspicious_word_ratio']:.1%} of text contains urgency or financial words)."
            )
            
        # 3. Presence of links / URLs in the text
        if features.get("has_url"):
            reasons.append("✗ URL links detected: Contains hyperlinked text directing users outside the email.")
            
        # 4. Length-based checks (phishing texts are often short/medium)
        if features.get("text_length", 0) > 0 and features.get("text_length") < 150 and risk_score > 50:
            reasons.append("✗ Suspiciously brief content: High-urgency messages are often kept short to prompt quick clicks.")

    # Generic check for very safe files
    if risk_score < 25:
        if not reasons:
            reasons.append("✓ Clean analysis: No significant threat indicators or suspicious patterns detected.")
        else:
            reasons.append("✓ Low risk profile: Features scored below standard SOC alert thresholds.")
            
    return reasons

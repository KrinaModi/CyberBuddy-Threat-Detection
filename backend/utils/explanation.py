import logging

# Set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def generate_threat_explanation(scan_type, risk_score, features, nlp_analysis=None, osint_data=None):
    """
    Generates a structured list of human-readable reasons explaining the threat analysis score.
    
    Parameters:
    - scan_type (str): 'URL' or 'EMAIL'
    - risk_score (int): Score between 0 and 100
    - features (dict): Custom extracted features
    - nlp_analysis (dict, optional): Word weights and NLP results
    - osint_data (dict, optional): VT and RDAP data
    
    Returns:
    - list: Structured list of string descriptions prefixed with '✓', '✗', or 'ℹ️'
    """
    reasons = []
    
    if scan_type == "URL":
        # 1. VirusTotal/Vendor Blacklist hits
        if osint_data:
            malicious_hits = osint_data.get("malicious_hits", 0)
            suspicious_hits = osint_data.get("suspicious_hits", 0)
            if malicious_hits > 0:
                threat_intensity = "verified active threat" if malicious_hits >= 5 else "suspicious reputation match"
                reasons.append(
                    f"✗ Blacklist match: Flagged by {malicious_hits} security vendors on VirusTotal ({threat_intensity})."
                )
            elif suspicious_hits > 0:
                reasons.append(
                    f"✗ Warning: Detected as suspicious by {suspicious_hits} vendors on VirusTotal."
                )
            
        # 2. IP address vs Domain name
        if features.get("is_ip_address"):
            reasons.append("✗ Suspicious structure: Uses raw IP address instead of a domain name (commonly used to bypass signature-based filters).")
            
        # 3. HTTPS connection presence
        if not features.get("has_https"):
            reasons.append("✗ Unsecured protocol: Connection is not secured via HTTPS (HTTP protocol detected), exposing traffic to eavesdropping.")
        else:
            reasons.append("✓ Secure protocol: HTTPS is active, protecting communication channel integrity.")
            
        # 4. Domain Age/Registration issues (if registrar info available)
        if osint_data and osint_data.get("registrar") and osint_data.get("registrar") != "Unknown Registrar":
            registrar = osint_data.get("registrar")
            reasons.append(f"✓ Valid registration info: Registered via an established registrar ({registrar}).")
        elif osint_data and osint_data.get("ip") == "Not resolved":
            reasons.append("✗ Missing registration trace: Registrar RDAP/WHOIS record could not be resolved (typical for orphaned or hostile hosts).")
            
        # 5. IP geolocation & Network resolution
        if osint_data and osint_data.get("ip") and osint_data.get("ip") != "Not resolved":
            ip_addr = osint_data.get("ip")
            country = osint_data.get("country", "Unknown")
            isp = osint_data.get("isp", "Unknown")
            reasons.append(f"ℹ️ Network resolution: Resolves to IP {ip_addr} located in {country} (ISP: {isp}).")
            
        # 6. High-Risk TLD
        if features.get("has_bad_tld"):
            reasons.append("✗ High-risk top-level domain: Uses a generic TLD (e.g. .xyz, .top, .click) frequently selected by threat actors for low registration fees.")
            
        # 7. Brand lookalikes / Imitations
        if features.get("has_suspicious_kw"):
            reasons.append("✗ Brand imitation indicators: Domain name matches a major online service or brand keyword but is not registered to the official parent entity.")

        # 8. Excessive subdomains / URL length
        if features.get("long_url"):
            reasons.append("✗ URL complexity: Length exceeds standard parameters, indicating nested subdomains or obfuscated query parameters.")

        # 9. URL Shortener
        if features.get("is_url_shortener"):
            reasons.append("✗ Link masking detected: Uses a popular URL shortener service to hide the final destination and bypass email security scans.")

        # 10. High entropy
        if features.get("high_entropy_sld"):
            reasons.append("✗ Domain randomness: High Shannon entropy detected in domain name, suggesting an auto-generated hostname typical of Domain Generation Algorithms (DGA).")

        # 11. Newly registered domain
        if features.get("newly_registered_domain"):
            reasons.append("✗ Newly registered domain: Created within the last 30 days (very common for disposable, short-lived phishing sites).")

    elif scan_type == "EMAIL":
        # 1. NLP ML Engine Results
        if risk_score >= 25 and nlp_analysis and nlp_analysis.get("top_features"):
            top_words = [item["word"] for item in nlp_analysis["top_features"] if item.get("contribution", 0) > 0.05]
            if top_words:
                reasons.append(
                    f"✗ ML Engine Flag: Content contains high-risk terms contributing to threat classification: {', '.join(top_words)}."
                )
        
        # 2. Suspicious word density
        if features.get("suspicious_word_ratio", 0) > 0.1:
            reasons.append(
                f"✗ High suspicious keyword density ({features['suspicious_word_ratio']:.1%} of text contains urgency, threat, or financial words)."
            )
            
        # 3. Presence of links / URLs in the text
        if features.get("has_url"):
            reasons.append("✗ URL links detected: Contains hyperlinked text directing users to external web servers.")
            
        # 4. Length-based checks (phishing texts are often short/medium)
        if features.get("text_length", 0) > 0 and features.get("text_length") < 150 and risk_score > 50:
            reasons.append("✗ Suspiciously brief content: High-urgency message is kept short to prompt quick actions before verification.")

    # Generic check for very safe inputs
    if risk_score < 25:
        if not reasons:
            reasons.append("✓ Clean analysis: No significant threat indicators or suspicious patterns detected.")
        else:
            reasons.append("✓ Low risk profile: Features scored below standard security operations center (SOC) alert thresholds.")
            
    return reasons

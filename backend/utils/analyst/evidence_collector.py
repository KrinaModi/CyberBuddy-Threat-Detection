def collect_evidence(scan_type, features, risk_score, classification, osint_data=None, nlp_analysis=None, screenshot_explanations=None):
    """
    Formats raw scan data into structured evidence tagged with source origins.
    Never hallucinates data. Only reports what is passed in.
    """
    evidence = []
    
    if scan_type == "URL":
        # VT Evidence
        if osint_data and "vt_data" in osint_data:
            vt_malicious = osint_data["vt_data"].get("malicious_hits", 0)
            if vt_malicious > 0:
                evidence.append(f"[VT] Flagged by {vt_malicious} security vendors on VirusTotal")
                
        # DNS Evidence
        if osint_data and "ip" in osint_data and osint_data["ip"] != "Not resolved":
            evidence.append(f"[DNS] Resolves to IP address: {osint_data['ip']}")
        else:
            evidence.append("[DNS] Fails to resolve to a valid IP address")
            
        if features.get("is_ip_address"):
            evidence.append("[STRUCT] Input is a raw IP address, bypassing domain name resolution")
            
        if not features.get("has_https"):
            evidence.append("[PROTOCOL] Connection does not use HTTPS (unencrypted HTTP)")
            
        # RDAP Evidence
        if osint_data and "registrar" in osint_data and osint_data["registrar"] != "Unknown Registrar":
            evidence.append(f"[RDAP] Domain registered via {osint_data['registrar']}")
            
        if features.get("newly_registered_domain"):
            evidence.append("[RDAP] Domain was registered very recently (under 30 days)")
            
        # GEOIP Evidence
        if osint_data and "country" in osint_data and osint_data["country"] != "Unknown":
            evidence.append(f"[GEOIP] IP hosted in: {osint_data['country']} (ISP: {osint_data.get('isp', 'Unknown')})")
            
        # Entropy & Struct Evidence
        if features.get("high_entropy_sld"):
            evidence.append("[ENTROPY] High character randomness detected in the second-level domain")
            
        if features.get("has_bad_tld"):
            evidence.append("[STRUCT] Uses a generic top-level domain often abused by spam/phishing")
            
        if features.get("has_suspicious_kw"):
            evidence.append("[STRUCT] Domain contains keywords typical of brand impersonation (e.g. login, verify, secure)")
            
        if features.get("is_url_shortener"):
            evidence.append("[STRUCT] Link is masked using a URL shortening service")

    elif scan_type == "EMAIL":
        if nlp_analysis and "top_features" in nlp_analysis and len(nlp_analysis["top_features"]) > 0:
            top_words = [item["word"] for item in nlp_analysis["top_features"] if item["contribution"] > 0.05]
            if top_words:
                evidence.append(f"[NLP] High-risk terms identified: {', '.join(top_words)}")
                
        if features.get("suspicious_word_ratio", 0) > 0.1:
            evidence.append(f"[NLP] High suspicious keyword density ({features['suspicious_word_ratio']:.1%} of text)")
            
        if features.get("has_url"):
            evidence.append("[STRUCT] Message contains external URL links")
            
        if features.get("text_length", 0) > 0 and features.get("text_length") < 150 and risk_score > 50:
            evidence.append("[STRUCT] Unusually brief message length for legitimate communications")
            
    elif scan_type == "SCREENSHOT":
        if screenshot_explanations:
            for exp in screenshot_explanations:
                # Clean up existing markers
                cleaned = exp.replace('✓', '').replace('✗', '').replace('ℹ️', '').strip()
                evidence.append(f"[OCR/CV] {cleaned}")
                
    if not evidence:
        if classification in ["Safe", "Low Risk"]:
            evidence.append("[SYSTEM] No significant threat indicators detected during analysis")
        else:
            evidence.append("[SYSTEM] Threat indicators triggered based on overall risk scoring model")
            
    return evidence

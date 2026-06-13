def generate_ai_analysis(scan_type, target, risk_score, classification, reasons):
    """
    Simulates a natural language AI Cybersecurity Assistant providing expert commentary 
    on the threat classification, targeted brand, and recommendations.
    """
    target = target.strip()
    
    if scan_type == "URL":
        target_lower = target.lower()
        
        # Identify targeted brands
        brands = {
            "paypal": "PayPal payment services",
            "bank": "banking portals",
            "secure": "secure sign-in portals",
            "login": "login authentication pages",
            "verify": "account verification utilities",
            "microsoft": "Microsoft 365 cloud credentials",
            "netflix": "Netflix subscription billing",
            "apple": "Apple ID credentials",
            "google": "Google account authentication",
            "amazon": "Amazon retail accounts"
        }
        
        detected_brand = None
        for key, name in brands.items():
            if key in target_lower:
                detected_brand = name
                break
                
        if classification == "Malicious":
            brand_phrase = f" imitating {detected_brand}" if detected_brand else ""
            commentary = (
                f"CyberBuddy Threat Assessment: This URL exhibits classic indicators of a phishing landing page{brand_phrase}. "
                f"The network registrar analysis indicates high-density structural signs, such as lookalike keywords, an unsecured link protocol, "
                f"or a high-risk TLD. Security vendor reports confirm malicious behavior, signifying an active credential-harvesting vector. "
                f"Action Required: Immediately block access to this indicator at your network gateway and flag the host in DNS records."
            )
        elif classification == "Suspicious":
            brand_phrase = f" related to {detected_brand}" if detected_brand else ""
            commentary = (
                f"CyberBuddy Threat Assessment: This URL is flagged as Suspicious. While it may not be on active security blacklists yet, "
                f"structural analysis identifies potential brand imitation{brand_phrase}, a generic top-level domain, or a newly registered domain. "
                f"Phishing campaigns often register domains and wait before executing spam cycles. "
                f"Recommendation: Analysts should monitor network egress to this domain and avoid inputting sensitive credentials."
            )
        else:
            commentary = (
                f"CyberBuddy Threat Assessment: The URL resolving details indicate a standard clean reputation. "
                f"It operates on a secure protocol and standard TLD, matching expected structures of safe corporate environments. "
                f"No immediate security posture changes are necessary."
            )
            
    else:  # EMAIL
        target_lower = target.lower()
        has_urgency = any(w in target_lower for w in ["urgent", "verify", "immediate", "suspend", "action required"])
        has_financial = any(w in target_lower for w in ["money", "bank", "invoice", "payment", "card", "billing"])
        
        if classification == "Malicious":
            urgency_phrase = " urgent action commands" if has_urgency else " suspicious links"
            financial_phrase = " financial spoofing language" if has_financial else " anomalous keywords"
            commentary = (
                f"CyberBuddy Threat Assessment: The email content contains severe indicators of credentials harvesting or social engineering. "
                f"Natural Language Processing highlights high-weight tokens matching{urgency_phrase} and{financial_phrase}. "
                f"The structural syntax patterns strongly suggest a spoofing campaign designed to compromise endpoint security or steal user passwords. "
                f"Action Required: Alert user targets, isolate the threat within mail transfer agents (MTAs), and purge it from mailboxes."
            )
        elif classification == "Suspicious":
            commentary = (
                f"CyberBuddy Threat Assessment: The email demonstrates anomalous syntax features. "
                f"The frequency of high-urgency keywords or unsolicited transaction references warrants caution. "
                f"Although it does not trigger standard malicious classifications, it possesses indicators common to promotional spam or secondary phishing waves. "
                f"Recommendation: Mark as junk and instruct users to verify sender headers manually before opening attachments."
            )
        else:
            commentary = (
                f"CyberBuddy Threat Assessment: Email body checks clean. The language is conversational, free of urgent pressure prompts, "
                f"and does not contain malicious URL links. No action is required."
            )
            
    return commentary

import socket
import requests
import math
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse
from utils.scoring import get_threat_classification

import os
# Read VT API key from environment, default to None if not present
API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

def extract_domain(url):
    """
    Safely extract domain name from a URL or raw string.
    """
    if not url.lower().startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain
    except Exception:
        return ""

def get_dns_records(domain):
    """
    Resolve IP address of the domain.
    """
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return None

def get_ip_geolocation(ip):
    """
    Get geolocation details of the IP address.
    """
    if not ip or ip.startswith(('127.', '192.168.', '10.')):
        return {"country": "Localhost / Private Network", "isp": "Internal"}
        
    try:
        # Use free ip-api.com service
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "city": data.get("city", "Unknown")
                }
    except Exception:
        pass
    
    return {"country": "Unknown", "isp": "Unknown"}

def calculate_entropy(text):
    """
    Calculates the Shannon entropy of a string to detect randomized strings (DGA).
    """
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return entropy

def is_url_shortener(domain):
    """
    Checks if a domain is a known URL shortener service.
    """
    shortener_domains = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", 
        "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "rebrand.ly", 
        "tiny.cc", "shorturl.at", "shorte.st", "cutt.ly", "rb.gy"
    }
    return domain in shortener_domains

def get_registrar_and_registration_rdap(domain):
    """
    Queries public RDAP to find registrar and registration details.
    """
    registrar = "Unknown Registrar"
    created_date = None
    try:
        res = requests.get(f"https://rdap.org/domain/{domain}", timeout=3)
        if res.status_code == 200:
            data = res.json()
            # Find registrar name
            for entity in data.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    for vcard in entity.get("vcardArray", [None, []])[1]:
                        if vcard[0] == "fn":
                            registrar = vcard[3]
                            break
            # Find registration date
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    created_date = event.get("eventDate")
                    break
    except Exception:
        pass
    return registrar, created_date

def calculate_domain_age_days(created_date_str):
    """
    Parses creation date string and calculates domain age in days.
    """
    if not created_date_str:
        return None
    try:
        from datetime import timezone
        # standard ISO format date extraction (e.g. 2023-01-24T18:20:00Z)
        # extract the first 10 characters (YYYY-MM-DD)
        date_part = created_date_str[:10]
        created_dt = datetime.strptime(date_part, "%Y-%m-%d")
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        age_days = (now - created_dt).days
        return age_days
    except Exception:
        return None

def extract_sld(domain):
    """
    Extracts the second-level domain (SLD) from a domain name.
    """
    parts = domain.split('.')
    if len(parts) >= 2:
        if parts[-2] in ('co', 'com', 'org', 'net', 'gov', 'edu', 'mil') and len(parts) >= 3:
            return parts[-3]
        return parts[-2]
    return domain

def get_registrar_rdap(domain):
    # Retain for backward compatibility just in case, calling the new combined helper
    registrar, _ = get_registrar_and_registration_rdap(domain)
    return registrar

def query_virustotal(url):
    """
    Queries VirusTotal API for URL reputation.
    """
    if not API_KEY:
        return {
            "malicious_hits": 0,
            "suspicious_hits": 0,
            "harmless_hits": 0
        }

    headers = {"x-apikey": API_KEY}
    try:
        # Step 1: Submit URL/Get report
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=5
        )
        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            # Query the analysis (sometimes we need to poll, let's wait 1.5s or just try to retrieve)
            import time
            time.sleep(1.5)
            report = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=5
            )
            if report.status_code == 200:
                stats = report.json()["data"]["attributes"]["stats"]
                return {
                    "malicious_hits": stats.get("malicious", 0),
                    "suspicious_hits": stats.get("suspicious", 0),
                    "harmless_hits": stats.get("harmless", 0)
                }
    except Exception as e:
        print("VirusTotal query error:", e)
    
    # Return empty hits if request fails
    return {
        "malicious_hits": 0,
        "suspicious_hits": 0,
        "harmless_hits": 0
    }

def scan_url_osint(url):
    """
    Runs full OSINT scan on URL, resolving IP, geolocation, registrar, and reputation.
    """
    domain = extract_domain(url).lower()
    ip = get_dns_records(domain)
    geo = get_ip_geolocation(ip)
    registrar, created_date = get_registrar_and_registration_rdap(domain)
    vt_result = query_virustotal(url)
    
    # Granular Multi-Factored URL Risk Scoring Engine
    base_risk = 0
    
    # 1. SSL/HTTPS check
    has_https = url.lower().startswith("https")
    if not has_https:
        base_risk += 10
        
    # 2. DNS Resolution check
    if not ip:
        base_risk += 10
        
    # 3. High-Risk TLD check
    high_risk_tlds = [".xyz", ".club", ".top", ".tk", ".loan", ".work", ".click", ".gq", ".cf", ".ml", ".ga", ".buzz", ".fit", ".date", ".info"]
    has_bad_tld = any(domain.endswith(tld) for tld in high_risk_tlds)
    if has_bad_tld:
        base_risk += 15
        
    # 4. Domain length and structure
    if len(url) > 50:
        base_risk += 5
    
    # Phishing domains often stack subdomains (dots)
    dot_count = domain.count('.')
    if dot_count >= 3:
        base_risk += 10
        
    # Phishing domains often use hyphens (e.g. paypal-login)
    if '-' in domain:
        base_risk += 5
        
    # 5. Suspicious Brand Keywords (lookalikes)
    suspicious_keywords = ["paypal", "bank", "login", "verify", "secure", "free", "win", "update", "signin", "netflix", "microsoft", "apple", "support", "credential"]
    # Check if keyword is in domain but it is NOT the official domain
    has_suspicious_kw = False
    for kw in suspicious_keywords:
        if kw in domain:
            # exclude benign official domains
            benign_exceptions = ["paypal.com", "microsoft.com", "apple.com", "netflix.com"]
            if not any(benign in domain for benign in benign_exceptions):
                has_suspicious_kw = True
                break
    if has_suspicious_kw:
        base_risk += 20
        
    # 6. Advanced Indicators: Direct IP Address
    is_ip = False
    try:
        socket.inet_aton(domain)
        is_ip = True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, domain)
            is_ip = True
        except Exception:
            pass
            
    if is_ip:
        base_risk += 20

    # 7. Advanced Indicators: Shannon Entropy
    sld = extract_sld(domain)
    sld_entropy = calculate_entropy(sld)
    has_high_entropy = False
    if len(sld) >= 8 and sld_entropy > 4.2:
        base_risk += 10
        has_high_entropy = True

    # 8. Advanced Indicators: URL Shortener Check
    is_shortener = is_url_shortener(domain)
    if is_shortener:
        base_risk += 15

    # 9. Advanced Indicators: Domain Registration Age Check
    age_days = calculate_domain_age_days(created_date)
    is_new_domain = False
    if age_days is not None:
        if age_days < 30:
            base_risk += 20
            is_new_domain = True
        elif age_days < 180:
            base_risk += 10

    # 10. Reputation / VirusTotal Hits
    vt_malicious = vt_result.get("malicious_hits", 0)
    vt_suspicious = vt_result.get("suspicious_hits", 0)
    
    reputation_score = vt_malicious * 20 + vt_suspicious * 5
    
    # Combine base structural risk and reputation
    total_score = base_risk + reputation_score
    risk_score = min(100, max(0, total_score))
    
    # Use standardized scoring classification
    classification = get_threat_classification(risk_score)
    if vt_malicious >= 3 and risk_score < 90:
        # Override to Malicious if VirusTotal is certain
        classification = "Malicious"
        risk_score = max(90, risk_score)
        
    features = {
        "is_ip_address": 1 if is_ip else 0,
        "has_https": 1 if has_https else 0,
        "has_dns_resolution": 1 if ip else 0,
        "has_bad_tld": 1 if has_bad_tld else 0,
        "has_suspicious_kw": 1 if has_suspicious_kw else 0,
        "long_url": 1 if len(url) > 50 else 0,
        "is_url_shortener": 1 if is_shortener else 0,
        "high_entropy_sld": 1 if has_high_entropy else 0,
        "newly_registered_domain": 1 if is_new_domain else 0
    }
    
    domain_info = {
        "ip": ip or "Not resolved",
        "registrar": registrar,
        "country": geo.get("country", "Unknown"),
        "isp": geo.get("isp", "Unknown")
    }
    
    return {
        "risk_score": risk_score,
        "classification": classification,
        "features": features,
        "domain_info": domain_info,
        "vt_data": vt_result
    }


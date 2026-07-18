"""
CyberBuddy Threat Detection - APIs Package
==========================================

This package contains thin, reusable wrapper modules for every external
threat-intelligence API integrated into CyberBuddy.  Each sub-module is
responsible for exactly one external service and exposes a consistent
function interface that higher-level code can rely on.

Available wrapper modules
--------------------------
- virustotal  : VirusTotal URL / IP / file hash reputation
- otx         : AlienVault OTX Indicators of Compromise
- abuseipdb   : AbuseIPDB IP address reputation
- ipinfo      : IPInfo.io geolocation and ASN enrichment
- urlhaus     : URLhaus malicious URL feed lookup

Shared configuration
---------------------
All wrappers import from `utils.apis.config`, which holds:
  - API_KEYS   – environment-variable-backed dictionary of API keys
  - BASE_URLS  – canonical endpoint base URLs per service
  - DEFAULT_TIMEOUT / DEFAULT_HEADERS – safe HTTP request defaults

Usage example (once wrappers are implemented)
---------------------------------------------
    from utils.apis.virustotal import check_url_reputation
    from utils.apis.abuseipdb   import check_ip_reputation
    from utils.apis.ipinfo      import get_ip_info

    vt_result     = check_url_reputation("https://example.com")
    abuse_result  = check_ip_reputation("1.2.3.4")
    geo_result    = get_ip_info("1.2.3.4")

Author: CyberBuddy Team
"""

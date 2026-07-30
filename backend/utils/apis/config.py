"""
CyberBuddy Threat Detection - Shared API Configuration Module
==============================================================

This module serves as the single source of truth for all external API
configuration. It is imported by every API wrapper inside utils/apis/ to
avoid duplication and to ensure that environment variables are read only once
at import time (after load_dotenv() has already been called in app.py).

Usage (in any api wrapper module):
    from utils.apis.config import API_KEYS, DEFAULT_TIMEOUT, DEFAULT_HEADERS

Design Notes:
    - load_dotenv() is intentionally NOT called here. The application entry
      point (app.py) already calls load_dotenv() before any imports that reach
      this module, so the environment is guaranteed to be populated.
    - All API keys are read with os.getenv() and will be None if the
      corresponding variable is missing from the .env file.
    - DEFAULT_TIMEOUT and DEFAULT_HEADERS provide safe, consistent defaults
      for every outbound HTTP request made by the API wrappers.

Author: CyberBuddy Team
"""

import os

# ---------------------------------------------------------------------------
# API Key Registry
# ---------------------------------------------------------------------------
# All keys are read from environment variables.
# The keys below correspond exactly to the variable names that must be present
# in the project's .env file.  None means the key has not been configured yet.

API_KEYS: dict[str, str | None] = {
    "VIRUSTOTAL":  os.getenv("VIRUSTOTAL_API_KEY"),
    "OTX":         os.getenv("OTX_API_KEY"),
    "ABUSEIPDB":   os.getenv("ABUSEIPDB_API_KEY"),
    "IPINFO":      os.getenv("IPINFO_API_KEY"),
    "URLHAUS":     os.getenv("URLHAUS_API_KEY"),   # URLhaus currently free/no-auth but kept for future
}

# ---------------------------------------------------------------------------
# Shared HTTP Request Defaults
# ---------------------------------------------------------------------------

# Seconds to wait for a response before raising requests.Timeout.
# Individual wrappers may override this value for their own calls.
DEFAULT_TIMEOUT: int = 10

# Base User-Agent string sent with every outbound request so that external
# services can identify traffic originating from CyberBuddy.
DEFAULT_USER_AGENT: str = "CyberBuddy-ThreatDetection/1.0 (contact: security@cyberbuddy.local)"

# Generic headers applied to all requests unless a wrapper provides its own.
DEFAULT_HEADERS: dict[str, str] = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "application/json",
}

# ---------------------------------------------------------------------------
# Base URLs (centralised so they are easy to update when APIs version-bump)
# ---------------------------------------------------------------------------

BASE_URLS: dict[str, str] = {
    "VIRUSTOTAL": "https://www.virustotal.com/api/v3",
    "OTX":        "https://otx.alienvault.com/api/v1",
    "ABUSEIPDB":  "https://api.abuseipdb.com/api/v2",
    "IPINFO":     "https://ipinfo.io",
    "URLHAUS":    "https://urlhaus-api.abuse.ch/v1",
}

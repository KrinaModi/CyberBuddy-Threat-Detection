"""
CyberBuddy Threat Detection - AbuseIPDB API Wrapper
=====================================================

Service : AbuseIPDB (https://www.abuseipdb.com)
API Docs: https://docs.abuseipdb.com/
Auth     : API key sent via 'Key' request header
Tier     : Free (1,000 checks/day) / Premium (varies)

AbuseIPDB is a project dedicated to helping combat the spread of hackers,
spammers and abusive activity on the internet. It maintains a crowd-sourced
database of reported malicious IP addresses.

This module will provide functions for querying the AbuseIPDB v2 REST API.
Supported lookups (planned):
  - IP address abuse confidence score and report count
  - IP block / CIDR range check
  - Report submission (for honeypot/IDS integration)
  - Blacklist retrieval

Note: No API calls are made in this module yet.
      All functions below contain TODO stubs only.

Author: CyberBuddy Team
"""

import requests

from utils.apis.config import API_KEYS, BASE_URLS, DEFAULT_TIMEOUT

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# API key loaded from shared config (sourced from .env via os.getenv)
_API_KEY: str | None = API_KEYS["ABUSEIPDB"]

# AbuseIPDB v2 base URL
_BASE_URL: str = BASE_URLS["ABUSEIPDB"]

# AbuseIPDB uses 'Key' as the header name (not 'Authorization: Bearer')
_HEADERS: dict[str, str] = {
    "Key": _API_KEY or "",
    "Accept": "application/json",
}

# Number of days to look back when counting abuse reports (API max = 365)
DEFAULT_MAX_AGE_DAYS: int = 90


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _is_configured() -> bool:
    """Return True if the AbuseIPDB API key is present and non-empty."""
    return bool(_API_KEY)


# ---------------------------------------------------------------------------
# Public API functions (stubs – no HTTP calls yet)
# ---------------------------------------------------------------------------

def check_ip_reputation(ip: str, max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> dict:
    """
    Check the abuse confidence score and report count for an IP address.

    Args:
        ip           (str): IPv4 or IPv6 address to evaluate.
        max_age_days (int): How many days back to look for reports (1-365).
                            Defaults to DEFAULT_MAX_AGE_DAYS (90 days).

    Returns:
        dict: Normalised result containing:
              - abuse_confidence_score  (int  0-100)
              - total_reports           (int)
              - country_code            (str)
              - isp                     (str)
              - usage_type              (str)
              - is_whitelisted          (bool)
              - source                  (str) – always "abuseipdb"

    TODO: Implement via GET /check with params ip, maxAgeInDays, verbose.
    TODO: Map usage_type to human-readable labels (e.g. 'DCH' → 'Data Center').
    TODO: Return safe defaults (score=0, reports=0) when key is missing.
    """
    # TODO: implement
    raise NotImplementedError("check_ip_reputation is not yet implemented.")


def check_cidr_block(cidr: str, max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> dict:
    """
    Check a CIDR block for reported abusive addresses.

    Args:
        cidr         (str): CIDR notation (e.g. '192.168.0.0/24').
        max_age_days (int): Look-back window in days.

    Returns:
        dict: Summary of abusive IPs found within the block.

    TODO: Implement via GET /check-block with params network, maxAgeInDays.
    TODO: Validate CIDR format with Python's ipaddress module before request.
    """
    # TODO: implement
    raise NotImplementedError("check_cidr_block is not yet implemented.")


def report_ip(ip: str, categories: list[int], comment: str = "") -> dict:
    """
    Submit a report for an IP address that has been observed behaving abusively.

    Args:
        ip         (str):       IPv4 or IPv6 address to report.
        categories (list[int]): AbuseIPDB category IDs (see API docs for full list).
                                Common values: 14=Port Scan, 15=Hacking, 21=Web App Attack.
        comment    (str):       Optional free-text description of the abuse.

    Returns:
        dict: Confirmation of the submission including the new confidence score.

    TODO: Implement via POST /report with params ip, categories (CSV), comment.
    TODO: Validate that categories contains at least one valid integer.
    TODO: Require GDPR-safe comment guidelines (do not include personal data).
    """
    # TODO: implement
    raise NotImplementedError("report_ip is not yet implemented.")


def get_blacklist(confidence_minimum: int = 90, limit: int = 10000) -> list[dict]:
    """
    Retrieve a list of IP addresses that have been reported with high confidence.

    Args:
        confidence_minimum (int): Minimum abuse confidence score to include (25-100).
        limit              (int): Maximum number of IPs to return (max 10,000).

    Returns:
        list[dict]: Each entry contains the IP address and its confidence score.

    TODO: Implement via GET /blacklist with params confidenceMinimum, limit.
    TODO: Cache the response for a configurable TTL to avoid hammering the API.
    """
    # TODO: implement
    raise NotImplementedError("get_blacklist is not yet implemented.")

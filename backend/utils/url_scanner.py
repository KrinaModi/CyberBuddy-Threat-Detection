import requests
import time
import os

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

def scan_url(url):
    if not API_KEY:
        return "Safe"
        
    headers = {
        "x-apikey": API_KEY
    }

    # Step 1: Submit URL
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if response.status_code != 200:
        return "ERROR"

    analysis_id = response.json()["data"]["id"]

    # Step 2: Wait for analysis
    time.sleep(3)

    # Step 3: Get results
    report = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )

    stats = report.json()["data"]["attributes"]["stats"]

    malicious = stats["malicious"]
    suspicious = stats["suspicious"]

    if malicious > 0:
        return "Malicious"
    elif suspicious > 0:
        return "Suspicious"
    else:
        return "Safe"
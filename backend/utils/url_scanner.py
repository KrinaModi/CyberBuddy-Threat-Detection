import requests
import time

API_KEY = "8f600656464cc1b095265dc2f56de64805f013e40a2c254e7f99ee02d56ec1af"

def scan_url(url):
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
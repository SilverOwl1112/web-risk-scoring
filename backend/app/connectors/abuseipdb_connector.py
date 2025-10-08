# connectors/abuseipdb_connector.py
import os, requests

ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip_reputation(ip):
    data = {"abuse_confidence_score": 0}
    if not ABUSE_API_KEY:
        return data
    try:
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        r = requests.get(ABUSE_URL, headers=headers, params=params)
        if r.status_code == 200:
            j = r.json()
            data["abuse_confidence_score"] = j["data"]["abuseConfidenceScore"]
    except Exception:
        pass
    return data

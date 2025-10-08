# connectors/vt_connector.py
import os, requests

VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_URL = "https://www.virustotal.com/api/v3/domains/"

def vt_domain_report(domain):
    data = {"vt_malicious_score": 0}
    if not VT_API_KEY:
        return data
    try:
        r = requests.get(f"{VT_URL}{domain}", headers={"x-apikey": VT_API_KEY})
        if r.status_code == 200:
            j = r.json()
            malicious = j["data"]["attributes"]["last_analysis_stats"]["malicious"]
            suspicious = j["data"]["attributes"]["last_analysis_stats"]["suspicious"]
            total = malicious + suspicious
            data["vt_malicious_score"] = total
    except Exception:
        pass
    return data

# backend/app/connectors/vt_connector.py
import os, requests
VT_API = os.getenv("VT_API_KEY", "")

def query_domain(domain):
    if not VT_API:
        return {"note": "VT key not set"}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API}
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code == 200:
        return r.json()
    return {"error": f"status_code_{r.status_code}"}

# backend/app/connectors/shodan_connector.py
import os, requests
SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")

def query_host(host):
    if not SHODAN_KEY:
        return {"note": "shodan key not set"}
    url = f"https://api.shodan.io/shodan/host/{host}?key={SHODAN_KEY}"
    r = requests.get(url, timeout=15)
    if r.status_code == 200:
        return r.json()
    return {"error": f"status_code_{r.status_code}"}

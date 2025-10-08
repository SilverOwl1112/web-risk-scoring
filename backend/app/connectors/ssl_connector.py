# connectors/ssl_connector.py
import requests, time

SSL_LABS_API = "https://api.ssllabs.com/api/v3/analyze"

def check_ssl_grade(domain):
    data = {"ssl_grade": "N/A", "ssl_issues": 0}
    try:
        params = {"host": domain, "publish": "off", "startNew": "on", "all": "done"}
        r = requests.get(SSL_LABS_API, params=params)
        j = r.json()
        if "endpoints" in j and len(j["endpoints"]) > 0:
            grade = j["endpoints"][0].get("grade", "N/A")
            data["ssl_grade"] = grade
            if grade not in ["A", "A+", "B"]:
                data["ssl_issues"] = 1
    except Exception:
        pass
    return data

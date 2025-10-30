# app/connectors/nvd_connector.py
import os
import requests
import datetime
from typing import Dict

"""
Fetch vulnerability counts from NVD API based on domain, IP, or vendor/product hints.
We’ll use NVD’s REST API v2 (no API key required for small requests).
If you have an NVD API key, set it in your .env as NVD_API_KEY to lift rate limits.
"""

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_vuln_count(query: str) -> Dict:
    """
    Given a domain or product keyword, returns a vulnerability count.
    The query term can be a software, vendor, or known string (e.g., 'wordpress', 'apache', 'nginx').
    """
    try:
        params = {
            "keywordSearch": query,
            "resultsPerPage": 1,  # we only need totalResults count
        }
        api_key = os.getenv("NVD_API_KEY")
        if api_key:
            params["apiKey"] = api_key

        resp = requests.get(NVD_API, params=params, timeout=10)
        if resp.status_code != 200:
            print(f"[nvd_connector] HTTP {resp.status_code} for query={query}")
            return {"nvd_vuln_count": 0}

        data = resp.json()
        total = data.get("totalResults", 0)
        return {"nvd_vuln_count": int(total)}

    except Exception as e:
        print(f"[nvd_connector] error: {e}")
        return {"nvd_vuln_count": 0}

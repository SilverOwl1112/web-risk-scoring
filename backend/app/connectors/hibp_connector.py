# backend/app/connectors/hibp_connector.py
import os
import requests
import csv
from dotenv import load_dotenv
load_dotenv()

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()
LOCAL_CSV = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                         "ml", "datasets", "cyber_risk_dataset.csv")

def _read_local_pwned_count(target):
    try:
        if not os.path.exists(LOCAL_CSV):
            return None
        with open(LOCAL_CSV, "r", encoding="utf-8", errors="ignore") as fh:
            reader = csv.DictReader(fh)
            target_l = target.lower()
            for row in reader:
                if 'email' in row and row['email'] and row['email'].lower() == target_l:
                    return int(row.get('pwned_count', 0) or 0)
                if 'domain' in row and row['domain'] and row['domain'].lower() == target_l:
                    return int(row.get('pwned_count', 0) or 0)
                if 'email' in row and row['email'] and ('@' in target_l is False):
                    try:
                        domain_part = row['email'].split('@')[-1].lower()
                        if domain_part == target_l:
                            return int(row.get('pwned_count', 0) or 0)
                    except Exception:
                        pass
    except Exception:
        return None
    return None

def check_pwned(target):
    """
    Returns dict: {"pwned_count": int}
    Uses HIBP if API key present; otherwise falls back to local CSV.
    """
    data = {"pwned_count": 0}

    # If API key is provided, try the HIBP endpoints (breachedaccount for emails,
    # unifiedsearch for domains)
    if HIBP_API_KEY:
        try:
            headers = {
                "hibp-api-key": HIBP_API_KEY,
                "user-agent": "CyberRiskScanner/1.0"
            }
            # If looks like an email -> breachedaccount endpoint
            if "@" in target:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}"
                params = {"truncateResponse": "false"}
                r = requests.get(url, headers=headers, params=params, timeout=20)
                if r.status_code == 200:
                    breaches = r.json()
                    data["pwned_count"] = len(breaches)
                elif r.status_code == 404:
                    data["pwned_count"] = 0
                else:
                    # non-200 -> fallback later
                    pass
            else:
                # Domain / organization -> use unifiedsearch
                url = f"https://haveibeenpwned.com/api/v3/unifiedsearch/{target}"
                r = requests.get(url, headers=headers, timeout=20)
                if r.status_code == 200:
                    j = r.json()
                    # unifiedsearch may contain 'breaches'
                    if isinstance(j, dict) and "breaches" in j:
                        data["pwned_count"] = len(j.get("breaches") or [])
                    else:
                        # sometimes unifiedsearch returns list-like
                        try:
                            data["pwned_count"] = len(j)
                        except Exception:
                            data["pwned_count"] = 0
                elif r.status_code == 404:
                    data["pwned_count"] = 0
                else:
                    pass
        except requests.exceptions.HTTPError:
            pass
        except Exception:
            pass

    # If HIBP not available or returned nothing, try local CSV fallback
    if data["pwned_count"] == 0:
        try:
            local = _read_local_pwned_count(target)
            if local is not None:
                data["pwned_count"] = int(local)
        except Exception:
            pass

    return data

# backend/app/connectors/hibp_connector.py
import os
import requests
import csv

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()
# path to local dataset fallback (adjust if your repo layout differs)
LOCAL_CSV = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                         "ml", "datasets", "cyber_risk_dataset.csv")

def _read_local_pwned_count(target):
    """
    Look for a row in local CSV where an email/domain matches 'target'.
    CSV must contain a column like 'email' or 'domain' and 'pwned_count'.
    This is a simple best-effort local lookup for demo mode.
    """
    try:
        if not os.path.exists(LOCAL_CSV):
            return None
        with open(LOCAL_CSV, "r", encoding="utf-8", errors="ignore") as fh:
            reader = csv.DictReader(fh)
            target_l = target.lower()
            for row in reader:
                # try a few heuristics: exact email match, exact domain match,
                # or domain contained in some column like 'email' or 'domain'
                # adjust column names if your CSV differs
                if 'email' in row and row['email'] and row['email'].lower() == target_l:
                    return int(row.get('pwned_count', 0) or 0)
                if 'domain' in row and row['domain'] and row['domain'].lower() == target_l:
                    return int(row.get('pwned_count', 0) or 0)
                # fallback: if email column contains the domain
                if 'email' in row and row['email'] and ('@' in target_l is False):
                    try:
                        domain_part = row['email'].split('@')[-1].lower()
                        if domain_part == target_l:
                            return int(row.get('pwned_count', 0) or 0)
                    except Exception:
                        pass
    except Exception:
        # silently fail local lookup
        return None
    return None

def check_pwned(target):
    """
    Returns dict: {"pwned_count": int}
    Behavior:
      - if HIBP_API_KEY present -> call real HIBP API (breachedaccount)
      - else -> attempt local CSV lookup
      - else -> return 0
    Notes:
      - HIBP API requires an API key for breachedaccount endpoint.
      - This function never raises; it returns best-effort results.
    """
    data = {"pwned_count": 0}

    # If API key is provided, use HIBP API (breachedaccount endpoint).
    if HIBP_API_KEY:
        try:
            headers = {
                "hibp-api-key": HIBP_API_KEY,
                "user-agent": "CyberRiskScanner/1.0"
            }
            # HIBP expects an account (email); for a domain you can still try unified search,
            # but many endpoints require email. We'll try the breachedaccount endpoint if target looks like an email.
            if "@" in target:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}?truncateResponse=false"
                r = requests.get(url, headers=headers, timeout=20)
                if r.status_code == 200:
                    breaches = r.json()
                    data["pwned_count"] = len(breaches)
                else:
                    # If 404 -> not found (0)
                    data["pwned_count"] = 0
            else:
                # target looks like a domain; attempt unified search endpoint (best-effort)
                url = f"https://haveibeenpwned.com/api/v3/unifiedsearch/{target}"
                r = requests.get(url, headers=headers, timeout=20)
                if r.status_code == 200:
                    j = r.json()
                    # unifiedsearch may return 'breaches' or 'accounts' info - count breaches if present
                    if isinstance(j, dict) and "breaches" in j:
                        data["pwned_count"] = len(j.get("breaches") or [])
                    else:
                        data["pwned_count"] = 0
                else:
                    data["pwned_count"] = 0
        except Exception:
            # on any failure, fall back to local
            pass

    # If no key or API failed, try local CSV lookup for demo/fallback
    if data["pwned_count"] == 0:
        try:
            local = _read_local_pwned_count(target)
            if local is not None:
                data["pwned_count"] = int(local)
        except Exception:
            pass

    # final fallback: keep zero
    return data

# connectors/vt_connector.py
import os
import time
from typing import Dict

try:
    from virustotal_python import Virustotal
except Exception:
    Virustotal = None

# default polling behaviour
POLL_INTERVAL = 3
POLL_TIMEOUT = 60  # seconds


def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        try:
            return resp.data  # virustotal-python sometimes populates .data
        except Exception:
            return {}


def vt_domain_report(target: str) -> Dict:
    """
    Accepts either a domain (example.com) or a full URL (https://x).
    Returns a dict with vt_malicious_score, vt_suspicious_score, and vt_total_signals.
    Uses virustotal_python library for robust API usage and polling for URL analyses.
    """
    result = {"vt_malicious_score": 0, "vt_suspicious_score": 0, "vt_total_signals": 0}

    # check if library is present and key is set
    api_key = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
    if Virustotal is None or not api_key:
        return result

    # ensure virustotal_python sees the key in the expected env variable
    os.environ["VIRUSTOTAL_API_KEY"] = api_key

    try:
        # Do NOT pass api_key — library reads it from env
        with Virustotal() as vtotal:
            domain = target.strip().replace("https://", "").replace("http://", "").rstrip("/")

            # If it looks like a full URL, submit for URL scan
            if target.startswith("http://") or target.startswith("https://") or "/" in target:
                # Submit URL
                submit_resp = vtotal.request("urls", method="POST", params={"url": target})
                submit_json = _safe_json(submit_resp)

                analysis_id = None
                if "data" in submit_json and isinstance(submit_json["data"], dict):
                    analysis_id = submit_json["data"].get("id")
                if not analysis_id:
                    loc = submit_resp.headers.get("Location") or submit_resp.headers.get("location")
                    if loc and "/" in loc:
                        analysis_id = loc.rstrip("/").split("/")[-1]

                if not analysis_id:
                    return result

                # Poll analysis endpoint until finished
                start = time.time()
                analysis_json = None
                while time.time() - start <= POLL_TIMEOUT:
                    a_resp = vtotal.request(f"analyses/{analysis_id}")
                    a_json = _safe_json(a_resp)
                    status = a_json.get("data", {}).get("attributes", {}).get("status") if isinstance(a_json, dict) else None
                    if status == "completed":
                        analysis_json = a_json
                        break
                    time.sleep(POLL_INTERVAL)

                if analysis_json:
                    stats = analysis_json["data"]["attributes"].get("stats", {}) or {}
                    mal = stats.get("malicious", 0)
                    susp = stats.get("suspicious", 0)
                    total = sum(v for v in stats.values())
                    result.update({
                        "vt_malicious_score": int(mal),
                        "vt_suspicious_score": int(susp),
                        "vt_total_signals": int(total)
                    })
                return result

            # Otherwise, treat as domain
            resp = vtotal.request(f"domains/{domain}")
            j = _safe_json(resp)
            stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            total = sum(v for v in stats.values())
            result.update({
                "vt_malicious_score": int(mal),
                "vt_suspicious_score": int(susp),
                "vt_total_signals": int(total)
            })
            return result

    except Exception as e:
        print(f"[vt_connector] error: {e}")
        return result

def vt_ip_report(ip: str) -> Dict:
    """
    Queries VirusTotal for IP address reports.
    Returns malicious/suspicious/total detection counts similar to vt_domain_report().
    """
    result = {"vt_malicious_score": 0, "vt_suspicious_score": 0, "vt_total_signals": 0}

    api_key = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
    if Virustotal is None or not api_key:
        return result

    os.environ["VIRUSTOTAL_API_KEY"] = api_key

    try:
        with Virustotal() as vtotal:
            resp = vtotal.request(f"ip_addresses/{ip}")
            j = _safe_json(resp)
            stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            total = sum(v for v in stats.values())
            result.update({
                "vt_malicious_score": int(mal),
                "vt_suspicious_score": int(susp),
                "vt_total_signals": int(total)
            })
            return result

    except Exception as e:
        print(f"[vt_connector.ip] error: {e}")
        return result

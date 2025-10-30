# backend/app/features.py
def ssl_grade_to_num(grade):
    # map common SSL Lab grades to numeric severity (example mapping)
    if grade is None:
        return 0
    g = grade.strip().upper()
    mapping = {"A+": 0, "A": 0, "A-": 5, "B": 20, "C": 40, "D": 60, "E": 80, "F": 90, "T": 100}
    # some tools return just letters or scores; fallback:
    return mapping.get(g, 50)

def social_presence_to_num(s):
    # 'none', 'low', 'medium', 'high'
    if s is None: return 0
    s = s.lower()
    if s == "none": return 0
    if s == "low": return 20
    if s == "medium": return 50
    if s == "high": return 80
    return 0

def extract_features_from_osint(osint):
    """
    osint: dict possibly nested by connector name.
    Example:
      {
        "virustotal": {...},
        "abuseipdb": {...},
        "ssl": {...},
        ...
      }
    We flatten all nested dicts into one before extracting features.
    """
    # Flatten any nested dicts
    flat = {}
    for key, val in osint.items():
        if isinstance(val, dict):
            flat.update(val)
        else:
            flat[key] = val

    features = {}
    features["email_breached"] = int(flat.get("email_breached", 0))
    features["email_breach_count"] = int(flat.get("email_breach_count", 0))
    features["phone_breached"] = int(flat.get("phone_breached", 0))
    features["ip_abuse_score"] = int(flat.get("ip_abuse_score", 0))
    features["ip_abuse_reports"] = int(flat.get("ip_abuse_reports", 0))
    features["shodan_open_ports"] = int(flat.get("shodan_open_ports", 0))
    features["shodan_vuln_services"] = int(flat.get("shodan_vuln_services", 0))
    features["nvd_vuln_count"] = int(flat.get("nvd_vuln_count", 0))
    features["ssl_grade_num"] = ssl_grade_to_num(flat.get("ssl_grade"))
    features["ssl_expired"] = int(flat.get("ssl_expired", 0))
    features["social_presence_num"] = social_presence_to_num(flat.get("social_presence"))
    features["business_verified"] = int(flat.get("business_verified", 0))

    # ✅ Include VirusTotal signals explicitly
    features["vt_malicious_score"] = int(flat.get("vt_malicious_score", 0))
    features["vt_suspicious_score"] = int(flat.get("vt_suspicious_score", 0))
    features["vt_total_signals"] = int(flat.get("vt_total_signals", 0))

    return features

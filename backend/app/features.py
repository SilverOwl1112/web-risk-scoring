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
    osint: dict returned by connectors; keys expected:
      email_breached, email_breach_count, phone_breached,
      ip_abuse_score, ip_abuse_reports,
      shodan_open_ports, shodan_vuln_services,
      nvd_vuln_count,
      ssl_grade, ssl_expired, social_presence, business_verified
    Returns a dict with feature names matching training CSV.
    """
    features = {}
    features["email_breached"] = int(osint.get("email_breached", 0))
    features["email_breach_count"] = int(osint.get("email_breach_count", 0))
    features["phone_breached"] = int(osint.get("phone_breached", 0))
    features["ip_abuse_score"] = int(osint.get("ip_abuse_score", 0))
    features["ip_abuse_reports"] = int(osint.get("ip_abuse_reports", 0))
    features["shodan_open_ports"] = int(osint.get("shodan_open_ports", 0))
    features["shodan_vuln_services"] = int(osint.get("shodan_vuln_services", 0))
    features["nvd_vuln_count"] = int(osint.get("nvd_vuln_count", 0))
    features["ssl_grade_num"] = ssl_grade_to_num(osint.get("ssl_grade"))
    features["ssl_expired"] = int(osint.get("ssl_expired", 0))
    features["social_presence_num"] = social_presence_to_num(osint.get("social_presence"))
    features["business_verified"] = int(osint.get("business_verified", 0))
    return features


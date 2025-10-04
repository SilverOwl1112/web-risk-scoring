# backend/app/scoring.py
WEIGHTS = {
    'exposure_reputation': 20,
    'email_breach': 10,
    'open_ports': 15,
    'known_vuln': 15,
    'ssl_issues': 10,
    'whois_suspicious': 5,
    'malware_flags': 15,
    'ai_anomaly': 10
}

def compute_risk_score(features):
    # Example simplified scoring
    score = 0.0
    details = []
    # open ports (map 0..N to 0..weight)
    open_ports = features.get('shodan_open_ports', 0)
    score += min(open_ports, 10) / 10 * WEIGHTS['open_ports']
    details.append(f"Open ports: {open_ports}")

    malware_votes = features.get('vt_malicious_votes', 0)
    score += min(malware_votes, 5) / 5 * WEIGHTS['malware_flags']
    details.append(f"VT malicious votes: {malware_votes}")

    breach = features.get('hibp_breach_count', 0)
    score += min(breach, 5) / 5 * WEIGHTS['email_breach']
    details.append(f"HIBP breaches: {breach}")

    # normalize to 0..100
    score = min(round(score, 2), 100.0)
    return score, "; ".join(details)


# backend/app/features.py
def extract_features_from_enrichment(enrich):
    """
    Transform raw enrichment JSON into a numeric dict for scoring.
    Keep features explainable.
    """
    f = {}
    # example features - expand with real mappings
    f['shodan_open_ports'] = len(enrich.get('shodan', {}).get('ports', [])) if enrich.get('shodan') else 0
    f['vt_malicious_votes'] = enrich.get('vt', {}).get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) if enrich.get('vt') else 0
    f['hibp_breach_count'] = len(enrich.get('hibp', {}).get('breaches', [])) if enrich.get('hibp') else 0
    # more features...
    return f


def calculate_attack_surface_score(
    subdomains,
    technologies,
    endpoints,
    cves,
    vulnerabilities
):

    score = 0

    score += len(subdomains) * 2
    score += len(technologies) * 3
    score += len(endpoints) * 1
    score += len(cves) * 4
    score += len(vulnerabilities) * 5

    score = min(score, 100)

    if score < 20:
        level = "Very Low"
    elif score < 40:
        level = "Low"
    elif score < 60:
        level = "Moderate"
    elif score < 80:
        level = "High"
    else:
        level = "Critical"

    return {
        "attack_surface_score": score,
        "attack_surface_level": level
    }

import requests
import dns.resolver

COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "dev",
    "test",
    "staging",
    "api",
    "admin",
    "portal",
    "blog",
    "beta"
]

TAKEOVER_SIGNATURES = [
    "there is no app configured",
    "no such bucket",
    "repository not found",
    "heroku | no such app",
    "github pages site not found",
    "domain not found",
    "the specified bucket does not exist"
]


def discover_subdomains(domain):

    discovered = []

    for sub in COMMON_SUBDOMAINS:

        subdomain = f"{sub}.{domain}"

        try:
            dns.resolver.resolve(subdomain, "A")
            discovered.append(subdomain)

        except:
            continue

    return discovered


def check_takeover(subdomain):

    try:

        r = requests.get("http://" + subdomain, timeout=5)

        body = r.text.lower()

        for sig in TAKEOVER_SIGNATURES:

            if sig in body:
                return True

    except:
        pass

    return False


def scan_subdomains(domain):

    results = []

    subs = discover_subdomains(domain)

    for sub in subs:

        takeover = check_takeover(sub)

        results.append({
            "subdomain": sub,
            "takeover_risk": takeover
        })

    return {
        "discovered_subdomains": results,
        "total_subdomains": len(results),
        "possible_takeovers": sum(1 for r in results if r["takeover_risk"])
    }

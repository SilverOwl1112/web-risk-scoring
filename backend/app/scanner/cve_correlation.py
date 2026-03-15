import requests
from Wappalyzer import Wappalyzer, WebPage


def detect_technologies(url):
    try:
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        technologies = wappalyzer.analyze(webpage)
        return list(technologies)
    except Exception:
        return []


def query_nvd(keyword):

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 3
    }

    try:
        r = requests.get(url, params=params, timeout=10)
        data = r.json()

        cves = []

        for item in data.get("vulnerabilities", []):
            cve = item["cve"]

            cves.append({
                "id": cve["id"],
                "description": cve["descriptions"][0]["value"]
            })

        return cves

    except Exception:
        return []


def correlate_cves(url):

    technologies = detect_technologies(url)

    results = []

    for tech in technologies:
        cves = query_nvd(tech)

        results.append({
            "technology": tech,
            "cves": cves
        })

    return results

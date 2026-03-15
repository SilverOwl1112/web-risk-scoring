# backend/app/scanner/web_scanner.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

MAX_DEPTH = 2
MAX_PAGES = 10

HEADERS = {
    "User-Agent": "Mozilla/5.0 RiskScanner"
}

SEVERITY_SCORE = {
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 20,
    "CRITICAL": 30
}


class WebScanner:

    def __init__(self, base_url):
        self.base_url = base_url
        self.visited = set()
        self.pages = []
        self.vulnerabilities = []
        self.api_endpoints = []
        self.js_files = []

    # ---------------- CRAWLER ----------------

    def crawl(self):

        to_visit = [(self.base_url, 0)]

        while to_visit:

            url, depth = to_visit.pop(0)

            if url in self.visited:
                continue

            if depth > MAX_DEPTH:
                continue

            if len(self.pages) >= MAX_PAGES:
                break

            try:
                r = requests.get(url, headers=HEADERS, timeout=5)

                self.visited.add(url)
                self.pages.append(url)

                soup = BeautifulSoup(r.text, "html.parser")

                for link in soup.find_all("a", href=True):

                    full = urljoin(self.base_url, link["href"])

                    if urlparse(full).netloc == urlparse(self.base_url).netloc:

                        to_visit.append((full, depth + 1))

                for script in soup.find_all("script", src=True):

                    js_url = urljoin(self.base_url, script["src"])
                    self.js_files.append(js_url)

            except:
                pass

    # ---------------- HEADER CHECK ----------------

    def check_headers(self, response, url):

        required = [
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options"
        ]

        missing = [h for h in required if h not in response.headers]

        if missing:

            self.vulnerabilities.append({
                "type": "Missing Security Headers",
                "url": url,
                "severity": "MEDIUM",
                "details": missing
            })

    # ---------------- LOGIN FORM DETECTION ----------------

    def detect_login(self, soup, url):

        if soup.find("input", {"type": "password"}):

            self.vulnerabilities.append({
                "type": "Login Form Detected",
                "url": url,
                "severity": "LOW"
            })

    # ---------------- CSRF CHECK ----------------

    def detect_csrf(self, soup, url):

        forms = soup.find_all("form")

        for form in forms:

            token = form.find("input", {"type": "hidden"})

            if not token:

                self.vulnerabilities.append({
                    "type": "Possible CSRF",
                    "url": url,
                    "severity": "MEDIUM"
                })

    # ---------------- XSS TEST ----------------

    def test_xss(self, url):

        payload = "<script>alert(1)</script>"

        try:

            r = requests.get(url + "?q=" + payload, timeout=5)

            if payload in r.text:

                self.vulnerabilities.append({
                    "type": "Reflected XSS",
                    "url": url,
                    "severity": "HIGH"
                })

        except:
            pass

    # ---------------- SQLI TEST ----------------

    def test_sqli(self, url):

        payload = "' OR '1'='1"

        errors = [
            "sql syntax",
            "mysql",
            "syntax error",
            "odbc",
            "pdo"
        ]

        try:

            r = requests.get(url + "?id=" + payload, timeout=5)

            if any(e in r.text.lower() for e in errors):

                self.vulnerabilities.append({
                    "type": "SQL Injection",
                    "url": url,
                    "severity": "CRITICAL"
                })

        except:
            pass

    # ---------------- OPEN REDIRECT ----------------

    def test_redirect(self, url):

        try:

            test_url = url + "?redirect=https://evil.com"

            r = requests.get(test_url, allow_redirects=False)

            if "evil.com" in r.headers.get("Location", ""):

                self.vulnerabilities.append({
                    "type": "Open Redirect",
                    "url": url,
                    "severity": "HIGH"
                })

        except:
            pass

    # ---------------- DIRECTORY TRAVERSAL ----------------

    def test_traversal(self, url):

        payload = "../../etc/passwd"

        try:

            r = requests.get(url + "?file=" + payload)

            if "root:x:" in r.text:

                self.vulnerabilities.append({
                    "type": "Directory Traversal",
                    "url": url,
                    "severity": "HIGH"
                })

        except:
            pass

    # ---------------- JS SECRET DETECTION ----------------

    def scan_js(self):

        patterns = ["api_key", "secret", "token", "password"]

        for js in self.js_files:

            try:

                r = requests.get(js)

                content = r.text.lower()

                for p in patterns:

                    if p in content:

                        self.vulnerabilities.append({
                            "type": "Possible Secret in JS",
                            "url": js,
                            "severity": "MEDIUM"
                        })

                        break

            except:
                pass

    # ---------------- API ENDPOINT DISCOVERY ----------------

    def detect_api(self):

        for page in self.pages:

            if any(x in page for x in ["/api/", "/v1/", "/rest/"]):

                self.api_endpoints.append(page)

    # ---------------- SCAN RUNNER ----------------

    def run_scan(self):

        self.crawl()

        for url in self.pages:

            try:

                r = requests.get(url, headers=HEADERS, timeout=5)

                soup = BeautifulSoup(r.text, "html.parser")

                self.check_headers(r, url)
                self.detect_login(soup, url)
                self.detect_csrf(soup, url)

                self.test_xss(url)
                self.test_sqli(url)
                self.test_redirect(url)
                self.test_traversal(url)

            except:
                pass

        self.scan_js()
        self.detect_api()

        score = self.calculate_score()

        return {
            "pages_scanned": len(self.pages),
            "vulnerabilities": self.vulnerabilities,
            "api_endpoints": self.api_endpoints,
            "web_risk_score": score
        }

    # ---------------- RISK SCORE ----------------

    def calculate_score(self):

        total = 0

        for v in self.vulnerabilities:

            total += SEVERITY_SCORE.get(v["severity"], 0)

        return min(total, 100)

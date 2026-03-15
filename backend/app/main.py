# backend/app/main.py
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict
import traceback
import os
import json
import re
import ipaddress

# === Phase 2 Scanners ===
from .scanner.web_scanner import WebScanner
from .scanner.cve_correlation import correlate_cves
from .scanner.subdomain_scanner import scan_subdomains
from app.ml.ai_risk_predictor import predict_risk
from app.scanner.attack_surface_score import calculate_attack_surface_score

# --- Import connectors ---
from .connectors import (
    shodan_connector,
    vt_connector,
    hibp_connector,
    abuseipdb_connector,
    ssl_connector,
    nvd_connector
)

from .features import extract_features_from_osint
from .scoring import predict_score
from . import report


# --- Initialize FastAPI ---
app = FastAPI(title="Cyber Risk Scoring API")

# --- Allow CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Health Check ---
@app.get("/")
async def root():
    return {"status": "online"}


# --- Request Model ---
class ScanRequest(BaseModel):
    target: str


# ===============================
# === MAIN SCAN ENDPOINT
# ===============================
@app.post("/api/scan")
async def scan_endpoint(req: ScanRequest):

    target = req.target.strip()
    osint = {}

    # Detect IP
    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    try:

        # ===============================
        # === PHASE 1 – OSINT SCANS
        # ===============================

        # --- Shodan ---
        try:
            osint.update(shodan_connector.scan_host(target))
        except Exception as e:
            print("shodan error:", e)
            osint.update({"shodan_open_ports": 0, "shodan_vuln_services": 0})

        # --- VirusTotal ---
        try:
            if is_ip:
                osint.update(vt_connector.vt_ip_report(target))
            else:
                osint.update(vt_connector.vt_domain_report(target))
        except Exception as e:
            print("vt error:", e)
            osint.update({
                "vt_malicious_score": 0,
                "vt_suspicious_score": 0,
                "vt_total_signals": 0
            })

        # --- HaveIBeenPwned ---
        try:
            if not is_ip:
                osint.update(hibp_connector.check_pwned(target))
            else:
                osint.update({"pwned_count": 0})
        except Exception as e:
            print("hibp error:", e)
            osint.update({"pwned_count": 0})

        # --- AbuseIPDB ---
        try:
            if is_ip:
                osint.update(abuseipdb_connector.check_ip_reputation(target))
            else:
                osint.update({"abuse_confidence_score": 0})
        except Exception as e:
            print("abuseipdb error:", e)
            osint.update({"abuse_confidence_score": 0})

        # --- SSL Labs ---
        try:
            if not is_ip:
                osint.update(await ssl_connector.check_ssl_grade_async(target))
            else:
                osint.update({"ssl_grade": "N/A", "ssl_issues": 0})
        except Exception as e:
            print("ssl error:", e)
            osint.update({"ssl_grade": "N/A", "ssl_issues": 0})

        # --- NVD keyword scan ---
        try:
            if not is_ip:
                osint.update(nvd_connector.get_vuln_count(target))
            else:
                osint.update({"nvd_vuln_count": 0})
        except Exception as e:
            print("nvd error:", e)
            osint.update({"nvd_vuln_count": 0})


        # ===============================
        # === PHASE 2 – WEB SCANNER
        # ===============================

        web_scan_result = {}

        if not is_ip:
            try:
                url = "http://" + target if not target.startswith("http") else target
                scanner = WebScanner(url)
                web_scan_result = scanner.run_scan()
            except Exception as e:
                print("web scanner error:", e)
                web_scan_result = {}


        # ===============================
        # === PHASE 2C – CVE CORRELATION
        # ===============================

        cve_results = {}

        if not is_ip:
            try:
                url = "http://" + target if not target.startswith("http") else target
                cve_results = correlate_cves(url)
            except Exception as e:
                print("cve correlation error:", e)
                cve_results = {}


        # ===============================
        # === SUBDOMAIN DISCOVERY
        # ===============================

        subdomain_results = {}

        if not is_ip:
            try:
                subdomain_results = scan_subdomains(target)
            except Exception as e:
                print("subdomain scan error:", e)
                subdomain_results = {}


        # ===============================
        # === ML RISK SCORING
        # ===============================

        features = extract_features_from_osint(osint)
        result = predict_score(features)

        # --- Extract metrics for AI model ---

        vulnerabilities = web_scan_result.get("vulnerabilities", [])
        cves = cve_results if isinstance(cve_results, list) else []
        subdomains = subdomain_results.get("subdomains", []) if isinstance(subdomain_results, dict) else []
        missing_headers = web_scan_result.get("missing_security_headers", 0)

        # Extract technology + endpoint data
        technologies = web_scan_result.get("technologies", [])
        endpoints = web_scan_result.get("endpoints", [])

        risk_level = predict_risk(
            len(vulnerabilities),
            len(cves),
            len(subdomains),
            missing_headers
        )

        attack_surface = calculate_attack_surface_score(
            subdomains,
            technologies,
            endpoints,
            cves,
            vulnerabilities
        )


        # ===============================
        # === FINAL SCAN JSON
        # ===============================

        full_scan = {
            "target": target,
            "osint": osint,
            "features": features,
            "result": result,
            "web_scan": web_scan_result,
            "cve_correlation": cve_results,
            "subdomain_analysis": subdomain_results,
            "ai_risk_prediction": risk_level,
            "attack_surface": attack_surface
        }


        # ===============================
        # === SAVE RESULT FOR REPORT
        # ===============================

        safe_name = re.sub(r"[^\w\-\.]", "_", target)
        os.makedirs("reports", exist_ok=True)

        cached_json_path = os.path.join("reports", f"{safe_name}_scan.json")

        with open(cached_json_path, "w", encoding="utf-8") as fh:
            json.dump(full_scan, fh, indent=2)


        return full_scan

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# ===============================
# === REPORT DOWNLOAD ENDPOINT
# ===============================
@app.post("/api/report")
async def download_report(req: ScanRequest):

    from fastapi.concurrency import run_in_threadpool

    try:

        target = req.target.strip()

        if not target:
            raise HTTPException(status_code=400, detail="Target required")

        os.makedirs("reports", exist_ok=True)

        safe_name = re.sub(r"[^\w\-\.]", "_", target)
        cached_json_path = os.path.join("reports", f"{safe_name}_scan.json")

        if not os.path.exists(cached_json_path):
            raise HTTPException(
                status_code=404,
                detail="Scan result not found. Run /api/scan first."
            )

        with open(cached_json_path, "r", encoding="utf-8") as fh:
            cached = json.load(fh)

        score = cached["result"]["score"]
        category = cached["result"]["category"]

        full_json = cached

        def sync_generate():
            return report.generate_report(
                target=safe_name,
                score=score,
                details="Full OSINT and scanning results included.",
                full_json=full_json
            )

        output_path = await run_in_threadpool(sync_generate)

        if not os.path.exists(output_path):
            raise HTTPException(status_code=500, detail="Report generation failed")

        filename = os.path.basename(output_path)

        return FileResponse(
            path=output_path,
            filename=filename,
            media_type="application/pdf"
        )

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# --- Run App Locally ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000)

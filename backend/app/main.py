# backend/app/main.py
from dotenv import load_dotenv
# ensure env vars are loaded BEFORE connectors are imported
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict
import traceback
import os

# --- Import connectors (now env loaded) ---
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
from . import report  # ✅ for PDF report generation

# --- Initialize FastAPI ---
app = FastAPI(title="Cyber Risk Scoring API")

# --- Allow CORS for Flutter and Web Clients ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# (rest of file unchanged — routes, report endpoint, etc.)
# --- Health Check Endpoint ---
@app.get("/")
async def root():
    return {"status": "online"}

# --- Request Model ---
class ScanRequest(BaseModel):
    target: str  # domain or IP

# --- Main Scan Endpoint (with IP + Domain handling) ---
@app.post("/api/scan")
async def scan_endpoint(req: ScanRequest):
    import ipaddress

    target = req.target.strip()
    osint = {}

    # --- Detect if it's an IP address ---
    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False  # it's a domain

    try:
        # === 1. Shodan Scan ===
        try:
            osint.update(shodan_connector.scan_host(target))
        except Exception as e:
            print(f"[SCAN] shodan error: {e}")
            osint.update({"shodan_open_ports": 0, "shodan_vuln_services": 0})

        # === 2. VirusTotal ===
        try:
            if is_ip:
                # use IP report if available
                osint.update(vt_connector.vt_ip_report(target))
            else:
                osint.update(vt_connector.vt_domain_report(target))
        except Exception as e:
            print(f"[SCAN] vt error: {e}")
            osint.update({"vt_malicious_score": 0, "vt_suspicious_score": 0, "vt_total_signals": 0})

        # === 3. Have I Been Pwned (only meaningful for domains/emails) ===
        try:
            if not is_ip:
                osint.update(hibp_connector.check_pwned(target))
            else:
                osint.update({"pwned_count": 0})
        except Exception as e:
            print(f"[SCAN] hibp error: {e}")
            osint.update({"pwned_count": 0})

        # === 4. AbuseIPDB (only valid for IPs) ===
        try:
            if is_ip:
                osint.update(abuseipdb_connector.check_ip_reputation(target))
            else:
                osint.update({"abuse_confidence_score": 0})
        except Exception as e:
            print(f"[SCAN] abuseipdb error: {e}")
            osint.update({"abuse_confidence_score": 0})

        # === 5. SSL Labs (domain-only, skip for IPs) ===
        try:
            if not is_ip:
                osint.update(await ssl_connector.check_ssl_grade_async(target))
            else:
                osint.update({"ssl_grade": "N/A", "ssl_issues": 0})
        except Exception as e:
            print(f"[SCAN] ssl error: {e}")
            osint.update({"ssl_grade": "N/A", "ssl_issues": 0})


        # === 6. NVD Vulnerabilities (keyword-based, domain-only) ===
        try:
            if not is_ip:
                osint.update(nvd_connector.get_vuln_count(target))
            else:
                osint.update({"nvd_vuln_count": 0})
        except Exception as e:
            print(f"[SCAN] nvd error: {e}")
            osint.update({"nvd_vuln_count": 0})


        # === 7. Feature Extraction + Scoring ===
        features = extract_features_from_osint(osint)
        result = predict_score(features)

        return {"target": target, "osint": osint, "features": features, "result": result}

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# --- Generate and Download Report Endpoint ---
# --- Generate and Download Report Endpoint ---
# --- Generate and Download Report Endpoint (REPLACE THIS BLOCK) ---
@app.post("/api/report")
async def download_report(req: ScanRequest):
    """
    Generates a PDF report for `target`.
    - Reuses cached scan if available (reports/{target}_scan.json).
    - Otherwise performs a safe live scan (with timeout for SSL Labs).
    - Runs PDF generation/upload in a threadpool to avoid blocking the event loop.
    """
    import asyncio
    from fastapi.concurrency import run_in_threadpool
    import json
    import re

    try:
        target = req.target.strip()
        if not target:
            raise HTTPException(status_code=400, detail="Target is required")

        os.makedirs("reports", exist_ok=True)

        # sanitize safe filename (replace slashes, colons, spaces)
        safe_name = re.sub(r"[^\w\-\.]", "_", target)

        # Cached scan path
        cached_json_path = os.path.join("reports", f"{safe_name}_scan.json")

        osint = {}
        features = {}
        result_data = {}

        # 1) If cached scan exists, reuse it
        if os.path.exists(cached_json_path):
            try:
                with open(cached_json_path, "r", encoding="utf-8") as fh:
                    cached = json.load(fh)
                osint = cached.get("osint", {}) or {}
                features = cached.get("features", {}) or {}
                # If cached result_data stored as top-level structure, reuse; else rebuild
                result_data = cached if isinstance(cached, dict) and "score" in cached else cached.get("result", {}) or {}
            except Exception as e:
                # if cache read fails, fall back to live scan
                print(f"[REPORT] failed to read cache {cached_json_path}: {e}")
                osint = {}
                features = {}
                result_data = {}

        # 2) If no useful cache, run a safe live scan (non-blocking behavior for SSL)
        if not result_data or "score" not in result_data:
            # Gather connectors (each guarded)
            try:
                # Shodan (safe)
                try:
                    osint.update(shodan_connector.scan_host(target))
                except Exception as e:
                    print(f"[REPORT] shodan error: {e}")
                    osint.update({"shodan_open_ports": 0, "shodan_vuln_services": 0})
                # VirusTotal (safe)
                try:
                    osint.update(vt_connector.vt_domain_report(target))
                except Exception as e:
                    print(f"[REPORT] vt error: {e}")
                    osint.update({"vt_malicious_score": 0, "vt_suspicious_score": 0, "vt_total_signals": 0})
                # HIBP
                try:
                    osint.update(hibp_connector.check_pwned(target))
                except Exception as e:
                    print(f"[REPORT] hibp error: {e}")
                    osint.update({"pwned_count": 0})
                # AbuseIPDB
                try:
                    osint.update(abuseipdb_connector.check_ip_reputation(target))
                except Exception as e:
                    print(f"[REPORT] abuseipdb error: {e}")
                    osint.update({"abuse_confidence_score": 0})
                # SSL Labs -> **bounded** timeout to avoid hanging
                try:
                    ssl_info = None
                    # await ssl analysis with timeout (12s). If it hangs, fallback.
                    try:
                        ssl_info = await asyncio.wait_for(ssl_connector.check_ssl_grade_async(target), timeout=12.0)
                    except asyncio.TimeoutError:
                        print(f"[REPORT] ssl_connector timeout for {target}")
                    except Exception as e:
                        print(f"[REPORT] ssl_connector error: {e}")
                    if ssl_info:
                        osint.update(ssl_info)
                    else:
                        osint.update({"ssl_grade": "N/A", "ssl_issues": 0})
                except Exception as e:
                    print(f"[REPORT] ssl outer error: {e}")
                    osint.update({"ssl_grade": "N/A", "ssl_issues": 0})
                # === NVD Vulnerabilities (keyword-based, domain-only) ===
                try:
                    osint.update(nvd_connector.get_vuln_count(target))
                except Exception as e:
                    print(f"[REPORT] nvd error: {e}")
                    osint.update({"nvd_vuln_count": 0})

            except Exception as e:
                print(f"[REPORT] unexpected scan error: {e}")

            # Extract features and compute score
            try:
                features = extract_features_from_osint(osint)
                result_data = predict_score(features)
                # attach osint for completeness
                result_data["osint"] = osint
            except Exception as e:
                print(f"[REPORT] feature/score error: {e}")
                result_data = {"score": None, "category": "N/A"}

            # Cache the scan results for future report calls
            try:
                with open(cached_json_path, "w", encoding="utf-8") as fh:
                    json.dump(result_data, fh, indent=2)
            except Exception as e:
                print(f"[REPORT] failed to write cache {cached_json_path}: {e}")

        # 3) Build full_json for report content
        score = result_data.get("score")
        category = result_data.get("category")
        full_json = {
            "target": target,
            "score": score,
            "category": category,
            "osint": osint,
            "features": features,
            "result": result_data
        }

        # 4) Generate PDF in threadpool (prevents event-loop blocking and ctrl+c hang)
        def sync_generate():
            # call existing report.generate_report (synchronous)
            return report.generate_report(
                target=safe_name,
                score=score,
                details="Full OSINT + scoring included in report JSON.",
                full_json=full_json
            )

        output_path = await run_in_threadpool(sync_generate)

        # 5) Check output and return FileResponse for download
        if not output_path or not os.path.exists(output_path):
            raise HTTPException(status_code=500, detail="Report generation failed")

        filename = os.path.basename(output_path)
        return FileResponse(path=output_path, filename=filename, media_type="application/pdf")

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
# --- end /api/report replacement ---

# --- Run App Locally ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000)

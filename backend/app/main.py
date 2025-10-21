# backend/app/main.py

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict
from dotenv import load_dotenv
import traceback
import os

# --- Import connectors ---
from .connectors import (
    shodan_connector,
    vt_connector,
    hibp_connector,
    abuseipdb_connector,
    ssl_connector
)
from .features import extract_features_from_osint
from .scoring import predict_score
from . import report  # ✅ for PDF report generation

# --- Load environment variables ---
load_dotenv()

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

# --- Health Check Endpoint ---
@app.get("/")
async def root():
    return {"status": "online"}

# --- Request Model ---
class ScanRequest(BaseModel):
    target: str  # domain or IP

# --- Main Scan Endpoint ---
@app.post("/api/scan")
async def scan_endpoint(req: ScanRequest):
    target = req.target.strip()
    osint = {}

    try:
        # === 1. Shodan Scan ===
        try:
            osint.update(shodan_connector.scan_host(target))
        except Exception:
            osint.update({"shodan_open_ports": 0, "shodan_vuln_services": 0})

        # === 2. VirusTotal ===
        try:
            osint.update(vt_connector.vt_domain_report(target))
        except Exception:
            osint.update({"vt_malicious_score": 0})

        # === 3. Have I Been Pwned ===
        try:
            osint.update(hibp_connector.check_pwned(target))
        except Exception:
            osint.update({"pwned_count": 0})

        # === 4. AbuseIPDB ===
        try:
            osint.update(abuseipdb_connector.check_ip_reputation(target))
        except Exception:
            osint.update({"abuse_confidence_score": 0})

        # === 5. SSL Labs ===
        try:
            osint.update(ssl_connector.check_ssl_grade(target))
        except Exception:
            osint.update({"ssl_grade": "N/A", "ssl_issues": 0})

        # === 6. Feature Extraction + Scoring ===
        features = extract_features_from_osint(osint)
        result = predict_score(features)

        return {"target": target, "osint": osint, "features": features, "result": result}

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# --- Generate and Download Report Endpoint ---
@app.post("/api/report")
async def download_report(req: ScanRequest):
    try:
        target = req.target.strip()
        os.makedirs("reports", exist_ok=True)

        # Generate a live score and details for the report
        try:
            features = extract_features_from_osint({})
            result_data = predict_score(features)
            score = result_data.get("score") if result_data else None
            details = "Scan details available in JSON."  # Replace with actual scan details if needed
        except Exception:
            score = None
            details = None
            result_data = None

        # Include JSON scan result in the report
        full_json = {
            "target": target,
            "score": score,
            "details": details,
            "features": features if 'features' in locals() else {},
            "result": result_data if result_data else {}
        }

        output_path = report.generate_report(
            target=target,
            score=score,
            details=details,
            full_json=full_json
        )

        if not os.path.exists(output_path):
            raise HTTPException(status_code=404, detail="Report generation failed.")

        filename = os.path.basename(output_path)
        return FileResponse(
            path=output_path,
            filename=filename,
            media_type="application/pdf"
        )

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# --- Run App Locally ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000)

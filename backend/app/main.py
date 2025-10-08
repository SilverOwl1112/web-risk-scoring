# backend/app/main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict
import traceback

from .connectors import (
    shodan_connector,
    vt_connector,
    hibp_connector,
    abuseipdb_connector,
    ssl_connector
)
from .features import extract_features_from_osint
from .scoring import predict_score

app = FastAPI(title="Cyber Risk Scoring API")

class ScanRequest(BaseModel):
    target: str  # domain or IP

@app.post("/api/scan")
async def scan_endpoint(req: ScanRequest):
    target = req.target.strip()
    osint = {}
    try:
        # === 1. Shodan Scan ===
        try:
            osint.update(shodan_connector.scan_host(target))
        except Exception as e:
            osint.update({"shodan_open_ports": 0, "shodan_vuln_services": 0})

        # === 2. VirusTotal ===
        try:
            osint.update(vt_connector.vt_domain_report(target))
        except Exception as e:
            osint.update({"vt_malicious_score": 0})

        # === 3. Have I Been Pwned ===
        try:
            osint.update(hibp_connector.check_pwned(target))
        except Exception as e:
            osint.update({"pwned_count": 0})

        # === 4. AbuseIPDB ===
        try:
            osint.update(abuseipdb_connector.check_ip_reputation(target))
        except Exception as e:
            osint.update({"abuse_confidence_score": 0})

        # === 5. SSL Labs ===
        try:
            osint.update(ssl_connector.check_ssl_grade(target))
        except Exception as e:
            osint.update({"ssl_grade": "N/A", "ssl_issues": 0})

        # === 6. Feature Extraction + Scoring ===
        features = extract_features_from_osint(osint)
        result = predict_score(features)

        return {"target": target, "osint": osint, "features": features, "result": result}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

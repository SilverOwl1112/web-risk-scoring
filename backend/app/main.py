# backend/app/main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.features import extract_features_from_enrichment
from app.scoring import compute_risk_score
from app.report import generate_pdf_report
from app.models import init_db, SessionLocal, ScanResult

app = FastAPI(title="Web Risk Scoring API")

# initialize DB
init_db()

class ScanRequest(BaseModel):
    target: str   # domain or IP
    mode: str = "passive"  # 'passive' or 'full' (full disabled unless permitted)
    meta: dict = {}

@app.post("/api/scan")
def start_scan(payload: ScanRequest):
    target = payload.target
    # 1) Call connectors to enrich data (placeholders - safe read-only)
    # Note: implement connectors in app/connectors/*.py and use API keys set via env
    from app.connectors import shodan_connector, vt_connector, hibp_connector
    enrichment = {}
    # Do safe, read-only enrichments (no active exploits)
    try:
        enrichment['shodan'] = shodan_connector.query_host(target)    # returns dict or None
        enrichment['vt'] = vt_connector.query_domain(target)
        enrichment['hibp'] = hibp_connector.check_domain(target)
    except Exception as e:
        # log and continue
        enrichment['error'] = str(e)

    # 2) Extract features
    features = extract_features_from_enrichment(enrichment)

    # 3) Compute score
    score, details = compute_risk_score(features)

    # 4) Persist result
    db = SessionLocal()
    record = ScanResult(target=target, score=score, details=details)
    db.add(record)
    db.commit()
    db.refresh(record)

    # 5) generate report (pdf) and return URL placeholder
    pdf_path = generate_pdf_report(record.id, target, score, details)
    # Upload pdf_path to S3 in production; here we return local path
    return {"scan_id": record.id, "score": score, "details": details, "report": pdf_path}


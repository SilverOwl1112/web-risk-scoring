# backend/app/scoring.py
import os
import joblib
import boto3
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

# === Define paths ===
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_DIR = os.path.join(BASE_DIR, "ml", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

MODEL_PATH = os.path.join(MODEL_DIR, "xgb_model.joblib")
COLUMNS_PATH = os.path.join(MODEL_DIR, "model_columns.joblib")

S3_BUCKET = os.getenv("S3_BUCKET_NAME")
S3_MODEL_KEY = os.getenv("S3_MODEL_KEY", "models/xgb_model.joblib")
S3_COLUMNS_KEY = os.getenv("S3_COLUMNS_KEY", "models/model_columns.joblib")

_model = None
_model_columns = None

def download_model_from_s3():
    """Download model files from S3 if not already cached locally."""
    s3 = boto3.client("s3")
    try:
        if not os.path.exists(MODEL_PATH):
            print(f"⬇️ Downloading model from S3: {S3_MODEL_KEY}")
            s3.download_file(S3_BUCKET, S3_MODEL_KEY, MODEL_PATH)
        if not os.path.exists(COLUMNS_PATH):
            print(f"⬇️ Downloading columns from S3: {S3_COLUMNS_KEY}")
            s3.download_file(S3_BUCKET, S3_COLUMNS_KEY, COLUMNS_PATH)
    except Exception as e:
        print(f"⚠️ Model download failed: {e}")

def load_model_and_columns():
    global _model, _model_columns
    if _model is None or _model_columns is None:
        download_model_from_s3()
        _model = joblib.load(MODEL_PATH)
        _model_columns = joblib.load(COLUMNS_PATH)
        # Ensure columns is a list
        if hasattr(_model_columns, "tolist"):
            _model_columns = list(_model_columns.tolist())
        elif isinstance(_model_columns, (list, tuple)):
            _model_columns = list(_model_columns)
        else:
            # fallback: try to coerce
            _model_columns = list(_model_columns)
    return _model, _model_columns

def categorize(score):
    if score <= 40:
        return "Low"
    elif score <= 70:
        return "Medium"
    else:
        return "High"

def predict_score(feature_dict):
    """
    feature_dict contains both the original model features AND new connector outputs
    (vt_malicious_score, vt_suspicious_score, vt_total_signals, abuse_confidence_score,
     ssl_issues, pwned_count, shodan_vuln_services, etc.)

    Strategy:
     - Build a core_features dict only for columns the model was trained on (model_columns).
     - Predict using the model to obtain raw base score.
     - Apply rule-based amplification using the *extra* signals.
    """
    model, model_columns = load_model_and_columns()

    # --- Build core feature dict (only model columns) ---
    core_features = {}
    for col in model_columns:
        # fetch value from feature_dict or default 0
        core_features[col] = feature_dict.get(col, 0)

    # Create DF for model prediction
    df_core = pd.DataFrame([core_features])
    raw_pred = model.predict(df_core)[0]
    raw_score = float(raw_pred)
    base_score = int(round(raw_score))

    # --- Collect amplification signals (from connectors) ---
    vt_malicious = feature_dict.get("vt_malicious_score", 0)
    vt_suspicious = feature_dict.get("vt_suspicious_score", 0)
    vt_total = feature_dict.get("vt_total_signals", vt_malicious + vt_suspicious)
    abuse_score = feature_dict.get("abuse_confidence_score", 0)
    ssl_issues = feature_dict.get("ssl_issues", 0)
    pwned_count = feature_dict.get("pwned_count", 0)
    shodan_vulns = feature_dict.get("shodan_vuln_services", 0)
    shodan_ports = feature_dict.get("shodan_open_ports", 0)
    nvd_vuln_count = feature_dict.get("nvd_vuln_count", 0)

    # --- Rule-based amplification (transparent, tunable) ---
    amplified = base_score
    details = {"base_score": base_score}

    # VirusTotal signals (weighted by actual detections, not total vendors)
    vt_ratio = (vt_malicious + vt_suspicious) / max(vt_total, 1)

    if vt_malicious + vt_suspicious == 0:
        details["vt_boost"] = 0
    elif (vt_malicious + vt_suspicious) >= 4:
        amplified += 45
        details["vt_boost"] = 45
    elif (vt_malicious + vt_suspicious) >= 2:
        amplified += 30
        details["vt_boost"] = 30
    elif (vt_malicious + vt_suspicious) >= 1:
        amplified += 15
        details["vt_boost"] = 15
    else:
        details["vt_boost"] = 0

    # SSL issues
    if ssl_issues:
        amplified += 12
        details["ssl_boost"] = 12
    else:
        details["ssl_boost"] = 0

    # HIBP / pwned accounts
    if pwned_count >= 100:
        amplified += 18
        details["pwned_boost"] = 18
    elif pwned_count > 0:
        amplified += 8
        details["pwned_boost"] = 8
    else:
        details["pwned_boost"] = 0

    # Shodan signals
    if shodan_vulns >= 5:
        amplified += 18
        details["shodan_boost"] = 18
    elif shodan_vulns > 0:
        amplified += 8
        details["shodan_boost"] = 8
    else:
        details["shodan_boost"] = 0

    # Additional: large number of open ports, or many NVD vulns
    if shodan_ports >= 10:
        amplified += 5
        details["shodan_ports_boost"] = 5
    else:
        details["shodan_ports_boost"] = 0

    if nvd_vuln_count >= 10:
        amplified += 7
        details["nvd_boost"] = 7
    else:
        details["nvd_boost"] = 0

    # --- Final normalization/clamping ---
    final_score = min(max(int(round(amplified)), 0), 100)
    details["final_before_clamp"] = amplified
    details["final_score"] = final_score

    return {
        "score": final_score,
        "category": categorize(final_score),
        "raw": raw_score,
        "adjusted": True,
        "breakdown": details,
        # echo back key signals for transparency
        "vt_malicious": vt_malicious,
        "vt_suspicious": vt_suspicious,
        "vt_total_signals": vt_total,
        "abuse_score": abuse_score,
        "ssl_issues": ssl_issues,
        "pwned_count": pwned_count,
        "shodan_vulns": shodan_vulns,
        "shodan_open_ports": shodan_ports,
        "nvd_vuln_count": nvd_vuln_count
    }

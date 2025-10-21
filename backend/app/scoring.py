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
        download_model_from_s3()  # Ensure files exist before loading
        _model = joblib.load(MODEL_PATH)
        _model_columns = joblib.load(COLUMNS_PATH)
    return _model, _model_columns


def categorize(score):
    if score <= 40:
        return "Low"
    elif score <= 70:
        return "Medium"
    else:
        return "High"


def predict_score(feature_dict):
    model, model_columns = load_model_and_columns()

    df = pd.DataFrame([feature_dict])
    if "ssl_grade" in df.columns or "social_presence" in df.columns:
        df = pd.get_dummies(df, columns=["ssl_grade", "social_presence"], drop_first=True)
    df = df.reindex(columns=model_columns, fill_value=0)

    raw = model.predict(df)[0]
    score = int(round(raw))

    return {
        "score": score,
        "category": categorize(score),
        "raw": float(raw),
    }

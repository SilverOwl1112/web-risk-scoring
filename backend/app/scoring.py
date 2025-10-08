# backend/app/scoring.py
import os
import joblib
import numpy as np
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODEL_DIR = os.path.join(BASE_DIR, "ml", "models")

MODEL_PATH = os.path.join(MODEL_DIR, "xgb_model.joblib")
COLUMNS_PATH = os.path.join(MODEL_DIR, "model_columns.joblib")

_model = None
_model_columns = None


def load_model_and_columns():
    global _model, _model_columns
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model not found: {MODEL_PATH}")
        _model = joblib.load(MODEL_PATH)
    if _model_columns is None:
        if not os.path.exists(COLUMNS_PATH):
            raise FileNotFoundError(f"Model columns not found: {COLUMNS_PATH}")
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

    # Convert features to DataFrame
    df = pd.DataFrame([feature_dict])

    # Apply same one-hot encoding as training
    if "ssl_grade" in df.columns or "social_presence" in df.columns:
        df = pd.get_dummies(df, columns=["ssl_grade", "social_presence"], drop_first=True)

    # Align columns with model training set
    df = df.reindex(columns=model_columns, fill_value=0)

    raw = model.predict(df)[0]
    score = int(round(raw))

    return {
        "score": int(score),
        "category": categorize(score),
        "raw": float(raw)
    }

# ml/train_model.py
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score
import joblib
import os


def categorize(score):
    if score <= 40:
        return "Low"
    elif score <= 70:
        return "Medium"
    else:
        return "High"


def train_and_save_model():
    dataset_path = os.path.join(os.path.dirname(__file__), "datasets", "cyber_risk_dataset.csv")
    df = pd.read_csv(dataset_path)
    print(f"Loaded dataset with shape: {df.shape}")

    X = df.drop(columns=["final_risk_score"])
    y = df["final_risk_score"]

    # One-hot encode categorical columns
    X = pd.get_dummies(X, columns=["ssl_grade", "social_presence"], drop_first=True)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = xgb.XGBRegressor(
        objective="reg:squarederror",
        n_estimators=200,
        learning_rate=0.1,
        max_depth=6,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42
    )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"MSE: {mean_squared_error(y_test, y_pred):.2f}")
    print(f"R2 Score: {r2_score(y_test, y_pred):.2f}")

    model_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(model_dir, exist_ok=True)

    model_path = os.path.join(model_dir, "xgb_model.joblib")
    cols_path = os.path.join(model_dir, "model_columns.joblib")

    joblib.dump(model, model_path)
    joblib.dump(X.columns.tolist(), cols_path)

    print(f"✅ Saved model: {model_path}")
    print(f"✅ Saved model columns: {cols_path}")


if __name__ == "__main__":
    train_and_save_model()

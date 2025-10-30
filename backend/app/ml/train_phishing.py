# ml/train_phishing.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# For demonstration, use a simple URL feature CSV (you must download a phishing dataset)
df = pd.read_csv("datasets/phishing_dataset.csv")
# Example: features are precomputed; if not, create simple features (length, token counts)
X = df.drop(columns=["label"])
y = df["label"].map({"phishing":1, "legit":0})

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

pred = clf.predict(X_test)
print(classification_report(y_test, pred))

joblib.dump(clf, "models/phishing_clf.joblib")

# Anomaly detector for features
iso = IsolationForest(contamination=0.01, random_state=42)
iso.fit(X_train)
joblib.dump(iso, "models/anomaly_iso.joblib")

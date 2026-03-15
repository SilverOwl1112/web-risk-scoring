import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler

# ----- Generate synthetic training data -----

np.random.seed(42)

samples = 200

vulnerabilities = np.random.randint(0, 20, samples)
cves = np.random.randint(0, 15, samples)
subdomains = np.random.randint(1, 25, samples)
missing_headers = np.random.randint(0, 6, samples)

X = np.column_stack((vulnerabilities, cves, subdomains, missing_headers))

# Risk labels based on simple scoring logic
scores = vulnerabilities*2 + cves*3 + subdomains + missing_headers*2

y = []

for s in scores:
    if s < 15:
        y.append("Low")
    elif s < 30:
        y.append("Medium")
    elif s < 50:
        y.append("High")
    else:
        y.append("Critical")

# ----- Normalize features -----

scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# ----- Train model -----

model = RandomForestClassifier(n_estimators=100)
model.fit(X_scaled, y)

# ----- Prediction function -----

def predict_risk(vulns, cves, subs, headers_missing):

    features = np.array([[vulns, cves, subs, headers_missing]])
    features_scaled = scaler.transform(features)

    probs = model.predict_proba(features_scaled)[0]
    classes = model.classes_

    result = dict(zip(classes, probs.round(3)))

    predicted = model.predict(features_scaled)[0]

    return {
        "prediction": predicted,
        "probabilities": result
    }

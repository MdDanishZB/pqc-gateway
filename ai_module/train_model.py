import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

import joblib

data = pd.read_csv("dataset.csv")

X = data[[
    "latency",
    "jitter",
    "packet_loss",
    "throughput"
]]

y = data["threat_level"]

encoder = LabelEncoder()

y_encoded = encoder.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.2,
    random_state=42
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)

print(f"Model Accuracy: {accuracy * 100:.2f}%")

joblib.dump(model, "models/rf_model.pkl")
joblib.dump(encoder, "models/label_encoder.pkl")

print("Model Saved Successfully")
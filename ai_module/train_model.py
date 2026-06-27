import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import joblib

# Single source of truth — must match the online inference path (model_server.py)
# and the C gateway feature order. See features.py.
from features import FEATURES

data = pd.read_csv("dataset.csv")

X = data[FEATURES]
y = data["threat_level"]

encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

y_pred = model.predict(X_test)
print("\nClassification Report:")
print(classification_report(y_test, y_pred,
                             target_names=encoder.classes_))

print("\nFeature Importances:")
for feat, imp in sorted(zip(FEATURES, model.feature_importances_),
                         key=lambda x: x[1], reverse=True):
    print(f"  {feat:<20} {imp:.4f}")

joblib.dump(model,   "models/rf_model.pkl")
joblib.dump(encoder, "models/label_encoder.pkl")
print("\nModel saved to models/")

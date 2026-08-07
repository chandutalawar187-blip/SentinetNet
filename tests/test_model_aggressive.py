import joblib
import pandas as pd
import os

MODEL = os.path.join("models", "cic_model.pkl")
ENC = os.path.join("models", "cic_encoder.pkl")

model = joblib.load(MODEL)
encoder = joblib.load(ENC)

X = pd.DataFrame([{
    "Flow Duration": 1.0,
    "Total Fwd Packets": 120,
    "Total Backward Packets": 0,
    "Flow Bytes/s": 1000.0,
    "Flow Packets/s": 120.0
}])

pred = model.predict(X)[0]
try:
    label = encoder.inverse_transform([pred])[0]
except Exception:
    label = str(pred)

print("Predicted:", label)
print("Features:", X.to_dict(orient='records')[0])

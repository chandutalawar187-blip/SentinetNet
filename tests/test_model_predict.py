import joblib
import pandas as pd
import os

MODEL = os.path.join("models", "cic_model.pkl")
ENC = os.path.join("models", "cic_encoder.pkl")

print("Model file:", MODEL)
print("Encoder file:", ENC)

try:
    model = joblib.load(MODEL)
    encoder = joblib.load(ENC)
    print("Loaded model and encoder OK")
except Exception as e:
    print("Failed to load model/encoder:", e)
    raise

# Create two sample rows: benign low-rate and suspicious high-rate
rows = [
    {"Flow Duration": 10.0, "Total Fwd Packets": 2, "Total Backward Packets": 0, "Flow Bytes/s": 100.0, "Flow Packets/s": 0.2},
    {"Flow Duration": 5.0, "Total Fwd Packets": 50, "Total Backward Packets": 0, "Flow Bytes/s": 5000.0, "Flow Packets/s": 10.0}
]

X = pd.DataFrame(rows)
print("Feature columns:", list(X.columns))

try:
    preds = model.predict(X)
    print("Raw predictions:", preds)
    try:
        labels = encoder.inverse_transform(preds)
        print("Decoded labels:", labels)
    except Exception as e:
        print("Encoder inverse_transform failed:", e)
        print("Predictions as-is:", preds)
except Exception as e:
    print("Model prediction failed:", e)
    raise

print("Test complete")

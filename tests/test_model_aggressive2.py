import joblib
import pandas as pd
import os

MODEL = os.path.join("models", "cic_model.pkl")
ENC = os.path.join("models", "cic_encoder.pkl")

model = joblib.load(MODEL)
encoder = joblib.load(ENC)

# Build DataFrame with required columns (use model.feature_names_in_)
cols = list(getattr(model, 'feature_names_in_', []))
if not cols:
    raise SystemExit('Model has no feature_names_in_ attribute')

row = {c: 0.0 for c in cols}
# Set aggressive values for likely indicative features
for k,v in {
    'Flow Duration': 1.0,
    'Total Fwd Packets': 120.0,
    'Flow Bytes/s': 1000.0,
    'Flow Packets/s': 120.0,
    'Fwd Packets/s': 120.0,
    'SYN Flag Count': 120.0
}.items():
    if k in row:
        row[k] = v

X = pd.DataFrame([row], columns=cols)

pred = model.predict(X)[0]
try:
    label = encoder.inverse_transform([pred])[0]
except Exception:
    label = str(pred)

print('Predicted:', label)
print('Used features count:', len(cols))

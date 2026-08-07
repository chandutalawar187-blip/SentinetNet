import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

FILE = "../data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

print("Loading dataset...")

df = pd.read_csv(
    FILE,
    low_memory=False
)

df.columns = (
    df.columns
    .str.strip()
)

print(
    df["Label"]
    .value_counts()
)

# Auto-select numeric features (exclude Label) to give the model more signal
numeric = df.select_dtypes(include=['number']).columns.tolist()
if 'Label' in numeric:
    numeric.remove('Label')
features = numeric
print("Using features:", features)

df = df[
    features + [
        "Label"
    ]
]

df = df.replace(
    [float("inf"),-float("inf")],
    0
)

df = df.dropna()

encoder = LabelEncoder()

df["Label"] = (

    encoder.fit_transform(
        df["Label"]
    )

)

X = df[
    features
]

y = df[
    "Label"
]

X_train,X_test,y_train,y_test=(

    train_test_split(

        X,

        y,

        test_size=0.2,

        random_state=42

    )

)

model = RandomForestClassifier(

    n_estimators=100,

    random_state=42

)

print(
    "Training..."
)

model.fit(

    X_train,

    y_train

)

score = model.score(

    X_test,

    y_test

)

print(
    "Accuracy:",
    score
)

joblib.dump(
    model,
    "../models/cic_model.pkl"
)

joblib.dump(
    encoder,
    "../models/cic_encoder.pkl"
)

print(
    "Saved model"
)
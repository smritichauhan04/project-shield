"""
Project Shield - ML Model Training
Trains Isolation Forest (anomaly) + Random Forest (classifier) 
and saves models to disk.
"""
import numpy as np
import pandas as pd
import joblib
import os
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# ── Severity map ────────────────────────────────────────────────────────────
THREAT_WEIGHT = {"Normal": 0, "Probe": 35, "DoS": 65, "R2L": 80, "U2R": 95}

NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "count", "srv_count", "same_srv_rate", "diff_srv_rate", "dst_host_count"
]

def load_and_preprocess(csv_path="data/security_logs.csv"):
    df = pd.read_csv(csv_path)
    # Encode categorical
    for col in ["protocol_type", "service", "flag"]:
        le = LabelEncoder()
        df[col + "_enc"] = le.fit_transform(df[col].astype(str))

    feature_cols = NUMERIC_FEATURES + ["protocol_type_enc", "service_enc", "flag_enc"]
    X = df[feature_cols].values.astype(float)
    y = df["label"].values

    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y, scaler, feature_cols, df

def train():
    os.makedirs("model", exist_ok=True)
    print("[*] Loading data...")
    X, y, scaler, feature_cols, df = load_and_preprocess()

    # Binary labels for Isolation Forest (1=normal, -1=anomaly)
    y_bin = np.where(y == "Normal", 1, -1)

    # ── Isolation Forest ────────────────────────────────────────────────────
    print("[*] Training Isolation Forest...")
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.35,
        random_state=42,
        n_jobs=-1
    )
    iso.fit(X)
    if_scores = iso.decision_function(X)  # higher = more normal
    print(f"    Isolation Forest trained on {len(X)} samples")

    # ── Random Forest Classifier ────────────────────────────────────────────
    print("[*] Training Random Forest classifier...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    print("\n[✓] Random Forest Results:")
    print(classification_report(y_test, y_pred))

    # ── Save artifacts ───────────────────────────────────────────────────────
    joblib.dump(iso,          "model/isolation_forest.pkl")
    joblib.dump(rf,           "model/random_forest.pkl")
    joblib.dump(scaler,       "model/scaler.pkl")
    joblib.dump(feature_cols, "model/feature_cols.pkl")
    print("\n[✓] Models saved to model/")

if __name__ == "__main__":
    train()

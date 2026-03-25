"""
STEP 1 & 2: Data Collection, Preprocessing & Feature Engineering
Cyber Attacks Prediction & Precautions System
Dataset: NSL-KDD (downloaded automatically)
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.decomposition import PCA
import joblib
import os

# ─────────────────────────────────────────────
# 1. COLUMN DEFINITIONS (NSL-KDD schema)
# ─────────────────────────────────────────────
COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

# Attack type mapping → grouped categories
ATTACK_MAP = {
    "normal": "Normal",
    # DoS attacks
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "mailbomb": "DoS", "apache2": "DoS",
    "processtable": "DoS", "udpstorm": "DoS",
    # Probe attacks
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe", "satan": "Probe",
    "mscan": "Probe", "saint": "Probe",
    # R2L attacks
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L", "multihop": "R2L",
    "phf": "R2L", "spy": "R2L", "warezclient": "R2L", "warezmaster": "R2L",
    "sendmail": "R2L", "named": "R2L", "snmpgetattack": "R2L", "snmpguess": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "worm": "R2L",
    # U2R attacks
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R", "rootkit": "U2R",
    "httptunnel": "U2R", "ps": "U2R", "sqlattack": "U2R", "xterm": "U2R",
}


def download_dataset():
    """Download NSL-KDD dataset if not present."""
    import urllib.request

    os.makedirs("data", exist_ok=True)
    train_url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
    test_url  = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"

    if not os.path.exists("data/KDDTrain+.txt"):
        print("Downloading training data...")
        urllib.request.urlretrieve(train_url, "data/KDDTrain+.txt")
    if not os.path.exists("data/KDDTest+.txt"):
        print("Downloading test data...")
        urllib.request.urlretrieve(test_url, "data/KDDTest+.txt")
    print("Dataset ready.")


def load_data():
    """Load train and test CSVs."""
    train = pd.read_csv("data/KDDTrain+.txt", header=None, names=COLUMNS)
    test  = pd.read_csv("data/KDDTest+.txt",  header=None, names=COLUMNS)
    return train, test


def preprocess(df):
    """
    STEP 2: Clean and encode the dataframe.
    - Drop difficulty column
    - Map labels to attack categories
    - Encode categoricals
    - Remove duplicates / nulls
    """
    df = df.copy()

    # Drop difficulty score (not a feature)
    df.drop(columns=["difficulty"], inplace=True)

    # Map fine-grained labels → attack categories
    df["label"] = df["label"].str.strip().str.lower().map(ATTACK_MAP)
    df.dropna(subset=["label"], inplace=True)   # drop unknown labels
    df.drop_duplicates(inplace=True)
    df.dropna(inplace=True)

    # Encode categorical columns
    cat_cols = ["protocol_type", "service", "flag"]
    encoders = {}
    for col in cat_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le

    return df, encoders


def feature_engineering(train_df, test_df):
    """
    STEP 3: Feature selection, scaling, PCA.
    Returns X_train, X_test, y_train, y_test + scaler + label encoder.
    """
    feature_cols = [c for c in train_df.columns if c != "label"]

    X_train = train_df[feature_cols].values
    y_train = train_df["label"].values
    X_test  = test_df[feature_cols].values
    y_test  = test_df["label"].values

    # Scale features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # Encode target labels
    label_enc = LabelEncoder()
    y_train = label_enc.fit_transform(y_train)
    y_test  = label_enc.transform(y_test)

    # Optional PCA — keep 95% variance
    pca = PCA(n_components=0.95, random_state=42)
    X_train = pca.fit_transform(X_train)
    X_test  = pca.transform(X_test)

    print(f"Features after PCA: {X_train.shape[1]} (from {len(feature_cols)})")
    print(f"Train samples: {X_train.shape[0]} | Test samples: {X_test.shape[0]}")
    print(f"Classes: {list(label_enc.classes_)}")

    return X_train, X_test, y_train, y_test, scaler, pca, label_enc, feature_cols


def save_artifacts(scaler, pca, label_enc, cat_encoders, feature_cols):
    """Save preprocessing artifacts for use during inference."""
    os.makedirs("models", exist_ok=True)
    joblib.dump(scaler,       "models/scaler.pkl")
    joblib.dump(pca,          "models/pca.pkl")
    joblib.dump(label_enc,    "models/label_encoder.pkl")
    joblib.dump(cat_encoders, "models/cat_encoders.pkl")
    joblib.dump(feature_cols, "models/feature_cols.pkl")
    print("Preprocessing artifacts saved to models/")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    download_dataset()

    print("\n[1] Loading data...")
    train_raw, test_raw = load_data()
    print(f"    Train shape: {train_raw.shape} | Test shape: {test_raw.shape}")

    print("\n[2] Preprocessing...")
    train_clean, cat_encoders = preprocess(train_raw)
    test_clean,  _            = preprocess(test_raw)
    # Re-apply same encoders on test set for consistency
    for col, le in cat_encoders.items():
        test_clean[col] = test_clean[col]   # already encoded above

    print(f"    Attack distribution (train):\n{train_clean['label'].value_counts()}\n")

    print("[3] Feature engineering...")
    X_train, X_test, y_train, y_test, scaler, pca, label_enc, feature_cols = \
        feature_engineering(train_clean, test_clean)

    print("\n[4] Saving artifacts...")
    save_artifacts(scaler, pca, label_enc, cat_encoders, feature_cols)

    # Save processed arrays for model training
    np.save("data/X_train.npy", X_train)
    np.save("data/X_test.npy",  X_test)
    np.save("data/y_train.npy", y_train)
    np.save("data/y_test.npy",  y_test)
    print("Processed arrays saved to data/")
    print("\n✅ Step 1 & 2 complete. Run step2_train_models.py next.")

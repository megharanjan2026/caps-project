"""
CAPS Backend — Real ML Model Version
Uses the trained model from step2_train_models.py
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import os

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────
# Load trained ML artifacts
# ─────────────────────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE, "models")

print("Loading ML model and artifacts...")
MODEL        = joblib.load(os.path.join(MODELS_DIR, "best_model.pkl"))
SCALER       = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
PCA          = joblib.load(os.path.join(MODELS_DIR, "pca.pkl"))
LABEL_ENC    = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
CAT_ENC      = joblib.load(os.path.join(MODELS_DIR, "cat_encoders.pkl"))
FEATURE_COLS = joblib.load(os.path.join(MODELS_DIR, "feature_cols.pkl"))
print(f"Model loaded: {type(MODEL).__name__}")
print(f"Classes: {list(LABEL_ENC.classes_)}")

# ─────────────────────────────────────────────
# Attack type mapping from NSL-KDD to frontend
# NSL-KDD uses: DoS, Normal, Probe, R2L, U2R
# Frontend shows: DDoS, Normal, Phishing, Malware, Brute Force
# ─────────────────────────────────────────────
ATTACK_MAP = {
    "Normal": "Normal",
    "DoS":    "DDoS",
    "Probe":  "Phishing",
    "R2L":    "Malware",
    "U2R":    "Brute Force",
}

RISK_MAP = {
    "Normal": "LOW",
    "DoS":    "HIGH",
    "Probe":  "MEDIUM",
    "R2L":    "HIGH",
    "U2R":    "HIGH",
}

# ─────────────────────────────────────────────
# Build feature vector from user input
# Maps simple frontend inputs to full NSL-KDD feature vector
# ─────────────────────────────────────────────
def build_feature_vector(port, traffic, logins, url, proto):
    port    = int(port)
    traffic = int(traffic)
    logins  = int(logins)
    url     = int(url)

    proto_map = {
        "TCP":"tcp","HTTP":"tcp","HTTPS":"tcp",
        "FTP":"tcp","SSH":"tcp","SMTP":"tcp",
        "UDP":"udp","ICMP":"icmp"
    }
    proto_nsl = proto_map.get(proto.upper(), "tcp")

    service_map = {
        80:"http", 443:"http", 21:"ftp", 22:"ssh",
        25:"smtp", 23:"telnet", 53:"domain_u",
        3389:"private", 8080:"http_8001"
    }
    service = service_map.get(port, "private")
    flag    = "SF" if logins == 0 else "REJ"

    features = {
        "duration":                    min(traffic // 100, 58329),
        "protocol_type":               proto_nsl,
        "service":                     service,
        "flag":                        flag,
        "src_bytes":                   min(traffic * 10, 1379963888),
        "dst_bytes":                   min(traffic * 2,  1309937401),
        "land":                        0,
        "wrong_fragment":              0,
        "urgent":                      0,
        "hot":                         min(logins, 101),
        "num_failed_logins":           min(logins, 5),
        "logged_in":                   1 if logins == 0 else 0,
        "num_compromised":             min(logins * 2, 7479),
        "root_shell":                  1 if logins > 20 else 0,
        "su_attempted":                0,
        "num_root":                    min(logins, 7468),
        "num_file_creations":          0,
        "num_shells":                  0,
        "num_access_files":            0,
        "num_outbound_cmds":           0,
        "is_host_login":               0,
        "is_guest_login":              0,
        "count":                       min(traffic // 50, 511),
        "srv_count":                   min(traffic // 100, 511),
        "serror_rate":                 min(logins / 100, 1.0),
        "srv_serror_rate":             min(logins / 100, 1.0),
        "rerror_rate":                 0.0,
        "srv_rerror_rate":             0.0,
        "same_srv_rate":               1.0 if logins == 0 else 0.5,
        "diff_srv_rate":               0.0 if logins == 0 else 0.5,
        "srv_diff_host_rate":          0.0,
        "dst_host_count":              min(traffic // 200, 255),
        "dst_host_srv_count":          min(traffic // 200, 255),
        "dst_host_same_srv_rate":      1.0 if logins == 0 else 0.5,
        "dst_host_diff_srv_rate":      0.0,
        "dst_host_same_src_port_rate": 1.0 if port < 1024 else 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate":        min(logins / 100, 1.0),
        "dst_host_srv_serror_rate":    min(logins / 100, 1.0),
        "dst_host_rerror_rate":        0.0,
        "dst_host_srv_rerror_rate":    0.0,
    }

    row = []
    for col in FEATURE_COLS:
        val = features.get(col, 0)
        if col in CAT_ENC:
            le  = CAT_ENC[col]
            val = str(val)
            val = le.transform([val])[0] if val in le.classes_ else 0
        row.append(float(val))

    return np.array(row).reshape(1, -1)


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON body"}), 400

        port    = int(data.get("port",    80))
        traffic = int(data.get("traffic", 0))
        logins  = int(data.get("logins",  0))
        url     = int(data.get("url",     50))
        proto   = str(data.get("proto",   "TCP"))

        arr = build_feature_vector(port, traffic, logins, url, proto)
        arr = SCALER.transform(arr)
        arr = PCA.transform(arr)

        pred_index  = MODEL.predict(arr)[0]
        proba       = MODEL.predict_proba(arr)[0]
        confidence  = round(float(np.max(proba)) * 100, 1)

        nsl_label   = LABEL_ENC.inverse_transform([pred_index])[0]
        attack_type = ATTACK_MAP.get(nsl_label, "Unknown")
        risk        = RISK_MAP.get(nsl_label, "MEDIUM")
        is_attack   = nsl_label != "Normal"

        return jsonify({
            "isAttack":   is_attack,
            "attackType": attack_type,
            "risk":       risk,
            "confidence": confidence,
            "raw_label":  nsl_label,
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":  "ok",
        "model":   type(MODEL).__name__,
        "classes": list(LABEL_ENC.classes_)
    }), 200


@app.route("/", methods=["GET"])
def index():
    return jsonify({"message": "CAPS Backend running. POST to /predict"}), 200


if __name__ == "__main__":
    print("=" * 50)
    print("  CAPS Backend  →  http://localhost:5000")
    print("  Model: Real trained ML model")
    print("  POST /predict  |  GET /health")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=True)
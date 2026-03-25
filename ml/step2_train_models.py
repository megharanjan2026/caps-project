"""
STEP 4 & 5: ML Model Training & Evaluation
Cyber Attacks Prediction & Precautions System
Trains: Logistic Regression, Decision Tree, Random Forest, SVM
Evaluates: Accuracy, Precision, Recall, F1, ROC-AUC
Auto-selects best model and saves it.
"""

import numpy as np
import joblib
import os
import json
from sklearn.linear_model    import LogisticRegression
from sklearn.tree            import DecisionTreeClassifier
from sklearn.ensemble        import RandomForestClassifier
from sklearn.svm             import SVC
from sklearn.metrics         import (accuracy_score, precision_score,
                                     recall_score, f1_score,
                                     roc_auc_score, classification_report)


# ─────────────────────────────────────────────
# Load preprocessed data
# ─────────────────────────────────────────────
def load_data():
    X_train = np.load("data/X_train.npy")
    X_test  = np.load("data/X_test.npy")
    y_train = np.load("data/y_train.npy")
    y_test  = np.load("data/y_test.npy")
    return X_train, X_test, y_train, y_test


# ─────────────────────────────────────────────
# Model definitions
# ─────────────────────────────────────────────
MODELS = {
    "Logistic Regression": LogisticRegression(
        max_iter=1000, random_state=42, n_jobs=-1
    ),
    "Decision Tree": DecisionTreeClassifier(
        max_depth=20, random_state=42
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators=100, max_depth=20, random_state=42, n_jobs=-1
    ),
    "SVM": SVC(
        kernel="rbf", probability=True, random_state=42
    ),
}


# ─────────────────────────────────────────────
# Evaluation helper
# ─────────────────────────────────────────────
def evaluate(model, X_test, y_test, name):
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    n_classes = len(np.unique(y_test))
    avg = "macro"

    metrics = {
        "accuracy":  round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, average=avg, zero_division=0), 4),
        "recall":    round(recall_score(y_test, y_pred, average=avg, zero_division=0), 4),
        "f1":        round(f1_score(y_test, y_pred, average=avg, zero_division=0), 4),
        "roc_auc":   round(roc_auc_score(y_test, y_proba, multi_class="ovr", average=avg), 4),
    }

    print(f"\n{'='*50}")
    print(f"  {name}")
    print(f"{'='*50}")
    for k, v in metrics.items():
        print(f"  {k:12s}: {v}")
    print(f"\n  Classification Report:\n")
    label_enc = joblib.load("models/label_encoder.pkl")
    print(classification_report(
        y_test, y_pred,
        target_names=label_enc.classes_,
        zero_division=0
    ))

    return metrics


# ─────────────────────────────────────────────
# Train, evaluate, select best, save
# ─────────────────────────────────────────────
def train_and_select(X_train, X_test, y_train, y_test):
    os.makedirs("models", exist_ok=True)
    results = {}

    for name, model in MODELS.items():
        print(f"\n[Training] {name} ...")
        model.fit(X_train, y_train)
        metrics = evaluate(model, X_test, y_test, name)
        results[name] = {"model": model, "metrics": metrics}

        # Save each model
        safe_name = name.lower().replace(" ", "_")
        joblib.dump(model, f"models/{safe_name}.pkl")
        print(f"  Saved → models/{safe_name}.pkl")

    # Select best model by F1 score
    best_name = max(results, key=lambda n: results[n]["metrics"]["f1"])
    best_model = results[best_name]["model"]
    print(f"\n{'*'*50}")
    print(f"  BEST MODEL: {best_name}")
    print(f"  F1 Score  : {results[best_name]['metrics']['f1']}")
    print(f"{'*'*50}")

    joblib.dump(best_model, "models/best_model.pkl")

    # Save metrics summary as JSON
    summary = {name: data["metrics"] for name, data in results.items()}
    summary["best_model"] = best_name
    with open("models/metrics_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print("\nMetrics summary saved → models/metrics_summary.json")

    return best_name, best_model


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("[Loading data...]")
    X_train, X_test, y_train, y_test = load_data()
    print(f"  X_train: {X_train.shape} | X_test: {X_test.shape}")

    best_name, best_model = train_and_select(X_train, X_test, y_train, y_test)

    print("\n✅ Step 4 & 5 complete. Run step3_app.py next.")

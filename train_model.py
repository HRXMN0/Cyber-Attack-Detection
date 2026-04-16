# =============================================================================
# train_model.py — ML Model Training Pipeline
# Trains a Random Forest Classifier on the NSL-KDD dataset.
#
# NSL-KDD Reference:
#   https://www.unb.ca/cic/datasets/nsl.html
#   File used: KDDTrain+.txt  (place in the same directory as this script)
#
# Outputs:
#   attack_model.pkl  — trained RandomForestClassifier
#   encoders.pkl      — dict of LabelEncoders for categorical columns
#   columns.pkl       — list of feature column names used during training
# =============================================================================

import os
import pickle
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# ---------------------------------------------------------------------------
# 1. Column definitions for the NSL-KDD dataset
# ---------------------------------------------------------------------------
COL_NAMES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "attack_type", "difficulty_level",
]

# Categorical feature columns (will be label-encoded)
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

# Target column
TARGET_COL = "attack_type"

# Columns to drop (unused)
DROP_COLS = ["difficulty_level"]

# ---------------------------------------------------------------------------
# 2. Load dataset
# ---------------------------------------------------------------------------

def load_dataset(filepath: str) -> pd.DataFrame:
    """Load the NSL-KDD training file into a DataFrame."""
    if not os.path.exists(filepath):
        print(f"\n[ERROR] Dataset not found at: {filepath}")
        print("Please download KDDTrain+.txt from:")
        print("  https://www.unb.ca/cic/datasets/nsl.html")
        print("and place it in the same directory as train_model.py.\n")
        sys.exit(1)

    print(f"[INFO] Loading dataset from: {filepath}")
    df = pd.read_csv(filepath, header=None, names=COL_NAMES)
    print(f"[INFO] Dataset shape: {df.shape}")
    return df


# ---------------------------------------------------------------------------
# 3. Preprocess
# ---------------------------------------------------------------------------

def preprocess(df: pd.DataFrame):
    """
    Preprocess the NSL-KDD DataFrame:
      - Drop unnecessary columns
      - Label-encode categorical features
      - Return features (X), labels (y), and encoder dict
    """
    # Drop unused columns
    df = df.drop(columns=DROP_COLS, errors="ignore")

    # Normalise attack labels (strip trailing dot that some variants include)
    df[TARGET_COL] = df[TARGET_COL].str.lower().str.strip().str.rstrip(".")

    # Encode categorical feature columns
    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le
        print(f"[INFO] Encoded column '{col}' — {len(le.classes_)} unique values")

    # Separate features and target
    X = df.drop(columns=[TARGET_COL])
    y = df[TARGET_COL]

    print(f"[INFO] Feature matrix shape : {X.shape}")
    print(f"[INFO] Unique attack classes : {sorted(y.unique())}")

    return X, y, encoders


# ---------------------------------------------------------------------------
# 4. Train model
# ---------------------------------------------------------------------------

def train(X_train, y_train) -> RandomForestClassifier:
    """Train a RandomForestClassifier."""
    print("[INFO] Training Random Forest Classifier …")
    model = RandomForestClassifier(
        n_estimators=100,   # number of decision trees
        max_depth=20,       # prevents over-fitting while keeping accuracy
        random_state=42,
        n_jobs=-1,          # use all CPU cores
    )
    model.fit(X_train, y_train)
    print("[INFO] Training complete.")
    return model


# ---------------------------------------------------------------------------
# 5. Evaluate
# ---------------------------------------------------------------------------

def evaluate(model, X_test, y_test):
    """Print accuracy and per-class report."""
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[RESULT] Accuracy: {acc * 100:.2f}%\n")
    print("[RESULT] Classification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))
    return acc


# ---------------------------------------------------------------------------
# 6. Save artefacts
# ---------------------------------------------------------------------------

def save_artifacts(model, encoders, columns, out_dir: str = "."):
    """Persist model, encoders, and column list to disk."""
    model_path    = os.path.join(out_dir, "attack_model.pkl")
    encoders_path = os.path.join(out_dir, "encoders.pkl")
    columns_path  = os.path.join(out_dir, "columns.pkl")

    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    print(f"[SAVED] Model      → {model_path}")

    with open(encoders_path, "wb") as f:
        pickle.dump(encoders, f)
    print(f"[SAVED] Encoders   → {encoders_path}")

    with open(columns_path, "wb") as f:
        pickle.dump(list(columns), f)
    print(f"[SAVED] Columns    → {columns_path}")


# ---------------------------------------------------------------------------
# 7. Main entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    DATASET_FILE = os.path.join(os.path.dirname(__file__), "KDDTrain+.txt")

    # --- Load ---
    df = load_dataset(DATASET_FILE)

    # --- Preprocess ---
    X, y, encoders = preprocess(df)

    # --- Split ---
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[INFO] Train size: {len(X_train)} | Test size: {len(X_test)}")

    # --- Train ---
    model = train(X_train, y_train)

    # --- Evaluate ---
    evaluate(model, X_test, y_test)

    # --- Save ---
    save_artifacts(model, encoders, X.columns, out_dir=os.path.dirname(__file__) or ".")

    print("\n[DONE] All artefacts saved. Run app.py to start the Flask server.\n")
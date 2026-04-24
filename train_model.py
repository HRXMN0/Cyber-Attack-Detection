# =============================================================================
# train_model.py — ML Model Training Pipeline (XGBoost)
# Trains an XGBoost Classifier on the CICIDS2017 dataset.
# =============================================================================

import os
import pickle
import sys
import glob

import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------
DATASET_DIR = os.path.join(os.path.dirname(__file__), "dataset")
TARGET_COL = "label"

# We will sample N rows from each file to prevent MemoryError (e.g. 150k per file)
ROWS_PER_FILE = 150000 

def clean_labels(label: str) -> str:
    """Normalizes noisy dataset labels."""
    label = str(label).strip()
    # Handle strange unicode replacement chars just in case
    label = label.encode('ascii', 'ignore').decode() 
    if "BENIGN" in label or "Normal" in label:
        return "normal"
    elif "Web Attack" in label:
        return "web_attack"
    elif "Patator" in label or "Brute Force" in label:
        return "bruteforce"
    elif "DoS" in label or "DDoS" in label or "Heartbleed" in label:
        return "ddos"
    elif "PortScan" in label:
        return "portscan"
    elif "Bot" in label:
        return "botnet"
    elif "Infiltration" in label:
        return "infiltration"
    else:
        return label.lower()

# ---------------------------------------------------------------------------
# 2. Load and merge datasets
# ---------------------------------------------------------------------------
def load_datasets() -> pd.DataFrame:
    files = glob.glob(os.path.join(DATASET_DIR, "*.csv"))
    if not files:
        print(f"[ERROR] No CSV files found in {DATASET_DIR}")
        sys.exit(1)
        
    dfs = []
    print(f"[INFO] Found {len(files)} CSV files. Loading up to {ROWS_PER_FILE} rows each...")
    for f in files:
        try:
            print(f"       -> Reading {os.path.basename(f)}...")
            df_part = pd.read_csv(f, nrows=ROWS_PER_FILE, low_memory=False)
            
            # Clean column names immediately (strip whitespace)
            df_part.columns = df_part.columns.str.strip().str.lower()
            
            # Rename the target column if it's named 'label' (case insensitive match)
            if 'label' in df_part.columns:
                df_part.rename(columns={'label': TARGET_COL}, inplace=True)
            
            dfs.append(df_part)
        except Exception as e:
            print(f"       -> [WARN] Error reading {f}: {e}")
            
    df = pd.concat(dfs, ignore_index=True)
    print(f"[INFO] Merged dataset shape: {df.shape}")
    return df

# ---------------------------------------------------------------------------
# 3. Preprocess
# ---------------------------------------------------------------------------
def preprocess(df: pd.DataFrame):
    print("[INFO] Preprocessing data...")
    
    # 1. Drop the explicit port/IP columns if present, as they shouldn't purely dictate attacks
    cols_to_drop = [c for c in df.columns if 'ip' in c or 'port' in c]
    df = df.drop(columns=cols_to_drop, errors="ignore")
    
    # 2. Handle Infinity / NaNs
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    
    # 3. Clean Labels
    df[TARGET_COL] = df[TARGET_COL].apply(clean_labels)
    
    # 4. Filter out any garbage labels that are left as empty
    df = df[df[TARGET_COL] != ""]
    
    # 5. Label Encode the Target
    label_encoder = LabelEncoder()
    df[TARGET_COL] = label_encoder.fit_transform(df[TARGET_COL])
    print(f"[INFO] Class mapping: {dict(zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_)))}")
    
    # Ensure all remaining columns are numeric
    X = df.drop(columns=[TARGET_COL])
    y = df[TARGET_COL]
    
    # For any categorical features accidentally left in CICIDS2017, convert to numeric or drop
    for col in X.columns:
        if X[col].dtype == object:
            try:
                X[col] = pd.to_numeric(X[col])
            except:
                X.drop(columns=[col], inplace=True)
                
    encoders = {'target': label_encoder}
    return X, y, encoders

# ---------------------------------------------------------------------------
# 4. Train Model
# ---------------------------------------------------------------------------
def train(X_train, y_train) -> XGBClassifier:
    print("[INFO] Training XGBoost Classifier...")
    model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        n_jobs=-1,
        tree_method="hist",  # faster histogram-based training
    )
    model.fit(X_train, y_train)
    print("[INFO] Training complete.")
    return model

# ---------------------------------------------------------------------------
# 5. Evaluate
# ---------------------------------------------------------------------------
def evaluate(model, X_test, y_test, encoders):
    print("[INFO] Evaluating Model...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[RESULT] Accuracy: {acc * 100:.2f}%\n")
    
    # Map back to strings for the report
    target_le = encoders['target']
    target_names = target_le.classes_
    try:
        print("[RESULT] Classification Report:")
        print(classification_report(y_test, y_pred, target_names=target_names, zero_division=0))
    except Exception as e:
        print(f"[RESULT] Could not print detailed report: {e}")
        
    return acc

# ---------------------------------------------------------------------------
# 6. Save Artifacts
# ---------------------------------------------------------------------------
def save_artifacts(model, encoders, columns, out_dir: str = "."):
    model_path    = os.path.join(out_dir, "attack_model.pkl")
    encoders_path = os.path.join(out_dir, "encoders.pkl")
    columns_path  = os.path.join(out_dir, "columns.pkl")

    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    print(f"[SAVED] Model      -> {model_path}")

    with open(encoders_path, "wb") as f:
        pickle.dump(encoders, f)
    print(f"[SAVED] Encoders   -> {encoders_path}")

    with open(columns_path, "wb") as f:
        pickle.dump(list(columns), f)
    print(f"[SAVED] Columns    -> {columns_path}")

# ---------------------------------------------------------------------------
# 7. Main Pipeline
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    df = load_datasets()
    X, y, encoders = preprocess(df)
    
    print(f"[INFO] Splitting dataset... Features: {X.shape[1]}")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    model = train(X_train, y_train)
    evaluate(model, X_test, y_test, encoders)
    
    save_artifacts(model, encoders, X.columns, out_dir=os.path.dirname(__file__) or ".")
    print("\n[DONE] XGBoost artifacts successfully generated.")
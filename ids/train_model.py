# train_model.py
# Model training step
# Tunes XGBoost with a small grid search on a validation set,
# then retrains the best setting on the full training set and saves it.
# Run from the ~/fyp folder with the venv turned on.

import json
import os
import time

import pandas as pd
import xgboost as xgb
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight

TRAIN_FILE = "data/train.csv"
MODEL_FILE = "models/xgb_ids_model.json"
INFO_FILE = "models/model_info.json"
TUNING_FILE = "results/tuning_results.csv"

RANDOM_SEED = 42
VALIDATION_SIZE = 0.20
LEARNING_RATE = 0.1
MAX_TREES = 1000
EARLY_STOPPING = 50

# Fixed class order, the number is what XGBoost predicts
# (\u2013 is the dash used in the original CICIDS2017 label)
CLASS_NAMES = ["BENIGN", "DoS Hulk", "PortScan", "Web Attack \u2013 Brute Force"]
LABEL_TO_ID = {name: i for i, name in enumerate(CLASS_NAMES)}

# Settings to compare (grid search)
GRID = [
    {"max_depth": 6, "class_weights": "off"},
    {"max_depth": 6, "class_weights": "balanced"},
    {"max_depth": 10, "class_weights": "off"},
    {"max_depth": 10, "class_weights": "balanced"},
]

os.makedirs("models", exist_ok=True)
os.makedirs("results", exist_ok=True)

print("Loading", TRAIN_FILE)
train_df = pd.read_csv(TRAIN_FILE)
FEATURES = [c for c in train_df.columns if c != "Label"]
X = train_df[FEATURES]
y = train_df["Label"].map(LABEL_TO_ID)
if y.isna().any():
    raise ValueError("Found a label that is not one of the four classes")
y = y.astype(int)
print("Training set shape", X.shape)

# Take 20% of the training set as a validation set for tuning
X_fit, X_val, y_fit, y_val = train_test_split(
    X, y, test_size=VALIDATION_SIZE, stratify=y, random_state=RANDOM_SEED
)
print("Fit rows", len(X_fit), " Validation rows", len(X_val))


def make_weights(labels, mode):
    # Balanced weights make rare classes count more during training
    if mode == "balanced":
        return compute_sample_weight("balanced", labels)
    return None


def make_model(max_depth, n_estimators, early_stopping):
    return xgb.XGBClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=LEARNING_RATE,
        tree_method="hist",
        eval_metric="mlogloss",
        early_stopping_rounds=early_stopping,
        n_jobs=-1,
        random_state=RANDOM_SEED,
    )


# Grid search, each setting is trained on the fit rows and scored on validation
results = []
for i, setting in enumerate(GRID, start=1):
    depth = setting["max_depth"]
    weights_mode = setting["class_weights"]
    print()
    print(f"Setting {i} of {len(GRID)}, max_depth {depth}, class weights {weights_mode}")

    fit_w = make_weights(y_fit, weights_mode)
    val_w = make_weights(y_val, weights_mode)

    model = make_model(depth, MAX_TREES, EARLY_STOPPING)
    start = time.perf_counter()
    model.fit(
        X_fit,
        y_fit,
        sample_weight=fit_w,
        eval_set=[(X_val, y_val)],
        sample_weight_eval_set=[val_w] if val_w is not None else None,
        verbose=100,
    )
    train_seconds = time.perf_counter() - start

    # predict uses the best number of trees found by early stopping
    pred = model.predict(X_val)
    per_class = f1_score(y_val, pred, average=None, labels=[0, 1, 2, 3])
    macro = f1_score(y_val, pred, average="macro")
    trees = model.best_iteration + 1

    results.append({
        "max_depth": depth,
        "class_weights": weights_mode,
        "trees": trees,
        "macro_f1": round(float(macro), 5),
        "benign_f1": round(float(per_class[0]), 5),
        "dos_hulk_f1": round(float(per_class[1]), 5),
        "portscan_f1": round(float(per_class[2]), 5),
        "web_attack_f1": round(float(per_class[3]), 5),
        "train_seconds": round(train_seconds, 1),
    })
    print(f"Trees {trees}, validation macro F1 {macro:.5f}, "
          f"Web Attack F1 {per_class[3]:.5f}, time {train_seconds:.0f}s")

results_df = pd.DataFrame(results)
results_df.to_csv(TUNING_FILE, index=False)
print()
print("Grid search results")
print(results_df.to_string(index=False))

# Pick the setting with the highest validation macro F1
best = results_df.loc[results_df["macro_f1"].idxmax()]
best_depth = int(best["max_depth"])
best_weights = str(best["class_weights"])
best_trees = int(best["trees"])
print()
print(f"Best setting, max_depth {best_depth}, class weights {best_weights}, trees {best_trees}")

# Retrain the best setting on the full training set (fit plus validation)
print()
print("Retraining on the full training set", X.shape)
final_model = make_model(best_depth, best_trees, None)
start = time.perf_counter()
final_model.fit(X, y, sample_weight=make_weights(y, best_weights), verbose=False)
final_seconds = time.perf_counter() - start
print(f"Final training time {final_seconds:.0f}s")

final_model.save_model(MODEL_FILE)

# Save the details the prototype and the report will need
info = {
    "model_file": MODEL_FILE,
    "features": FEATURES,
    "class_names": CLASS_NAMES,
    "label_to_id": LABEL_TO_ID,
    "params": {
        "max_depth": best_depth,
        "class_weights": best_weights,
        "n_estimators": best_trees,
        "learning_rate": LEARNING_RATE,
        "tree_method": "hist",
    },
    "validation_macro_f1": float(best["macro_f1"]),
    "training_rows": int(len(X)),
    "final_training_seconds": round(final_seconds, 1),
    "xgboost_version": xgb.__version__,
}
with open(INFO_FILE, "w", encoding="utf-8") as f:
    json.dump(info, f, indent=2, ensure_ascii=False)

print()
print("Saved", MODEL_FILE)
print("Saved", INFO_FILE)
print("Saved", TUNING_FILE)

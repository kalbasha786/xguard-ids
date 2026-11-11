# evaluate_model.py
# Evaluation step
# Tests the final model on the whole test set and reports the confusion matrix,
# accuracy, per class and macro precision, recall and F1, and prediction time.
# Also tests the archived model (before the payload rule) on its own test set,
# so the report can show a before and after comparison.
# Run from the ~/fyp folder with the venv turned on.

import json
import os
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, precision_recall_fscore_support)

RANDOM_SEED = 42
ONE_BY_ONE_SAMPLE = 1000
RESULTS_DIR = "results"
SHORT_NAMES = ["BENIGN", "DoS Hulk", "PortScan", "Web Attack"]
LABELS = [0, 1, 2, 3]

FINAL_RUN = {
    "title": "after payload rule",
    "model": "models/xgb_ids_model.json",
    "info": "models/model_info.json",
    "test": "data/test.csv",
    "suffix": "",
}
BEFORE_RUN = {
    "title": "before payload rule",
    "model": "archive/original_labels/models/xgb_ids_model.json",
    "info": "archive/original_labels/models/model_info.json",
    "test": "archive/original_labels/test.csv",
    "suffix": "_before",
}


def save_confusion_matrix_image(cm, path, title):
    # Colour shows the percentage of each actual class, text shows the count
    row_pct = cm / cm.sum(axis=1, keepdims=True) * 100
    fig, ax = plt.subplots(figsize=(7.5, 6.5))
    image = ax.imshow(row_pct, cmap="Blues", vmin=0, vmax=100)
    ax.set_xticks(range(len(SHORT_NAMES)))
    ax.set_xticklabels(SHORT_NAMES, rotation=30, ha="right")
    ax.set_yticks(range(len(SHORT_NAMES)))
    ax.set_yticklabels(SHORT_NAMES)
    ax.set_xlabel("Predicted class")
    ax.set_ylabel("Actual class")
    ax.set_title(title)
    for i in range(len(SHORT_NAMES)):
        for j in range(len(SHORT_NAMES)):
            pct = row_pct[i, j]
            pct_text = "<0.01%" if 0 < pct < 0.01 else f"{pct:.2f}%"
            colour = "white" if pct > 50 else "black"
            ax.text(j, i, f"{cm[i, j]:,}\n({pct_text})",
                    ha="center", va="center", color=colour, fontsize=9)
    fig.colorbar(image, ax=ax, label="Percentage of the actual class")
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def evaluate(run, time_one_by_one):
    print()
    print("=" * 70)
    print("Testing the model", run["title"])
    print("=" * 70)

    with open(run["info"], encoding="utf-8") as f:
        info = json.load(f)
    features = info["features"]
    label_to_id = {name: i for i, name in enumerate(info["class_names"])}

    model = xgb.XGBClassifier()
    model.load_model(run["model"])

    test_df = pd.read_csv(run["test"])
    X_test = test_df[features]
    y_test = test_df["Label"].map(label_to_id)
    if y_test.isna().any():
        raise ValueError("Found a label that is not one of the four classes")
    y_test = y_test.astype(int).to_numpy()
    print("Test set shape", X_test.shape)

    # Warm up once so the timing below is fair
    model.predict(X_test.iloc[:100])

    # Batch prediction over the whole test set (the main evaluation)
    start = time.perf_counter()
    y_pred = model.predict(X_test)
    total_seconds = time.perf_counter() - start
    avg_microseconds = total_seconds / len(X_test) * 1_000_000

    accuracy = accuracy_score(y_test, y_pred)
    p, r, f1, support = precision_recall_fscore_support(
        y_test, y_pred, labels=LABELS, zero_division=0)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(
        y_test, y_pred, labels=LABELS, average="macro", zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=LABELS)
    report = classification_report(y_test, y_pred, labels=LABELS,
                                   target_names=SHORT_NAMES, digits=4, zero_division=0)

    print()
    print(report)
    print(f"Accuracy {accuracy:.5f}")
    print(f"Macro precision {macro_p:.5f}, macro recall {macro_r:.5f}, macro F1 {macro_f1:.5f}")

    cm_df = pd.DataFrame(cm, index=SHORT_NAMES, columns=SHORT_NAMES)
    cm_df.index.name = "Actual (rows) vs Predicted (columns)"
    print()
    print("Confusion matrix")
    with pd.option_context("display.width", 200):
        print(cm_df)

    print()
    print(f"Batch prediction, {total_seconds:.3f} s for {len(X_test):,} records, "
          f"average {avg_microseconds:.3f} microseconds per record")

    metrics = {
        "model": run["title"],
        "test_records": int(len(X_test)),
        "accuracy": float(accuracy),
        "macro_precision": float(macro_p),
        "macro_recall": float(macro_r),
        "macro_f1": float(macro_f1),
        "per_class": {
            SHORT_NAMES[i]: {
                "precision": float(p[i]),
                "recall": float(r[i]),
                "f1": float(f1[i]),
                "support": int(support[i]),
            } for i in LABELS
        },
        "batch_total_seconds": float(total_seconds),
        "batch_avg_microseconds_per_record": float(avg_microseconds),
    }

    # One by one prediction, closer to how the prototype feeds records
    if time_one_by_one:
        sample = X_test.sample(n=ONE_BY_ONE_SAMPLE, random_state=RANDOM_SEED)
        times = []
        for i in range(len(sample)):
            row = sample.iloc[[i]]
            t0 = time.perf_counter()
            model.predict(row)
            times.append(time.perf_counter() - t0)
        times_ms = np.array(times) * 1000
        print(f"One by one prediction ({ONE_BY_ONE_SAMPLE} records), "
              f"mean {times_ms.mean():.3f} ms, median {np.median(times_ms):.3f} ms, "
              f"slowest {times_ms.max():.3f} ms")
        metrics["one_by_one_records"] = ONE_BY_ONE_SAMPLE
        metrics["one_by_one_mean_ms"] = float(times_ms.mean())
        metrics["one_by_one_median_ms"] = float(np.median(times_ms))
        metrics["one_by_one_max_ms"] = float(times_ms.max())

    # Save everything for the report
    suffix = run["suffix"]
    with open(f"{RESULTS_DIR}/test_metrics{suffix}.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    with open(f"{RESULTS_DIR}/classification_report{suffix}.txt", "w", encoding="utf-8") as f:
        f.write(report)
    cm_df.to_csv(f"{RESULTS_DIR}/confusion_matrix{suffix}.csv")
    save_confusion_matrix_image(
        cm, f"{RESULTS_DIR}/confusion_matrix{suffix}.png",
        f"XGBoost confusion matrix on the test set\n({run['title']})")
    print("Saved results with suffix", repr(suffix) if suffix else "(none)")

    return metrics


os.makedirs(RESULTS_DIR, exist_ok=True)

after = evaluate(FINAL_RUN, time_one_by_one=True)

if all(os.path.exists(BEFORE_RUN[k]) for k in ("model", "info", "test")):
    before = evaluate(BEFORE_RUN, time_one_by_one=False)

    def row(m):
        web = m["per_class"]["Web Attack"]
        return {
            "BENIGN F1": m["per_class"]["BENIGN"]["f1"],
            "DoS Hulk F1": m["per_class"]["DoS Hulk"]["f1"],
            "PortScan F1": m["per_class"]["PortScan"]["f1"],
            "Web Attack precision": web["precision"],
            "Web Attack recall": web["recall"],
            "Web Attack F1": web["f1"],
            "Macro precision": m["macro_precision"],
            "Macro recall": m["macro_recall"],
            "Macro F1": m["macro_f1"],
            "Accuracy": m["accuracy"],
            "Web Attack test records": web["support"],
        }

    comparison = pd.DataFrame({"Before rule": row(before), "After rule": row(after)})
    comparison.to_csv(f"{RESULTS_DIR}/before_after_comparison.csv")
    print()
    print("=" * 70)
    print("Before and after comparison on the test set")
    print("=" * 70)
    display = comparison.copy().astype(object)
    for name in display.index:
        for col in display.columns:
            value = comparison.loc[name, col]
            display.loc[name, col] = f"{int(value)}" if name == "Web Attack test records" else f"{value:.5f}"
    print(display)
else:
    print()
    print("Archived model not found, skipping the before and after comparison")

print()
print("All results saved in the", RESULTS_DIR, "folder")

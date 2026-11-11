# make_demo_records.py
# Prototype step, prepares the demo records
# Picks random records from test.csv that the model classified correctly
# (fixed seed, so the same records are picked every run), adds a demo
# source IP to each one, and saves one file per scenario in the demo folder.
# Run from the ~/fyp folder with the venv turned on.

import json
import os

import numpy as np
import pandas as pd
import xgboost as xgb

MODEL_FILE = "models/xgb_ids_model.json"
INFO_FILE = "models/model_info.json"
TEST_FILE = "data/test.csv"
DEMO_DIR = "demo"
RANDOM_SEED = 42

# One file per scenario, class numbers are 0 BENIGN, 1 DoS Hulk, 2 PortScan, 3 Web Attack
SCENARIOS = [
    ("demo_main_1.csv", "Main 1", 0, "192.168.56.1"),
    ("demo_main_2.csv", "Main 2", 1, "192.168.56.1"),
    ("demo_extra_1.csv", "Extra 1", 2, "192.168.56.150"),
    ("demo_extra_2.csv", "Extra 2", 3, "192.168.56.151"),
    ("demo_extra_3.csv", "Extra 3", 1, "192.168.56.150"),
    ("demo_extra_4.csv", "Extra 4", 2, "10.0.2.2"),
    ("demo_extra_5.csv", "Extra 5", 0, "192.168.56.152"),
]

with open(INFO_FILE, encoding="utf-8") as f:
    info = json.load(f)
features = info["features"]
class_names = info["class_names"]
label_to_id = {name: i for i, name in enumerate(class_names)}

model = xgb.XGBClassifier()
model.load_model(MODEL_FILE)

print("Loading", TEST_FILE)
test_df = pd.read_csv(TEST_FILE)
actual = test_df["Label"].map(label_to_id).to_numpy()
predicted = model.predict(test_df[features])
correct = predicted == actual
print("Test records", len(test_df), " correctly classified", int(correct.sum()))

rng = np.random.default_rng(RANDOM_SEED)
used_rows = set()
summary = []
os.makedirs(DEMO_DIR, exist_ok=True)

for file_name, scenario, class_id, ip in SCENARIOS:
    # Correctly classified records of this class, not already used
    candidates = np.flatnonzero((actual == class_id) & correct)
    candidates = [r for r in candidates if r not in used_rows]
    row = int(rng.choice(candidates))
    used_rows.add(row)

    demo_df = test_df.loc[[row], features].reset_index(drop=True)
    demo_df.insert(0, "Label", class_names[class_id])
    demo_df.insert(0, "demo_source_ip", ip)
    demo_df.insert(0, "test_row", row)
    demo_df.insert(0, "scenario", scenario)
    demo_df.to_csv(os.path.join(DEMO_DIR, file_name), index=False)

    summary.append({
        "file": file_name,
        "scenario": scenario,
        "test_row": row,
        "demo_source_ip": ip,
        "Label": class_names[class_id],
        "Predicted": class_names[predicted[row]],
    })

print()
print("Saved", len(summary), "demo files in the", DEMO_DIR, "folder")
print(pd.DataFrame(summary).to_string(index=False))
print()
print("test_row is the record's position in test.csv, where 0 is the first record")
print("The Label column is only shown in the log, the controller decides from the 12 features")

# clean_data.py
# Data preparation, cleaning step
# Step 1, removes rows with infinite or negative values
# Step 2, removes exact duplicate rows
# Step 3, payload rule, relabels DoS Hulk and Web Attack rows that carry
#         no forward payload as BENIGN (Engelen, Rimmer and Joosen, 2021)
# Step 4, removes any new duplicates created by the relabelling
# Run from the ~/fyp folder with the venv turned on.

import numpy as np
import pandas as pd

INPUT_FILE = "data/filtered_cicids2017.csv"
OUTPUT_FILE = "data/cleaned_cicids2017.csv"

# Classes the payload rule applies to. PortScan is excluded because
# a port scan normally sends no data. (\u2013 is the dash in the original label)
WEB_ATTACK = "Web Attack \u2013 Brute Force"
PAYLOAD_RULE_CLASSES = ["DoS Hulk", WEB_ATTACK]

print("Loading", INPUT_FILE)
df = pd.read_csv(INPUT_FILE)
original_counts = df["Label"].value_counts()
print("Original shape", df.shape)

# Step 1, rows with infinite values (Flow Duration of 0) or negative values
features = df.drop(columns="Label")
inf_rows = np.isinf(features).any(axis=1)
neg_rows = (features < 0).any(axis=1)
bad_rows = inf_rows | neg_rows
print()
print("Step 1, broken rows")
print("Rows with infinite values", inf_rows.sum())
print("Rows with negative values", neg_rows.sum())
print("Broken rows removed", bad_rows.sum())
df = df[~bad_rows]

# Step 2, exact duplicate rows, keep the first copy only
dup_rows = df.duplicated()
print()
print("Step 2, duplicate rows")
print("Duplicate rows removed", dup_rows.sum())
df = df[~dup_rows]

# Step 3, payload rule
no_payload = df["Label"].isin(PAYLOAD_RULE_CLASSES) & (df["Total Length of Fwd Packets"] == 0)
print()
print("Step 3, payload rule (attack rows with no forward payload become BENIGN)")
print(df.loc[no_payload, "Label"].value_counts().to_string())
print("Rows relabelled", no_payload.sum())
df.loc[no_payload, "Label"] = "BENIGN"

# Step 4, the relabelled rows can now match existing BENIGN rows exactly
dup_rows = df.duplicated()
print()
print("Step 4, new duplicates after relabelling")
print("Duplicate rows removed", dup_rows.sum())
df = df[~dup_rows].reset_index(drop=True)

# Final check that the cleaned data has no problems left
features = df.drop(columns="Label")
print()
print("Remaining missing values", df.isna().sum().sum())
print("Remaining infinite values", np.isinf(features).sum().sum())
print("Remaining negative values", (features < 0).sum().sum())
print("Cleaned shape", df.shape)

# Class counts before and after cleaning
summary = pd.DataFrame({"Before": original_counts, "After": df["Label"].value_counts()})
summary.loc["Total"] = summary.sum()
print()
print(summary)

df.to_csv(OUTPUT_FILE, index=False)
print()
print("Saved", OUTPUT_FILE)

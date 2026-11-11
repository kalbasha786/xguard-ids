# clean_data.py
# Data preparation, cleaning step
# Removes rows with infinite or negative values, then removes exact duplicate rows.
# Run from the ~/fyp folder with the venv turned on.

import numpy as np
import pandas as pd

INPUT_FILE = "data/filtered_cicids2017.csv"
OUTPUT_FILE = "data/cleaned_cicids2017.csv"

print("Loading", INPUT_FILE)
df = pd.read_csv(INPUT_FILE)
before_counts = df["Label"].value_counts()
print("Original shape", df.shape)

features = df.drop(columns="Label")

# Rows with infinite values (caused by a Flow Duration of 0)
inf_rows = np.isinf(features).any(axis=1)
# Rows with negative values (impossible for real traffic)
neg_rows = (features < 0).any(axis=1)
bad_rows = inf_rows | neg_rows

print()
print("Rows with infinite values", inf_rows.sum())
print("Rows with negative values", neg_rows.sum())
print("Broken rows removed", bad_rows.sum())
df = df[~bad_rows]

# Exact duplicate rows, keep the first copy only
dup_rows = df.duplicated()
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
summary = pd.DataFrame({"Before": before_counts, "After": df["Label"].value_counts()})
summary.loc["Total"] = summary.sum()
print()
print(summary)

df.to_csv(OUTPUT_FILE, index=False)
print()
print("Saved", OUTPUT_FILE)

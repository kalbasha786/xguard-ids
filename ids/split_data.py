# split_data.py
# Data preparation, splitting step
# Splits the cleaned data into a 70% training set and a 30% test set.
# The split is stratified so both sets keep the same class percentages,
# and uses a fixed random seed so the same split is produced every run.
# Run from the ~/fyp folder with the venv turned on.

import pandas as pd
from sklearn.model_selection import train_test_split

INPUT_FILE = "data/cleaned_cicids2017.csv"
TRAIN_FILE = "data/train.csv"
TEST_FILE = "data/test.csv"
TEST_SIZE = 0.30
RANDOM_SEED = 42

print("Loading", INPUT_FILE)
df = pd.read_csv(INPUT_FILE)
print("Cleaned shape", df.shape)

train_df, test_df = train_test_split(
    df,
    test_size=TEST_SIZE,
    stratify=df["Label"],
    random_state=RANDOM_SEED,
)

print()
print("Training set shape", train_df.shape)
print("Test set shape", test_df.shape)

# Class counts and percentages in each set
train_counts = train_df["Label"].value_counts()
test_counts = test_df["Label"].value_counts()
summary = pd.DataFrame({
    "Train": train_counts,
    "Train %": (train_counts / len(train_df) * 100).round(3),
    "Test": test_counts,
    "Test %": (test_counts / len(test_df) * 100).round(3),
})
print()
print(summary)

# Leakage check, no identical row should appear in both sets
train_hash = pd.util.hash_pandas_object(train_df, index=False)
test_hash = pd.util.hash_pandas_object(test_df, index=False)
overlap = test_hash.isin(train_hash.values).sum()
print()
print("Identical rows found in both sets", overlap)

train_df.to_csv(TRAIN_FILE, index=False)
test_df.to_csv(TEST_FILE, index=False)
print()
print("Saved", TRAIN_FILE)
print("Saved", TEST_FILE)

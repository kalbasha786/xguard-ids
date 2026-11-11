# ids_controller.py
# Main prototype script, the IDS controller.
# Reads demo records one by one, predicts each one with the trained XGBoost
# model, then responds.
#   BENIGN   a local message only
#   Attack   the source IP is blocked with iptables (unless it is on the
#            never-block list or already blocked), then a Telegram alert is sent
# Every decision is written to logs/ids_events.csv.
#
# Run from the ~/fyp folder with sudo, using the venv's Python, for example
#   sudo venv/bin/python ids_controller.py demo/demo_main_1.csv

import csv
import json
import os
import sys
import time

import pandas as pd
import xgboost as xgb

import ids_firewall as fw
from telegram_alert import send_telegram

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(BASE_DIR, "models", "xgb_ids_model.json")
INFO_FILE = os.path.join(BASE_DIR, "models", "model_info.json")
EVENT_LOG = os.path.join(fw.LOG_DIR, "ids_events.csv")
EVENT_FIELDS = ["timestamp", "demo_file", "scenario", "test_row", "source_ip",
                "actual_label", "predicted_label", "confidence", "prediction_ms",
                "action", "telegram"]

# Names used on screen and in alerts, in the model's class order
DISPLAY_NAMES = ["BENIGN", "DoS Hulk", "PortScan", "Web Attack (Brute Force)"]
LINE = "-" * 64


def log_event(event):
    fw.make_log_dir()
    new_file = not os.path.exists(EVENT_LOG)
    with open(EVENT_LOG, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EVENT_FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerow(event)
    fw.give_to_user(EVENT_LOG)


def build_alert(attack, confidence, ip, action_text, demo_file, test_row):
    return (
        "\U0001F6A8 FYP IDS ALERT\n\n"
        f"Attack type  {attack}\n"
        f"Confidence  {confidence:.2%}\n"
        f"Source IP  {ip}\n"
        f"Action taken  {action_text}\n"
        f"Time  {fw.now_text()}\n"
        f"Record  {demo_file}, test row {test_row}"
    )


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage  sudo venv/bin/python ids_controller.py demo/demo_main_1.csv")
    demo_path = sys.argv[1]
    demo_file = os.path.basename(demo_path)

    fw.check_ready()

    with open(INFO_FILE, encoding="utf-8") as f:
        info = json.load(f)
    features = info["features"]
    class_names = info["class_names"]
    model = xgb.XGBClassifier()
    model.load_model(MODEL_FILE)

    fw.ensure_chain()
    restored = fw.restore_blocks()
    never_block = fw.load_never_block()

    demo_df = pd.read_csv(demo_path)
    missing = [c for c in features + ["demo_source_ip"] if c not in demo_df.columns]
    if missing:
        raise SystemExit(f"The demo file is missing these columns {missing}")

    print(LINE)
    print("FYP IDS controller started", fw.now_text())
    print("Demo file", demo_path, " records", len(demo_df))
    print("Never-block list", len(never_block), "IPs")
    if restored:
        print("Restored", restored, "earlier blocks from the blocklist file")

    for i in range(len(demo_df)):
        row = demo_df.iloc[i]
        ip = str(row["demo_source_ip"]).strip()
        scenario = row.get("scenario", "")
        test_row = row.get("test_row", "")
        actual = str(row.get("Label", ""))
        if actual in class_names:
            actual = DISPLAY_NAMES[class_names.index(actual)]

        print(LINE)
        print(f"Record {i + 1} of {len(demo_df)}   scenario {scenario}   test row {test_row}")
        print(f"Source IP        {ip}")

        if not fw.is_valid_ip(ip):
            print("Skipped, this is not a valid IP address")
            continue

        # Prediction, timed on its own like in the evaluation
        start = time.perf_counter()
        probabilities = model.predict_proba(demo_df.iloc[[i]][features])[0]
        prediction_ms = (time.perf_counter() - start) * 1000
        predicted_id = int(probabilities.argmax())
        confidence = float(probabilities[predicted_id])
        predicted = DISPLAY_NAMES[predicted_id]

        match = "correct" if predicted == actual else "does not match"
        print(f"Actual label     {actual}")
        print(f"Predicted        {predicted}   confidence {confidence:.2%}   "
              f"{prediction_ms:.2f} ms   ({match})")

        if predicted_id == 0:
            action = "NO_ACTION"
            telegram = "not needed"
            print("Result           BENIGN, no threat detected, no action taken")
        else:
            print("Result           ATTACK DETECTED")
            if ip in never_block:
                action = "NOT_BLOCKED_NEVER_BLOCK_LIST"
                action_text = "NOT blocked, this IP is on the never-block list. Please review manually."
                print(f"Action           {ip} is on the never-block list, so it was not blocked")
            elif fw.is_blocked(ip):
                action = "ALREADY_BLOCKED"
                action_text = "IP was already blocked, no new rule added."
                print(f"Action           {ip} is already blocked, no new rule added")
            else:
                # Block first, then alert, so protection is not delayed by the network
                fw.block_ip(ip)
                fw.add_to_blocklist(ip, predicted, demo_file, test_row)
                action = "BLOCKED"
                action_text = "IP blocked with iptables. It stays blocked until staff review and unblock it."
                print(f"Action           {ip} blocked with iptables")

            sent = send_telegram(build_alert(predicted, confidence, ip, action_text,
                                             demo_file, test_row))
            telegram = "sent" if sent else "failed"
            print("Telegram         alert sent" if sent else "Telegram         alert FAILED")

        log_event({
            "timestamp": fw.now_text(),
            "demo_file": demo_file,
            "scenario": scenario,
            "test_row": test_row,
            "source_ip": ip,
            "actual_label": actual,
            "predicted_label": predicted,
            "confidence": round(confidence, 6),
            "prediction_ms": round(prediction_ms, 3),
            "action": action,
            "telegram": telegram,
        })

    print(LINE)
    blocks = fw.list_iptables_blocks()
    print("IPs currently blocked by the IDS", ", ".join(blocks) if blocks else "none")
    print("Events logged in", EVENT_LOG)
    print(LINE)


if __name__ == "__main__":
    main()

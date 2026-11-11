# reset_demo.py
# Demo helper, prepares a clean run.
# Removes every IP blocked by the IDS, then moves the current log files
# into archive/logs_<date_time> so the next run starts with empty logs.
# The settings in the config folder are not touched.
#
# Run from the ~/fyp folder with sudo, for example
#   sudo venv/bin/python reset_demo.py
#   sudo venv/bin/python reset_demo.py --yes    (skips the confirmation)

import os
import shutil
import sys
from datetime import datetime

import ids_firewall as fw
from telegram_alert import send_telegram

LOG_FILES = ["ids_events.csv", "blocklist.csv", "staff_actions.csv"]
LINE = "-" * 64


def main():
    if os.geteuid() != 0:
        raise SystemExit("Please run with sudo, for example\n"
                         "  sudo venv/bin/python reset_demo.py")
    fw.check_ready()

    blocked = fw.list_iptables_blocks()
    existing_logs = [f for f in LOG_FILES if os.path.exists(os.path.join(fw.LOG_DIR, f))]

    print(LINE)
    print("Demo reset")
    print("IPs currently blocked by the IDS", ", ".join(blocked) if blocked else "none")
    print("Log files to archive", ", ".join(existing_logs) if existing_logs else "none")
    print(LINE)

    if "--yes" not in sys.argv:
        answer = input("Remove all IDS blocks and archive the logs? Type y to confirm > ")
        if answer.strip().lower() != "y":
            print("Cancelled, nothing was changed")
            return

    # Empty the IDS chain, the chain itself stays in place
    if fw.run_iptables(["-L", fw.CHAIN, "-n"]).returncode == 0:
        fw.run_iptables(["-F", fw.CHAIN])
    print("Removed", len(blocked), "IDS blocks")

    # Move the old logs into a dated archive folder
    if existing_logs:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_dir = os.path.join(fw.BASE_DIR, "archive", f"logs_{stamp}")
        os.makedirs(archive_dir, exist_ok=True)
        fw.give_to_user(os.path.dirname(archive_dir))
        fw.give_to_user(archive_dir)
        for name in existing_logs:
            shutil.move(os.path.join(fw.LOG_DIR, name), os.path.join(archive_dir, name))
        print("Old logs moved to", archive_dir)

    remaining = fw.list_iptables_blocks()
    print("IPs currently blocked by the IDS", ", ".join(remaining) if remaining else "none")
    print(LINE)

    # A marker in the Telegram chat, so the clean run is easy to find
    sent = send_telegram("\U0001F504 FYP IDS DEMO RESET\n\n"
                         "All IDS blocks removed and old logs archived.\n"
                         f"Clean run starting  {fw.now_text()}")
    print("Telegram reset marker sent" if sent else "Telegram reset marker FAILED")


if __name__ == "__main__":
    main()

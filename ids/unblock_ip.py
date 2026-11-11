# unblock_ip.py
# Staff tool, lists the IPs blocked by the IDS and unblocks one after review.
# Blocks never expire on their own, so this is the only way an IP gets unblocked.
# Every unblock is recorded in logs/staff_actions.csv and reported on Telegram.
#
# Run from the ~/fyp folder with sudo, for example
#   sudo venv/bin/python unblock_ip.py --list
#   sudo venv/bin/python unblock_ip.py 192.168.56.1

import csv
import ipaddress
import os
import sys

import ids_firewall as fw
from telegram_alert import send_telegram

STAFF_LOG = os.path.join(fw.LOG_DIR, "staff_actions.csv")
STAFF_FIELDS = ["timestamp", "ip", "action", "staff", "note", "blocked_at", "attack"]
LINE = "-" * 64
USAGE = ("Usage\n"
         "  sudo venv/bin/python unblock_ip.py --list          show blocked IPs\n"
         "  sudo venv/bin/python unblock_ip.py 192.168.56.1    unblock one IP")


def show_blocks():
    records = {r["ip"]: r for r in fw.read_blocklist()}
    live = fw.list_iptables_blocks()
    ips = sorted(set(records) | set(live), key=lambda x: ipaddress.ip_address(x))
    print(LINE)
    print("IPs blocked by the IDS")
    if not ips:
        print("None, no IPs are currently blocked")
    else:
        print(f"{'IP':<18}{'Blocked at':<22}{'Attack':<28}In iptables")
        for ip in ips:
            r = records.get(ip, {})
            print(f"{ip:<18}{r.get('blocked_at', 'unknown'):<22}"
                  f"{r.get('attack', 'unknown'):<28}{'yes' if ip in live else 'no'}")
    print(LINE)


def log_staff_action(row):
    fw.make_log_dir()
    new_file = not os.path.exists(STAFF_LOG)
    with open(STAFF_LOG, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=STAFF_FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerow(row)
    fw.give_to_user(STAFF_LOG)


def unblock(ip):
    records = {r["ip"]: r for r in fw.read_blocklist()}
    if ip not in records and not fw.is_blocked(ip):
        print(ip, "is not blocked by the IDS, nothing to do")
        return
    record = records.get(ip, {})
    blocked_at = record.get("blocked_at", "unknown")
    attack = record.get("attack", "unknown")

    print(LINE)
    print("IP to unblock    ", ip)
    print("Blocked at       ", blocked_at)
    print("Attack           ", attack)
    print(LINE)
    staff = input("Staff name > ").strip() or "unknown"
    note = input("Review note > ").strip() or "none"
    answer = input(f"Unblock {ip}? Type y to confirm > ").strip().lower()
    if answer != "y":
        print("Cancelled, the IP stays blocked")
        return

    removed = fw.unblock_ip(ip)
    fw.remove_from_blocklist(ip)
    log_staff_action({
        "timestamp": fw.now_text(),
        "ip": ip,
        "action": "UNBLOCKED",
        "staff": staff,
        "note": note,
        "blocked_at": blocked_at,
        "attack": attack,
    })
    print(f"{ip} unblocked, {removed} iptables rule removed, blocklist updated")

    message = (
        "\u2705 FYP IDS UNBLOCK\n\n"
        f"IP  {ip}\n"
        f"Unblocked by  {staff}\n"
        f"Review note  {note}\n"
        f"Originally blocked  {blocked_at} for {attack}\n"
        f"Time  {fw.now_text()}"
    )
    print("Telegram notice sent" if send_telegram(message) else "Telegram notice FAILED")


def main():
    if os.geteuid() != 0:
        raise SystemExit("Please run with sudo, for example\n"
                         "  sudo venv/bin/python unblock_ip.py --list")
    fw.check_ready()

    args = sys.argv[1:]
    if len(args) != 1 or args[0] in ("-h", "--help"):
        raise SystemExit(USAGE)
    if args[0] == "--list":
        show_blocks()
        return

    ip = args[0].strip()
    if not fw.is_valid_ip(ip):
        raise SystemExit(f"{ip} is not a valid IP address")
    unblock(ip)
    show_blocks()


if __name__ == "__main__":
    main()

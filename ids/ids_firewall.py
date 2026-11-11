# ids_firewall.py
# Response module, blocks and unblocks IP addresses with iptables.
# All IDS blocks live in their own iptables chain called FYP_IDS_BLOCK,
# so they are easy to list and never mixed up with other firewall rules.
# Blocked IPs are also recorded in logs/blocklist.csv, so a block stays
# in place until staff remove it, even after Kali restarts.
# Needs root, so the scripts that use it are run with sudo.

import csv
import ipaddress
import os
import shutil
import subprocess
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHAIN = "FYP_IDS_BLOCK"
LOG_DIR = os.path.join(BASE_DIR, "logs")
NEVER_BLOCK_FILE = os.path.join(BASE_DIR, "config", "never_block_list.txt")
BLOCKLIST_FILE = os.path.join(LOG_DIR, "blocklist.csv")
BLOCKLIST_FIELDS = ["ip", "blocked_at", "attack", "demo_file", "test_row"]

# Written to the never-block file the first time, staff can edit it later
DEFAULT_NEVER_BLOCK = [
    ("127.0.0.1", "Kali itself"),
    ("10.0.2.15", "Kali NAT address, eth0"),
    ("192.168.56.101", "Kali host-only address, eth1"),
    ("10.0.2.2", "VirtualBox NAT gateway, Kali's route to the internet and Telegram"),
    ("10.0.2.3", "VirtualBox NAT DNS server"),
]


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def give_to_user(path):
    # Files made under sudo belong to root, this hands them back to the normal user
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        try:
            os.chown(path, int(uid), int(gid))
        except OSError:
            pass


def make_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)
    give_to_user(LOG_DIR)


def is_valid_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def check_ready():
    if os.geteuid() != 0:
        raise SystemExit("Please run with sudo, iptables needs root, for example\n"
                         "  sudo venv/bin/python ids_controller.py demo/demo_main_1.csv")
    if shutil.which("iptables") is None:
        raise SystemExit("iptables was not found on this system")


def run_iptables(args):
    return subprocess.run(["iptables", *args], capture_output=True, text=True)


def ensure_chain():
    # Create the IDS chain once and send all incoming traffic through it
    if run_iptables(["-L", CHAIN, "-n"]).returncode != 0:
        run_iptables(["-N", CHAIN])
    if run_iptables(["-C", "INPUT", "-j", CHAIN]).returncode != 0:
        run_iptables(["-I", "INPUT", "1", "-j", CHAIN])


def is_blocked(ip):
    return run_iptables(["-C", CHAIN, "-s", ip, "-j", "DROP"]).returncode == 0


def block_ip(ip):
    result = run_iptables(["-A", CHAIN, "-s", ip, "-j", "DROP"])
    if result.returncode != 0:
        raise RuntimeError(f"iptables could not block {ip}, {result.stderr.strip()}")


def unblock_ip(ip):
    # Removes every IDS rule for this IP, returns how many were removed
    removed = 0
    while is_blocked(ip):
        run_iptables(["-D", CHAIN, "-s", ip, "-j", "DROP"])
        removed += 1
        if removed > 20:
            break
    return removed


def list_iptables_blocks():
    result = run_iptables(["-S", CHAIN])
    ips = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if "-s" in parts and "DROP" in parts:
            ips.append(parts[parts.index("-s") + 1].replace("/32", ""))
    return ips


def load_never_block():
    if not os.path.exists(NEVER_BLOCK_FILE):
        os.makedirs(os.path.dirname(NEVER_BLOCK_FILE), exist_ok=True)
        with open(NEVER_BLOCK_FILE, "w", encoding="utf-8") as f:
            f.write("# Never-block list, the IDS will alert but never block these IPs\n")
            f.write("# One IP per line, anything after # is a comment\n")
            for ip, note in DEFAULT_NEVER_BLOCK:
                f.write(f"{ip}  # {note}\n")
        give_to_user(NEVER_BLOCK_FILE)
    ips = set()
    with open(NEVER_BLOCK_FILE, encoding="utf-8") as f:
        for line in f:
            text = line.split("#")[0].strip()
            if text and is_valid_ip(text):
                ips.add(text)
    return ips


def read_blocklist():
    if not os.path.exists(BLOCKLIST_FILE):
        return []
    with open(BLOCKLIST_FILE, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_blocklist(rows):
    make_log_dir()
    with open(BLOCKLIST_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=BLOCKLIST_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    give_to_user(BLOCKLIST_FILE)


def add_to_blocklist(ip, attack, demo_file, test_row):
    rows = [r for r in read_blocklist() if r["ip"] != ip]
    rows.append({"ip": ip, "blocked_at": now_text(), "attack": attack,
                 "demo_file": demo_file, "test_row": test_row})
    write_blocklist(rows)


def remove_from_blocklist(ip):
    rows = read_blocklist()
    kept = [r for r in rows if r["ip"] != ip]
    write_blocklist(kept)
    return len(rows) - len(kept)


def restore_blocks():
    # Puts back any recorded block that iptables lost, for example after a restart
    restored = 0
    for row in read_blocklist():
        if is_valid_ip(row["ip"]) and not is_blocked(row["ip"]):
            block_ip(row["ip"])
            restored += 1
    return restored

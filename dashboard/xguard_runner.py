"""Runs the real XGuard backend from the dashboard.

The dashboard never predicts, blocks or alerts on its own. It writes the
chosen records into a CSV with the same columns as the demo files, then starts
the unchanged ids_controller.py on that file through sudo. Releases and resets
go through the unchanged unblock_ip.py and reset_demo.py. So whatever the
dashboard does is exactly what the terminal does, and every result lands in
the same log files.

Safety
    No shell is ever used, every command is a fixed list of arguments.
    Addresses are checked before they reach iptables.
    Text typed by staff is cleaned before it is passed to unblock_ip.py.
    sudo only allows the three backend scripts (see setup_permissions.sh).
"""

from __future__ import annotations

import io
import ipaddress
import json
import math
import os
import random
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

import xguard_data as xd

DEFAULT_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s", "Flow Packets/s",
    "Packet Length Mean", "Packet Length Std", "Fwd IAT Mean", "Bwd IAT Mean",
]
MAX_ROWS = 100
LAB_POOL = [f"192.168.56.{i}" for i in range(150, 200)]
OUTSIDE_POOL = [f"203.0.113.{i}" for i in range(10, 251)]
WINDOWS_HOST = "192.168.56.1"
IP_COLUMNS = ("demo_source_ip", "source_ip", "source ip", "src_ip", "src ip", "ip", "source address", "source_address")
NOT_LABELLED = "Not labelled"
KIND_TEXT = {"upload": "Uploaded file", "random": "Random test records", "manual": "Typed record"}

# One real record per class, used for the downloadable template and as the
# starting values of the typed record (taken from the demo files and test.csv)
EXAMPLE_ROWS = [
    {"source_ip": "203.0.113.20", "Label": "BENIGN", "values": [443, 5648475, 9, 6, 343, 5047, 954.2398612, 2.655584029, 336.875, 772.7722282, 706059.375, 27890.2]},
    {"source_ip": "203.0.113.21", "Label": "DoS Hulk", "values": [80, 83541173, 7, 7, 340, 11595, 142.8636871, 0.167582038, 796.0666667, 1424.246892, 13900000.0, 13900000.0]},
    {"source_ip": "203.0.113.22", "Label": "BENIGN", "values": [53, 255973, 2, 2, 64, 252, 1234.505202, 15.62664812, 69.6, 51.48592041, 3.0, 3.0]},
]
MANUAL_START = {"test_row": 523832, "Label": "DoS Hulk", "values": EXAMPLE_ROWS[1]["values"]}


def dashboard_dir() -> Path:
    return Path(__file__).resolve().parent


def runs_dir() -> Path:
    path = dashboard_dir() / "runs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def model_info(fyp_dir: Path) -> tuple[list[str], list[str]]:
    """Feature names and class names, read from the frozen model_info.json."""
    try:
        info = json.loads((fyp_dir / "models" / "model_info.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        info = {}
    features = info.get("features") if isinstance(info, dict) else None
    classes = info.get("class_names") if isinstance(info, dict) else None
    return list(features or DEFAULT_FEATURES), list(classes or ["BENIGN", "DoS Hulk", "PortScan", "Web Attack"])


def canonical_label(value: str, class_names: list[str]) -> str:
    """Spells a label the way the training data did, so the controller maps it."""
    text = " ".join(str(value).split())
    if not text:
        return NOT_LABELLED
    by_class = {xd.norm_label(c): c for c in class_names}
    return by_class.get(xd.norm_label(text), text)


def _key(name) -> str:
    return " ".join(str(name).replace("\ufeff", "").strip().lower().split())


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------
def ip_problem(text: str) -> str | None:
    try:
        ip = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return f"{text or 'This'} is not a valid IP address."
    if ip.version != 4:
        return "Only IPv4 addresses can be blocked by this firewall setup."
    if ip.is_unspecified or ip.is_multicast or str(ip) == "255.255.255.255":
        return f"{ip} is a special address and cannot be used as an attacker."
    return None


def ip_notes(ip: str, never_block: list[str]) -> list[str]:
    notes = []
    if ip in never_block:
        notes.append(f"{ip} is on the never-block list, so XGuard will alert but not block it.")
    if ip == WINDOWS_HOST:
        notes.append(f"{ip} is your Windows PC. If it is blocked, ping between Windows and Kali stops "
                     "until it is released, but the dashboard stays reachable through the port forward.")
    return notes


def assign_ips(count: int, mode: str, single: str = "", attackers: int = 5,
               file_ips: list[str] | None = None, seed: int | None = None) -> list[str]:
    """Source address for every row. Few attackers means repeat visits,
    which shows the already blocked behaviour."""
    rng = random.Random(seed)
    if mode == "single":
        return [single.strip()] * count
    if mode == "file":
        return [str(ip).strip() for ip in (file_ips or [])][:count]
    pool = OUTSIDE_POOL if mode == "outside" else LAB_POOL
    chosen = rng.sample(pool, k=max(1, min(attackers, len(pool))))
    return [rng.choice(chosen) for _ in range(count)]


# ---------------------------------------------------------------------------
# Building the file the controller reads
# ---------------------------------------------------------------------------
@dataclass
class Plan:
    kind: str
    features: pd.DataFrame          # the 12 feature columns, one row per record
    labels: list[str]
    scenarios: list[str]
    test_rows: list
    file_ips: list[str] | None = None
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return 0 if self.features is None else len(self.features)


def read_upload(data: bytes, filename: str, features: list[str], class_names: list[str]) -> Plan:
    """Checks an uploaded CSV and turns it into a plan. Never raises."""
    empty = Plan("upload", pd.DataFrame(columns=features), [], [], [])
    try:
        df = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False, encoding="utf-8-sig")
    except Exception as exc:
        empty.errors.append(f"The file could not be read as a CSV ({type(exc).__name__}).")
        return empty
    if df.empty:
        empty.errors.append("The file has a header but no rows.")
        return empty
    lookup = {_key(c): c for c in df.columns}
    missing = [f for f in features if _key(f) not in lookup]
    if missing:
        empty.errors.append("These feature columns are missing, " + ", ".join(missing) + ".")
        return empty

    notes = []
    if len(df) > MAX_ROWS:
        notes.append(f"The file has {len(df):,} rows. Only the first {MAX_ROWS} will be used.")
        df = df.head(MAX_ROWS)
    df = df.reset_index(drop=True)
    values = pd.DataFrame({f: pd.to_numeric(df[lookup[_key(f)]].astype(str).str.strip(), errors="coerce")
                           for f in features})
    finite = np.isfinite(values.to_numpy(dtype=float)).all(axis=1)

    ip_col = next((lookup[k] for k in IP_COLUMNS if k in lookup), None)
    file_ips = df[ip_col].astype(str).str.strip().tolist() if ip_col else None
    label_col = lookup.get("label")
    scenario_col = lookup.get("scenario")
    row_col = lookup.get("test_row")

    short = Path(filename).name[:40]
    keep = []
    bad_rows = []
    for i in range(len(df)):
        if not finite[i]:
            bad_rows.append(i + 1)
            continue
        keep.append(i)
    if bad_rows:
        shown = ", ".join(str(r) for r in bad_rows[:10]) + (" and more" if len(bad_rows) > 10 else "")
        notes.append(f"Skipped row {shown} because a feature value is missing or not a number.")
    if not keep:
        empty.errors.append("No row has valid numbers in all 12 features.")
        empty.notes = notes
        return empty

    labels, scenarios, test_rows = [], [], []
    for i in keep:
        labels.append(canonical_label(df.at[i, label_col], class_names) if label_col else NOT_LABELLED)
        given = str(df.at[i, scenario_col]).strip() if scenario_col else ""
        scenarios.append(given[:40] or f"Upload {short}")
        given_row = pd.to_numeric(df.at[i, row_col], errors="coerce") if row_col else float("nan")
        test_rows.append(int(given_row) if pd.notna(given_row) else i + 1)
    plan = Plan("upload", values.iloc[keep].reset_index(drop=True), labels, scenarios, test_rows,
                file_ips=[file_ips[i] for i in keep] if file_ips is not None else None, notes=notes)
    if not label_col:
        plan.notes.append("The file has no Label column, so results cannot be marked correct or wrong.")
    return plan


def build_run_frame(plan: Plan, ips: list[str], features: list[str]) -> pd.DataFrame:
    """Same column layout as the demo files made by make_demo_records.py."""
    frame = pd.DataFrame({
        "scenario": plan.scenarios,
        "test_row": plan.test_rows,
        "demo_source_ip": ips,
        "Label": plan.labels,
    })
    for f in features:
        frame[f] = plan.features[f].to_numpy()
    return frame


def write_run_file(frame: pd.DataFrame, kind: str) -> Path:
    folder = runs_dir()
    while True:
        path = folder / f"run_{datetime.now():%Y%m%d_%H%M%S}_{kind}.csv"
        if not path.exists():
            break
        time.sleep(1)
    frame.to_csv(path, index=False)
    return path


def template_csv(features: list[str]) -> bytes:
    rows = []
    for example in EXAMPLE_ROWS:
        row = {"source_ip": example["source_ip"], "Label": example["Label"]}
        row.update(dict(zip(features, example["values"])))
        rows.append(row)
    return pd.DataFrame(rows).to_csv(index=False).encode("utf-8")


# ---------------------------------------------------------------------------
# Test set sampling (records the model never saw during training)
# ---------------------------------------------------------------------------
def load_test_set(fyp_dir: Path) -> pd.DataFrame:
    df = pd.read_csv(fyp_dir / "data" / "test.csv")
    df["class"] = df["Label"].map(xd.norm_label)
    return df


def sample_test(df: pd.DataFrame, count: int, mix: str, seed: int) -> pd.DataFrame:
    """balanced gives every class the same share, natural keeps the real mix.
    The index of the result is the record's row number in test.csv."""
    count = max(1, min(int(count), MAX_ROWS))
    rng = np.random.default_rng(seed)
    if mix == "balanced":
        groups = [g for _, g in df.groupby("class", sort=True)]
        per = math.ceil(count / len(groups))
        parts = [g.sample(n=min(per, len(g)), random_state=int(rng.integers(1 << 31))) for g in groups]
        picked = pd.concat(parts)
        return picked.sample(frac=1, random_state=int(rng.integers(1 << 31))).head(count)
    return df.sample(n=count, random_state=int(rng.integers(1 << 31)))


def plan_from_test(sample: pd.DataFrame, features: list[str]) -> Plan:
    return Plan("random", sample[features].reset_index(drop=True), sample["Label"].astype(str).tolist(),
                ["Random draw"] * len(sample), [int(i) for i in sample.index])


def plan_manual(values: list[float], base_row: int, base_label: str, edited: bool,
                features: list[str]) -> Plan:
    frame = pd.DataFrame([values], columns=features)
    return Plan("manual", frame, [NOT_LABELLED if edited else base_label],
                ["Typed record, edited" if edited else "Typed record"], [int(base_row)])


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def use_sudo() -> bool:
    # Only switched off by the offline tests, never in normal use
    return os.environ.get("XGUARD_NO_SUDO") != "1"


def python_bin(fyp_dir: Path) -> str:
    return os.environ.get("XGUARD_TEST_PYTHON") or str(fyp_dir / "venv" / "bin" / "python")


def backend_command(fyp_dir: Path, script: str, *args) -> list[str]:
    command = [python_bin(fyp_dir), "-u", str(fyp_dir / script), *[str(a) for a in args]]
    return (["sudo", "-n"] + command) if use_sudo() else command


def permission_check(fyp_dir: Path) -> dict[str, bool]:
    """Asks sudo, without a password, whether each backend script may run."""
    samples = {"ids_controller.py": [str(runs_dir() / "check.csv")], "unblock_ip.py": ["--list"],
               "reset_demo.py": ["--yes"]}
    result = {}
    for script, args in samples.items():
        if not use_sudo():
            result[script] = True
            continue
        command = backend_command(fyp_dir, script, *args)
        try:
            check = subprocess.run(["sudo", "-n", "-l", *command[2:]], capture_output=True,
                                   text=True, timeout=8)
            result[script] = check.returncode == 0
        except (OSError, subprocess.SubprocessError):
            result[script] = False
    return result


def needs_permission(output: str) -> bool:
    text = output.lower()
    return "password is required" in text or "a terminal is required" in text or "not allowed to execute" in text


def clean_text(value: str, limit: int = 120, default: str = "none") -> str:
    text = "".join(ch if ch.isprintable() else " " for ch in str(value))
    text = " ".join(text.split())[:limit]
    return text or default


def run_unblock(fyp_dir: Path, ip: str, staff: str, note: str) -> tuple[str, str]:
    """Releases one address through unblock_ip.py. Returns (status, output)."""
    problem = ip_problem(ip)
    if problem:
        return "error", problem
    answers = f"{clean_text(staff, 60, 'unknown')}\n{clean_text(note, 200)}\ny\n"
    try:
        done = subprocess.run(backend_command(fyp_dir, "unblock_ip.py", ip), input=answers,
                              capture_output=True, text=True, timeout=60, cwd=str(fyp_dir))
    except subprocess.TimeoutExpired:
        return "error", "unblock_ip.py did not finish within 60 seconds."
    except OSError as exc:
        return "error", f"unblock_ip.py could not start ({exc})."
    output = (done.stdout or "") + (done.stderr or "")
    if needs_permission(output):
        return "permission", output
    if " unblocked, " in output:
        return "ok", output
    if "is not blocked by the IDS" in output:
        return "not_blocked", output
    return "error", output


def run_reset(fyp_dir: Path) -> tuple[str, str]:
    try:
        done = subprocess.run(backend_command(fyp_dir, "reset_demo.py", "--yes"), capture_output=True,
                              text=True, timeout=90, cwd=str(fyp_dir), stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return "error", "reset_demo.py did not finish within 90 seconds."
    except OSError as exc:
        return "error", f"reset_demo.py could not start ({exc})."
    output = (done.stdout or "") + (done.stderr or "")
    if needs_permission(output):
        return "permission", output
    return ("ok" if done.returncode == 0 and "Removed" in output else "error"), output


def tail(path: str | Path, lines: int = 80) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return "".join(f.readlines()[-lines:])
    except OSError:
        return ""


class RunManager:
    """Keeps track of the one detection run allowed at a time."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.handle = None
        self.info: dict | None = None

    def _refresh(self) -> None:
        if self.proc is not None and self.info and self.info["finished"] is None:
            code = self.proc.poll()
            if code is not None:
                self.info["returncode"] = code
                self.info["finished"] = datetime.now()
                if self.handle:
                    self.handle.close()
                    self.handle = None

    def busy(self) -> bool:
        with self.lock:
            self._refresh()
            return bool(self.info) and self.info["finished"] is None

    def start(self, fyp_dir: Path, csv_path: Path, rows: int, kind: str, user: str) -> tuple[bool, str]:
        with self.lock:
            self._refresh()
            if self.info and self.info["finished"] is None:
                return False, "Another run is still going. Wait for it to finish, or stop it first."
            log_path = csv_path.with_suffix(".log")
            handle = open(log_path, "w", encoding="utf-8")
            try:
                proc = subprocess.Popen(backend_command(fyp_dir, "ids_controller.py", csv_path),
                                        stdout=handle, stderr=subprocess.STDOUT,
                                        stdin=subprocess.DEVNULL, cwd=str(fyp_dir))
            except OSError as exc:
                handle.close()
                return False, f"The run could not start ({exc})."
            self.proc, self.handle = proc, handle
            self.info = {"name": csv_path.name, "path": str(csv_path), "log": str(log_path), "rows": rows,
                         "kind": kind, "user": user, "started": datetime.now(), "finished": None,
                         "returncode": None, "stopped": False, "reported": False}
            return True, csv_path.name

    def status(self) -> dict | None:
        with self.lock:
            self._refresh()
            if not self.info:
                return None
            info = dict(self.info)
        info["running"] = info["finished"] is None
        info["output"] = tail(info["log"])
        return info

    def stop(self) -> bool:
        with self.lock:
            if self.proc is None or self.proc.poll() is not None:
                return False
            self.info["stopped"] = True
            self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        return True

    def take_report(self) -> dict | None:
        """Returns a finished run once, so it is written to the activity log only once."""
        with self.lock:
            self._refresh()
            if self.info and self.info["finished"] is not None and not self.info["reported"]:
                self.info["reported"] = True
                return dict(self.info)
        return None


def previous_runs(limit: int = 10) -> list[dict]:
    rows = []
    for path in sorted(runs_dir().glob("run_*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]:
        kind = xd.run_kind(path.name) or "upload"
        try:
            with open(path, encoding="utf-8") as f:
                count = max(sum(1 for _ in f) - 1, 0)
        except OSError:
            count = 0
        started = xd.parse_archive_time(path.name)
        rows.append({"name": path.name, "kind": kind, "rows": count, "started": started})
    return rows


# ---------------------------------------------------------------------------
# Never-block list (config/never_block_list.txt in the main system)
# ---------------------------------------------------------------------------
# The machine's own addresses and its gateway. Removing one could let XGuard
# block itself or cut off Telegram, so the dashboard never removes these.
CORE_NEVER_BLOCK = ("127.0.0.1", "10.0.2.15", "192.168.56.101", "10.0.2.2", "10.0.2.3")
DEFAULT_NEVER_BLOCK_FILE = [
    "# Never-block list, the IDS will alert but never block these IPs",
    "# One IP per line, anything after # is a comment",
    "127.0.0.1  # Kali itself",
    "10.0.2.15  # Kali NAT address, eth0",
    "192.168.56.101  # Kali host-only address, eth1",
    "10.0.2.2  # VirtualBox NAT gateway, Kali's route to the internet and Telegram",
    "10.0.2.3  # VirtualBox NAT DNS server",
]


def never_block_path(fyp_dir: Path) -> Path:
    return fyp_dir / "config" / "never_block_list.txt"


def never_block_entries(fyp_dir: Path) -> list[dict]:
    """Every address on the list with its comment, and whether it is built in."""
    path = never_block_path(fyp_dir)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    entries, seen = [], set()
    for line in lines:
        address, _, comment = line.partition("#")
        address = address.strip()
        if not address or address in seen:
            continue
        seen.add(address)
        entries.append({"ip": address, "note": comment.strip(), "core": address in CORE_NEVER_BLOCK})
    return entries


def _write_never_block(path: Path, lines: list[str]) -> tuple[bool, str]:
    # Written in place, so the file keeps its owner and no folder rights are needed
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines).rstrip("\n") + "\n")
    except PermissionError:
        return False, (f"XGuard is not allowed to change {path}. In Kali run  "
                       f"sudo chown $USER:$USER {path}  then try again.")
    except OSError as exc:
        return False, f"The never-block list could not be saved ({type(exc).__name__})."
    return True, ""


def add_never_block(fyp_dir: Path, ip: str, note: str, added_by: str) -> tuple[bool, str]:
    ip = str(ip).strip()
    problem = ip_problem(ip)
    if problem:
        return False, problem
    if any(e["ip"] == ip for e in never_block_entries(fyp_dir)):
        return False, f"{ip} is already on the never-block list."
    path = never_block_path(fyp_dir)
    try:
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else list(DEFAULT_NEVER_BLOCK_FILE)
    except OSError:
        return False, "The never-block list could not be read."
    reason = clean_text(str(note).replace("#", " "), 60, "no reason given")
    who = clean_text(str(added_by).replace("#", " "), 40, "unknown")
    lines.append(f"{ip}  # {reason}, added by {who} on {datetime.now():%Y-%m-%d}")
    ok, message = _write_never_block(path, lines)
    return (True, f"{ip} added to the never-block list.") if ok else (False, message)


def remove_never_block(fyp_dir: Path, ip: str) -> tuple[bool, str]:
    ip = str(ip).strip()
    if ip in CORE_NEVER_BLOCK:
        return False, f"{ip} is one of the machine's own addresses, so it cannot be removed here."
    path = never_block_path(fyp_dir)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False, "The never-block list could not be read."
    kept = [line for line in lines if line.partition("#")[0].strip() != ip]
    if len(kept) == len(lines):
        return False, f"{ip} is not on the never-block list."
    ok, message = _write_never_block(path, kept)
    return (True, f"{ip} removed from the never-block list.") if ok else (False, message)


# ---------------------------------------------------------------------------
# Firewall status and restore
# ---------------------------------------------------------------------------
def firewall_status(fyp_dir: Path) -> dict | None:
    """Which recorded blocks are really in iptables, read with unblock_ip.py --list.
    Returns {ip: True or False}, or None when it cannot be checked."""
    try:
        done = subprocess.run(backend_command(fyp_dir, "unblock_ip.py", "--list"), capture_output=True,
                              text=True, timeout=20, cwd=str(fyp_dir), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    output = (done.stdout or "") + (done.stderr or "")
    if done.returncode != 0 or needs_permission(output):
        return None
    status = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1] in ("yes", "no") and not ip_problem(parts[0]):
            status[parts[0]] = parts[-1] == "yes"
    return status


def restore_blocks(fyp_dir: Path) -> tuple[str, str, int]:
    """Puts recorded blocks back into iptables using the controller's own start up
    restore step, by running it on a file with no records. Returns (status, output, count)."""
    features, _ = model_info(fyp_dir)
    columns = ["scenario", "test_row", "demo_source_ip", "Label", *features]
    path = runs_dir() / f"restore_{datetime.now():%Y%m%d_%H%M%S}.csv"
    pd.DataFrame(columns=columns).to_csv(path, index=False)
    try:
        done = subprocess.run(backend_command(fyp_dir, "ids_controller.py", path), capture_output=True,
                              text=True, timeout=120, cwd=str(fyp_dir), stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return "error", "The controller did not finish within 2 minutes.", 0
    except OSError as exc:
        return "error", f"The controller could not start ({exc}).", 0
    output = (done.stdout or "") + (done.stderr or "")
    if needs_permission(output):
        return "permission", output, 0
    match = re.search(r"Restored (\d+) earlier blocks", output)
    count = int(match.group(1)) if match else 0
    return ("ok" if done.returncode == 0 else "error"), output, count

"""Data layer for the XGuard IDS dashboard.

Everything in this file only READS files from the IDS folder (~/fyp).
Nothing here writes to the logs, runs iptables or sends Telegram messages.
It has no Streamlit code, so the logic can be tested on its own.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd

# ---------------------------------------------------------------------------
# File names and column layouts (taken from the real IDS log files)
# ---------------------------------------------------------------------------
EVENT_FILE = "ids_events.csv"
BLOCK_FILE = "blocklist.csv"
STAFF_FILE = "staff_actions.csv"
LOG_FILES = (EVENT_FILE, BLOCK_FILE, STAFF_FILE)

EVENT_COLUMNS = (
    "timestamp", "demo_file", "scenario", "test_row", "source_ip",
    "actual_label", "predicted_label", "confidence", "prediction_ms",
    "action", "telegram",
)
BLOCK_COLUMNS = ("ip", "blocked_at", "attack", "demo_file", "test_row")
STAFF_COLUMNS = ("timestamp", "ip", "action", "staff", "note", "blocked_at", "attack")

CLASS_ORDER = ("BENIGN", "DoS Hulk", "PortScan", "Web Attack")
ATTACK_CLASSES = CLASS_ORDER[1:]

# Plain wording shown on screen for the values stored in the logs
ACTION_TEXT = {
    "BLOCKED": "Blocked",
    "ALREADY_BLOCKED": "Already blocked",
    "NOT_BLOCKED_NEVER_BLOCK_LIST": "Protected, not blocked",
    "NO_ACTION": "No action",
}
TELEGRAM_TEXT = {
    "sent": "Sent",
    "failed": "Failed",
    "not needed": "Not needed",
}

# What each address on the never-block list is, for the Blocked IPs page
NEVER_BLOCK_ROLES = {
    "127.0.0.1": "Loopback, Kali talking to itself",
    "10.0.2.15": "Kali address on the NAT (internet) adapter",
    "192.168.56.101": "Kali address on the host-only (lab) adapter",
    "10.0.2.2": "VirtualBox NAT gateway, also carries the dashboard port forward",
    "10.0.2.3": "VirtualBox DNS server",
}

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


# ---------------------------------------------------------------------------
# Locating the IDS folder and its log sources
# ---------------------------------------------------------------------------
def default_fyp_dir() -> Path:
    """Folder of the frozen IDS project. XGUARD_FYP_DIR overrides it."""
    env = os.environ.get("XGUARD_FYP_DIR")
    if env:
        return Path(env).expanduser()
    kali = Path("/home/kali/fyp")
    if kali.exists():
        return kali
    return Path.home() / "fyp"


@dataclass(frozen=True)
class LogSource:
    key: str            # stable id used by the sidebar selector
    label: str          # text shown in the sidebar
    folder: Path        # folder holding the three CSV logs
    live: bool          # True for ~/fyp/logs, False for an archived run
    saved_at: datetime | None  # when an archived run was saved by reset_demo.py


def parse_archive_time(name: str) -> datetime | None:
    """logs_20261019_011242 -> datetime(2026, 10, 19, 1, 12, 42)."""
    match = re.search(r"(\d{8})_(\d{6})", name)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1) + match.group(2), "%Y%m%d%H%M%S")
    except ValueError:
        return None


def list_log_sources(fyp_dir: Path) -> list[LogSource]:
    """Live logs first, then archived runs (newest first)."""
    sources = [LogSource("live", "Live logs", fyp_dir / "logs", True, None)]
    archive = fyp_dir / "archive"
    if not archive.is_dir():
        return sources
    found = []
    try:
        folders = list(archive.iterdir())
    except OSError:
        return sources
    for folder in folders:
        if not folder.is_dir() or not any((folder / f).exists() for f in LOG_FILES):
            continue
        saved = parse_archive_time(folder.name)
        try:
            when = saved or datetime.fromtimestamp(folder.stat().st_mtime)
        except OSError:
            continue
        found.append((when, folder))
    for when, folder in sorted(found, key=lambda item: item[0], reverse=True):
        label = f"Archived run, {fmt_dt(when, seconds=False)}"
        sources.append(LogSource(folder.name, label, folder, False, when))
    return sources


# ---------------------------------------------------------------------------
# Safe reading
# ---------------------------------------------------------------------------
def file_signature(path: Path) -> tuple[int, int]:
    """Changes whenever the file changes. Used to refresh the cache."""
    try:
        info = path.stat()
        return (info.st_mtime_ns, info.st_size)
    except OSError:
        return (0, -1)


def _empty(columns) -> pd.DataFrame:
    return pd.DataFrame({c: pd.Series(dtype="object") for c in columns})


def read_csv_safe(path: Path, columns) -> tuple[pd.DataFrame, str | None]:
    """Read a log CSV as text. Never raises. Returns (table, problem or None)."""
    columns = tuple(columns)
    if not path.exists():
        return _empty(columns), None  # a missing log simply means no entries yet
    try:
        df = pd.read_csv(
            path, dtype=str, keep_default_na=False,
            on_bad_lines="skip", encoding="utf-8-sig",
        )
    except pd.errors.EmptyDataError:
        return _empty(columns), None
    except PermissionError:
        return _empty(columns), (
            f"{path.name} cannot be read because of file permissions. "
            f"Run  sudo chmod o+r {path}  in Kali."
        )
    except Exception as exc:  # unreadable or half written file
        return _empty(columns), f"{path.name} could not be read ({type(exc).__name__})."
    df = df.fillna("")
    df.columns = [str(c).strip() for c in df.columns]
    for column in columns:
        if column not in df.columns:
            df[column] = ""
    return df, None


def read_never_block(path: Path) -> tuple[list[str], str | None]:
    if not path.exists():
        return [], None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return [], f"{path.name} could not be read."
    addresses = []
    for line in text.splitlines():
        value = line.split("#", 1)[0].strip()
        if value:
            addresses.append(value)
    return addresses, None


# ---------------------------------------------------------------------------
# Cleaning the raw tables
# ---------------------------------------------------------------------------
def run_kind(demo_file: str) -> str | None:
    """upload, random or manual for files made by the dashboard, None for demo files."""
    match = re.match(r"run_\d{8}_\d{6}_(upload|random|manual)\.csv$", str(demo_file or ""))
    return match.group(1) if match else None


def norm_label(value: object) -> str:
    """One name per class, whatever spelling the file used."""
    text = str(value).strip()
    low = text.lower()
    if "web attack" in low:
        return "Web Attack"
    if low == "benign":
        return "BENIGN"
    if low.replace(" ", "") == "doshulk":
        return "DoS Hulk"
    if low.replace(" ", "") == "portscan":
        return "PortScan"
    return text


def to_time(series: pd.Series) -> pd.Series:
    parsed = pd.to_datetime(series, format=TIME_FORMAT, errors="coerce")
    has_text = series.astype(str).str.strip().ne("")
    if len(series) and parsed.isna().all() and has_text.any():
        parsed = pd.to_datetime(series, errors="coerce", format="mixed")
    return parsed


def prepare_events(raw: pd.DataFrame) -> pd.DataFrame:
    """Typed copy of ids_events.csv, kept in the order the IDS wrote it."""
    df = raw.copy()
    # A line the IDS is still writing has no prediction yet, so skip it
    df = df[df["predicted_label"].astype(str).str.strip().ne("")].reset_index(drop=True)
    df["time"] = to_time(df["timestamp"])
    df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce")
    df["prediction_ms"] = pd.to_numeric(df["prediction_ms"], errors="coerce")
    df["test_row"] = pd.to_numeric(df["test_row"], errors="coerce").astype("Int64")
    df["actual"] = df["actual_label"].map(norm_label).astype(object)
    df["predicted"] = df["predicted_label"].map(norm_label).astype(object)
    df["action"] = df["action"].astype(str).str.strip().str.upper().astype(object)
    df["telegram"] = df["telegram"].astype(str).str.strip().str.lower().astype(object)
    df["source_ip"] = df["source_ip"].astype(str).str.strip().astype(object)
    df["scenario"] = df["scenario"].astype(str).str.strip().astype(object)
    df["is_attack"] = df["predicted"].ne("BENIGN")
    df["event_no"] = range(1, len(df) + 1)
    return df


def prepare_blocks(raw: pd.DataFrame) -> pd.DataFrame:
    df = raw.copy().reset_index(drop=True)
    df["ip"] = df["ip"].astype(str).str.strip().astype(object)
    df["blocked_time"] = to_time(df["blocked_at"])
    df["attack_name"] = df["attack"].map(norm_label).astype(object)
    df["test_row"] = pd.to_numeric(df["test_row"], errors="coerce").astype("Int64")
    return df


def prepare_staff(raw: pd.DataFrame) -> pd.DataFrame:
    df = raw.copy().reset_index(drop=True)
    df["ip"] = df["ip"].astype(str).str.strip().astype(object)
    df["time"] = to_time(df["timestamp"])
    df["blocked_time"] = to_time(df["blocked_at"])
    df["attack_name"] = df["attack"].map(norm_label).astype(object)
    df["action"] = df["action"].astype(str).str.strip().str.upper().astype(object)
    df["blocked_seconds"] = (df["time"] - df["blocked_time"]).dt.total_seconds()
    return df


# ---------------------------------------------------------------------------
# Block history (current blocks plus staff releases)
# ---------------------------------------------------------------------------
HISTORY_COLUMNS = (
    "ip", "attack", "blocked_at", "released_at", "released_by",
    "note", "status", "seconds",
)


def build_block_history(events: pd.DataFrame, blocks: pd.DataFrame,
                        staff: pd.DataFrame, ref_now: datetime) -> pd.DataFrame:
    """One row per block.

    Released  the IP was unblocked by staff (staff_actions.csv)
    Blocked   the IP is still in blocklist.csv
    Cleared   a BLOCKED event with no matching entry in either file
    """
    rows = []
    for _, r in staff.iterrows():
        if r["action"] != "UNBLOCKED":
            continue
        rows.append({
            "ip": r["ip"], "attack": r["attack_name"], "blocked_at": r["blocked_time"],
            "released_at": r["time"], "released_by": r["staff"], "note": r["note"],
            "status": "Released",
        })
    for _, r in blocks.iterrows():
        rows.append({
            "ip": r["ip"], "attack": r["attack_name"], "blocked_at": r["blocked_time"],
            "released_at": pd.NaT, "released_by": "", "note": "", "status": "Blocked",
        })
    # The event is written after the Telegram attempt, so it can be a few
    # seconds (or a timeout) later than the moment the block was applied.
    tolerance = 180
    for _, e in events[events["action"] == "BLOCKED"].iterrows():
        matched = False
        for row in rows:
            if row["ip"] != e["source_ip"]:
                continue
            if pd.isna(row["blocked_at"]) or pd.isna(e["time"]):
                matched = True
                break
            if abs((e["time"] - row["blocked_at"]).total_seconds()) <= tolerance:
                matched = True
                break
        if not matched:
            rows.append({
                "ip": e["source_ip"], "attack": e["predicted"], "blocked_at": e["time"],
                "released_at": pd.NaT, "released_by": "", "note": "", "status": "Cleared",
            })
    hist = pd.DataFrame(rows, columns=list(HISTORY_COLUMNS[:-1]))
    if hist.empty:
        return pd.DataFrame({c: pd.Series(dtype="object") for c in HISTORY_COLUMNS})
    hist["blocked_at"] = pd.to_datetime(hist["blocked_at"], errors="coerce")
    hist["released_at"] = pd.to_datetime(hist["released_at"], errors="coerce")
    seconds = []
    for _, r in hist.iterrows():
        if pd.isna(r["blocked_at"]):
            seconds.append(float("nan"))
        elif r["status"] == "Released" and pd.notna(r["released_at"]):
            seconds.append((r["released_at"] - r["blocked_at"]).total_seconds())
        elif r["status"] == "Blocked":
            seconds.append((pd.Timestamp(ref_now) - r["blocked_at"]).total_seconds())
        else:
            seconds.append(float("nan"))
    hist["seconds"] = seconds
    return hist.sort_values("blocked_at", kind="stable", na_position="last").reset_index(drop=True)


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------
def summarize(events: pd.DataFrame, blocks: pd.DataFrame) -> dict:
    ms = events["prediction_ms"].dropna()
    return {
        "records": int(len(events)),
        "attacks": int(events["is_attack"].sum()) if len(events) else 0,
        "benign": int((~events["is_attack"]).sum()) if len(events) else 0,
        "blocked_now": int(len(blocks)),
        "alerts_sent": int(events["telegram"].eq("sent").sum()),
        "alerts_failed": int(events["telegram"].eq("failed").sum()),
        "median_ms": float(ms.median()) if len(ms) else None,
        "addresses": int(events["source_ip"].nunique()),
        "last_time": events["time"].dropna().max() if len(events) else None,
    }


# ---------------------------------------------------------------------------
# Result files from Part 5 (static, the model is frozen)
# ---------------------------------------------------------------------------
def load_results(fyp_dir: Path) -> dict:
    results_dir = fyp_dir / "results"
    out = {"metrics": None, "confusion": None, "before_after": None,
           "tuning": None, "model_info": None, "problems": []}

    def note(name):
        out["problems"].append(f"{name} could not be read.")

    path = results_dir / "test_metrics.json"
    if path.exists():
        try:
            out["metrics"] = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            note(path.name)

    path = results_dir / "confusion_matrix.csv"
    if path.exists():
        try:
            cm = pd.read_csv(path, index_col=0)
            cm.index = [norm_label(i) for i in cm.index]
            cm.columns = [norm_label(c) for c in cm.columns]
            out["confusion"] = cm.apply(pd.to_numeric, errors="coerce").fillna(0).astype(int)
        except Exception:
            note(path.name)

    path = results_dir / "before_after_comparison.csv"
    if path.exists():
        try:
            ba = pd.read_csv(path, index_col=0)
            ba.index = [str(i).strip() for i in ba.index]
            out["before_after"] = ba.apply(pd.to_numeric, errors="coerce")
        except Exception:
            note(path.name)

    path = results_dir / "tuning_results.csv"
    if path.exists():
        try:
            out["tuning"] = pd.read_csv(path)
        except Exception:
            note(path.name)

    path = fyp_dir / "models" / "model_info.json"
    if path.exists():
        try:
            out["model_info"] = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            note(path.name)
    return out


def confusion_extras(cm: pd.DataFrame) -> pd.DataFrame:
    """Correct and misclassified counts per actual class."""
    rows = []
    for cls in cm.index:
        total = int(cm.loc[cls].sum())
        correct = int(cm.loc[cls, cls]) if cls in cm.columns else 0
        rows.append({"class": cls, "correct": correct, "misclassified": total - correct})
    return pd.DataFrame(rows).set_index("class")


def biggest_error(cm: pd.DataFrame) -> tuple[str, str, int] | None:
    best = None
    for actual in cm.index:
        for predicted in cm.columns:
            if actual == predicted:
                continue
            count = int(cm.loc[actual, predicted])
            if count and (best is None or count > best[2]):
                best = (actual, predicted, count)
    return best


# ---------------------------------------------------------------------------
# Turning one event into plain language (used by the decision trace)
# ---------------------------------------------------------------------------
@dataclass
class Stage:
    name: str
    value: str
    note: str
    state: str            # LED style: ok, block, repeat, protect, idle, fail, info
    color_class: str = ""  # set when the value is a traffic class
    mono: bool = False


def decision_stages(e: pd.Series) -> list[Stage]:
    action = e["action"]
    telegram = e["telegram"]
    predicted = e["predicted"]
    attack = predicted != "BENIGN"

    where = e["scenario"] or "Replayed record"
    kind = run_kind(e.get("demo_file", ""))
    if pd.notna(e["test_row"]):
        if kind == "upload":
            where = f"{where}, row {int(e['test_row'])}"
        elif kind == "manual":
            where = f"{where}, from test row {int(e['test_row'])}"
        else:
            where = f"{where}, test row {int(e['test_row'])}"
    stages = [Stage("Flow record", e["source_ip"] or "Unknown", where, "info", mono=True)]

    if pd.notna(e["confidence"]) and pd.notna(e["prediction_ms"]):
        model_note = f"{fmt_conf(e['confidence'])} confidence in {e['prediction_ms']:.2f} ms"
    else:
        model_note = "Prediction details missing"
    stages.append(Stage("XGBoost", predicted or "Unknown", model_note,
                        "ok" if not attack else "block", color_class=predicted))

    if not attack:
        stages.append(Stage("Safety check", "Skipped", "Normal traffic needs no response", "idle"))
    elif action == "NOT_BLOCKED_NEVER_BLOCK_LIST":
        stages.append(Stage("Safety check", "Protected", "On the never-block list", "protect"))
    else:
        stages.append(Stage("Safety check", "Passed", "Not on the never-block list", "ok"))

    if action == "BLOCKED":
        stages.append(Stage("Firewall", "Blocked", "Rule added to FYP_IDS_BLOCK", "block"))
    elif action == "ALREADY_BLOCKED":
        stages.append(Stage("Firewall", "Already blocked", "No duplicate rule added", "repeat"))
    elif action == "NOT_BLOCKED_NEVER_BLOCK_LIST":
        stages.append(Stage("Firewall", "Not blocked", "Address is protected", "protect"))
    elif action == "NO_ACTION":
        stages.append(Stage("Firewall", "No action", "Traffic allowed", "idle"))
    else:
        stages.append(Stage("Firewall", action.title() or "Unknown", "Unrecognised action", "idle"))

    if telegram == "sent":
        stages.append(Stage("Telegram", "Alert sent", "Staff notified", "ok"))
    elif telegram == "failed":
        detail = "Block was already in place" if action in ("BLOCKED", "ALREADY_BLOCKED") else "Failure written to the log"
        stages.append(Stage("Telegram", "Alert failed", detail, "fail"))
    elif telegram == "not needed":
        stages.append(Stage("Telegram", "Not needed", "No alert for normal traffic", "idle"))
    else:
        stages.append(Stage("Telegram", telegram.title() or "Unknown", "Unrecognised status", "idle"))
    return stages


def decision_summary(e: pd.Series) -> str:
    ip = e["source_ip"] or "an unknown address"
    cls = e["predicted"]
    action = e["action"]
    telegram = e["telegram"]
    if action == "NO_ACTION" or cls == "BENIGN":
        return f"The flow from {ip} was normal traffic, so no firewall rule and no alert were needed."
    if action == "BLOCKED":
        if telegram == "failed":
            return (f"XGuard classified the flow from {ip} as {cls} and blocked the address. "
                    "The Telegram alert then failed, but protection was not affected because "
                    "blocking happens before alerting, and the failure is in the log.")
        return f"XGuard classified the flow from {ip} as {cls}, blocked the address, then alerted staff on Telegram."
    if action == "ALREADY_BLOCKED":
        tail = "Staff were alerted again." if telegram == "sent" else "The alert could not be delivered."
        return f"{ip} sent {cls} traffic but was already blocked, so no duplicate rule was added. {tail}"
    if action == "NOT_BLOCKED_NEVER_BLOCK_LIST":
        tail = "Staff were alerted to review it." if telegram == "sent" else "The alert could not be delivered."
        return (f"XGuard classified the flow from {ip} as {cls}, but {ip} is on the never-block list, "
                f"so no firewall rule was added. {tail}")
    return f"XGuard classified the flow from {ip} as {cls}."


def outcome(e: pd.Series) -> str:
    """Overall colour of a decision: block, protect or ok."""
    if e["action"] in ("BLOCKED", "ALREADY_BLOCKED"):
        return "block"
    if e["action"] == "NOT_BLOCKED_NEVER_BLOCK_LIST":
        return "protect"
    return "ok"


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
def fmt_dt(ts, seconds: bool = True) -> str:
    if ts is None or pd.isna(ts):
        return "Unknown time"
    clock = f"{ts:%H:%M:%S}" if seconds else f"{ts:%H:%M}"
    return f"{ts.day} {ts:%b %Y}, {clock}"


def fmt_short(ts) -> str:
    if ts is None or pd.isna(ts):
        return "Unknown"
    return f"{ts.day} {ts:%b} {ts:%H:%M:%S}"


def fmt_duration(seconds) -> str:
    if seconds is None or pd.isna(seconds):
        return "Unknown"
    s = max(0, int(round(float(seconds))))
    days, rem = divmod(s, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days} d {hours} h"
    if hours:
        return f"{hours} h {minutes} min"
    if minutes:
        return f"{minutes} min {secs} s"
    return f"{secs} s"


def fmt_ago(ts, now: datetime) -> str:
    if ts is None or pd.isna(ts):
        return "unknown"
    seconds = (pd.Timestamp(now) - ts).total_seconds()
    if seconds < 10:
        return "just now"
    return f"{fmt_duration(seconds)} ago"


def fmt_conf(value) -> str:
    if value is None or pd.isna(value):
        return "Unknown"
    return f"{float(value) * 100:.4f}%"


def fmt_ms(value) -> str:
    if value is None or pd.isna(value):
        return "Unknown"
    return f"{float(value):.2f} ms"


def event_label(e: pd.Series) -> str:
    return f"#{e['event_no']}  {fmt_short(e['time'])}  {e['scenario']}, {e['predicted']} from {e['source_ip']}"


# ---------------------------------------------------------------------------
# Runs (one input file each) and their summaries
# ---------------------------------------------------------------------------
KIND_TEXT = {"upload": "Uploaded file", "random": "Random test records", "manual": "Typed record"}


def run_label(demo_file: str) -> str:
    kind = run_kind(demo_file)
    if not kind:
        return demo_file or "Unknown file"
    when = parse_archive_time(demo_file)
    return f"{KIND_TEXT[kind]}, {fmt_short(when)}" if when else KIND_TEXT[kind]


def run_order(events: pd.DataFrame) -> list[str]:
    """Input files, newest first, by their latest decision."""
    if events.empty:
        return []
    last = events.groupby("demo_file")["event_no"].max().sort_values(ascending=False)
    return [str(f) for f in last.index if str(f)]


def summarize_run(rows: pd.DataFrame) -> dict:
    labelled = rows[rows["actual"].isin(CLASS_ORDER)]
    ms = rows["prediction_ms"].dropna()
    return {
        "records": int(len(rows)),
        "attacks": int(rows["is_attack"].sum()),
        "blocked": int(rows["action"].eq("BLOCKED").sum()),
        "already": int(rows["action"].eq("ALREADY_BLOCKED").sum()),
        "protected": int(rows["action"].eq("NOT_BLOCKED_NEVER_BLOCK_LIST").sum()),
        "sent": int(rows["telegram"].eq("sent").sum()),
        "failed": int(rows["telegram"].eq("failed").sum()),
        "labelled": int(len(labelled)),
        "correct": int((labelled["actual"] == labelled["predicted"]).sum()),
        "median_ms": float(ms.median()) if len(ms) else None,
        "addresses": int(rows["source_ip"].nunique()),
        "first": rows["time"].min() if len(rows) else None,
        "last": rows["time"].max() if len(rows) else None,
        "classes": rows["predicted"].value_counts().to_dict(),
    }


def run_report_text(demo_file: str, rows: pd.DataFrame, started_by: str = "") -> str:
    """Plain text summary of one run, for the report appendix."""
    s = summarize_run(rows)
    lines = [
        "XGuard IDS run report",
        "",
        f"Run                    {run_label(demo_file)}",
        f"Input file             {demo_file}",
        f"Started by             {started_by or 'not recorded'}",
        f"First decision         {fmt_dt(s['first'])}",
        f"Last decision          {fmt_dt(s['last'])}",
        "",
        f"Records checked        {s['records']}",
        f"Attacks detected       {s['attacks']}",
        f"Newly blocked          {s['blocked']}",
        f"Already blocked        {s['already']}",
        f"Protected, not blocked {s['protected']}",
        f"Telegram alerts sent   {s['sent']}",
        f"Telegram alerts failed {s['failed']}",
        f"Source addresses       {s['addresses']}",
        f"Median prediction      {fmt_ms(s['median_ms'])}",
    ]
    if s["labelled"]:
        lines.append(f"Correct on labelled    {s['correct']} of {s['labelled']}")
    lines += ["", "Predicted classes"]
    for cls in list(CLASS_ORDER) + [c for c in s["classes"] if c not in CLASS_ORDER]:
        if cls in s["classes"]:
            lines.append(f"  {cls:<21}{s['classes'][cls]}")
    lines += ["", "Decisions", ""]
    header = f"{'Time':<20}{'Source':<17}{'True label':<13}{'Predicted':<12}{'Firewall':<24}Telegram"
    lines.append(header)
    for _, e in rows.iterrows():
        actual = e["actual"] if e["actual"] in CLASS_ORDER else "-"
        lines.append(f"{fmt_short(e['time']):<20}{e['source_ip']:<17}{actual:<13}{e['predicted']:<12}"
                     f"{ACTION_TEXT.get(e['action'], e['action']):<24}{TELEGRAM_TEXT.get(e['telegram'], e['telegram'])}")
    return "\n".join(lines) + "\n"

"""Accounts, roles and the activity log of the XGuard IDS dashboard.

Passwords are never stored. Each one is turned into a salted PBKDF2-SHA256
hash, and only the salt and hash are kept in config/users.json (readable by
the owner only). The first admin account is created in the Kali terminal, so
only someone with access to the machine can set the dashboard up.

Terminal use, from the ~/fyp_dashboard folder
    venv/bin/python xguard_auth.py create-admin
    venv/bin/python xguard_auth.py reset-password <username>
    venv/bin/python xguard_auth.py list
"""

from __future__ import annotations

import csv
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

ROLES = ("viewer", "analyst", "admin")
ROLE_TEXT = {"viewer": "Viewer", "analyst": "Analyst", "admin": "Admin"}
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}
ROLE_SUMMARY = {
    "viewer": "Can watch every page, cannot change anything",
    "analyst": "Can also run detection and release blocked addresses",
    "admin": "Can also reset the demo, manage accounts and edit the never-block list",
}
# Lowest role allowed to do each thing
PERMISSIONS = {"view": "viewer", "run": "analyst", "unblock": "analyst", "reset": "admin", "users": "admin",
               "neverblock": "admin"}

ITERATIONS = 240_000
USERNAME_PATTERN = re.compile(r"^[a-z0-9_.-]{3,32}$")
AUDIT_FIELDS = ["timestamp", "user", "role", "action", "detail"]


def dashboard_dir() -> Path:
    return Path(__file__).resolve().parent


def users_file() -> Path:
    return dashboard_dir() / "config" / "users.json"


def audit_file() -> Path:
    return dashboard_dir() / "logs" / "dashboard_audit.csv"


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def can(role: str | None, permission: str) -> bool:
    if role not in ROLE_RANK:
        return False
    return ROLE_RANK[role] >= ROLE_RANK[PERMISSIONS.get(permission, "admin")]


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
def hash_password(password: str, salt: bytes | None = None, iterations: int = ITERATIONS) -> dict:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {"salt": salt.hex(), "hash": digest.hex(), "iterations": iterations}


def verify_password(password: str, record: dict) -> bool:
    try:
        salt = bytes.fromhex(record["salt"])
        expected = bytes.fromhex(record["hash"])
        iterations = int(record.get("iterations", ITERATIONS))
    except (KeyError, ValueError, TypeError):
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(digest, expected)


def password_problem(password: str, confirm: str | None = None) -> str | None:
    """Returns why a password is not acceptable, or None if it is fine."""
    if confirm is not None and password != confirm:
        return "The two passwords do not match."
    if len(password) < 8:
        return "Use at least 8 characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Use at least one letter and one number."
    return None


def username_problem(username: str) -> str | None:
    if not USERNAME_PATTERN.match(username):
        return "Use 3 to 32 lowercase letters, numbers, dots, dashes or underscores."
    return None


# ---------------------------------------------------------------------------
# Account storage
# ---------------------------------------------------------------------------
def load_users() -> dict:
    path = users_file()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    users = data.get("users", {}) if isinstance(data, dict) else {}
    return users if isinstance(users, dict) else {}


def save_users(users: dict) -> None:
    path = users_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write to a temporary file first, then swap it in, so a crash never leaves half a file
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".users_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"users": users}, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def has_users() -> bool:
    return bool(load_users())


def admin_count(users: dict) -> int:
    return sum(1 for u in users.values() if u.get("role") == "admin")


def create_user(username: str, name: str, role: str, password: str,
                must_change: bool = False) -> tuple[bool, str]:
    username = username.strip().lower()
    name = " ".join(name.split()) or username
    users = load_users()
    problem = username_problem(username) or password_problem(password)
    if problem:
        return False, problem
    if role not in ROLES:
        return False, "Choose a valid role."
    if username in users:
        return False, f"The username {username} is already taken."
    users[username] = {"name": name[:60], "role": role, "created": now_text(), "last_login": "",
                       "must_change": bool(must_change), **hash_password(password)}
    save_users(users)
    return True, f"Account {username} created as {ROLE_TEXT[role]}."


def set_role(username: str, role: str) -> tuple[bool, str]:
    users = load_users()
    if username not in users or role not in ROLES:
        return False, "Account or role not found."
    if users[username]["role"] == "admin" and role != "admin" and admin_count(users) <= 1:
        return False, "This is the last admin account, so it must stay an admin."
    users[username]["role"] = role
    save_users(users)
    return True, f"{username} is now {ROLE_TEXT[role]}."


def set_password(username: str, password: str, must_change: bool = False) -> tuple[bool, str]:
    users = load_users()
    if username not in users:
        return False, "Account not found."
    problem = password_problem(password)
    if problem:
        return False, problem
    users[username].update(hash_password(password))
    users[username]["must_change"] = bool(must_change)
    save_users(users)
    extra = " They will be asked to choose their own at the next sign in." if must_change else ""
    return True, f"Password changed for {username}.{extra}"


def change_own_password(username: str, current: str, new: str, repeat: str) -> tuple[bool, str]:
    users = load_users()
    record = users.get(username)
    if record is None:
        return False, "Account not found."
    if not verify_password(current, record):
        return False, "Your current password is not correct."
    problem = password_problem(new, repeat)
    if problem:
        return False, problem
    if new == current:
        return False, "Choose a password different from the current one."
    record.update(hash_password(new))
    record["must_change"] = False
    save_users(users)
    return True, "Password changed."


def needs_password_change(username: str) -> bool:
    return bool(load_users().get(username, {}).get("must_change"))


def delete_user(username: str, acting_user: str) -> tuple[bool, str]:
    users = load_users()
    if username not in users:
        return False, "Account not found."
    if username == acting_user:
        return False, "You cannot delete the account you are signed in with."
    if users[username]["role"] == "admin" and admin_count(users) <= 1:
        return False, "This is the last admin account, so it cannot be deleted."
    del users[username]
    save_users(users)
    return True, f"Account {username} deleted."


LOCK_AFTER = 5          # wrong passwords in a row
LOCK_WINDOW = 600       # counted over 10 minutes
LOCK_SECONDS = 60       # then the account is locked for a minute


def _guard_file() -> Path:
    return dashboard_dir() / "config" / "login_guard.json"


def _load_guard() -> dict:
    try:
        data = json.loads(_guard_file().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_guard(data: dict) -> None:
    try:
        path = _guard_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        pass


def lock_remaining(username: str) -> int:
    """Seconds left on a lock for this username, 0 if it is not locked."""
    entry = _load_guard().get(username.strip().lower(), {})
    return max(0, int(entry.get("locked_until", 0) - time.time()))


def record_failure(username: str) -> bool:
    """Counts a wrong password. Returns True if this attempt locked the account."""
    key = username.strip().lower() or "unknown"
    data = _load_guard()
    now = time.time()
    entry = data.get(key, {})
    fails = [t for t in entry.get("fails", []) if now - t < LOCK_WINDOW] + [now]
    locked = len(fails) >= LOCK_AFTER
    data[key] = {"fails": [] if locked else fails,
                 "locked_until": now + LOCK_SECONDS if locked else entry.get("locked_until", 0)}
    _save_guard(data)
    return locked


def clear_failures(username: str) -> None:
    data = _load_guard()
    if data.pop(username.strip().lower(), None) is not None:
        _save_guard(data)


def authenticate(username: str, password: str) -> dict | None:
    username = username.strip().lower()
    users = load_users()
    record = users.get(username)
    if record is None:
        # Spend the same time as a real check, so wrong usernames are not easier to spot
        verify_password(password, hash_password("timing-guard", b"\x00" * 16))
        return None
    if not verify_password(password, record):
        return None
    record["last_login"] = now_text()
    save_users(users)
    return {"username": username, "name": record.get("name", username), "role": record.get("role", "viewer")}


def current_role(username: str) -> str | None:
    """Role as stored now, so a role change takes effect on the next page load."""
    record = load_users().get(username)
    return record.get("role") if record else None


# ---------------------------------------------------------------------------
# Activity log of the dashboard itself (logins, runs, releases, resets)
# ---------------------------------------------------------------------------
def audit(user: str, role: str, action: str, detail: str = "") -> None:
    path = audit_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        new_file = not path.exists()
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=AUDIT_FIELDS)
            if new_file:
                writer.writeheader()
            writer.writerow({"timestamp": now_text(), "user": user, "role": role,
                             "action": action, "detail": " ".join(str(detail).split())[:300]})
    except OSError:
        pass  # the dashboard keeps working even if the log cannot be written


def read_audit(limit: int = 200) -> list[dict]:
    path = audit_file()
    if not path.exists():
        return []
    try:
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    except OSError:
        return []
    return rows[-limit:][::-1]


# ---------------------------------------------------------------------------
# Terminal commands
# ---------------------------------------------------------------------------
def _ask_password() -> str:
    while True:
        first = getpass.getpass("Password > ")
        second = getpass.getpass("Repeat password > ")
        problem = password_problem(first, second)
        if not problem:
            return first
        print(problem)


def _cli(args: list[str]) -> int:
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    command = args[0]
    if command == "create-admin":
        username = input("Username > ").strip().lower()
        problem = username_problem(username)
        if problem:
            print(problem)
            return 1
        name = input("Display name (shown in the staff log) > ").strip()
        ok, message = create_user(username, name, "admin", _ask_password())
        print(message)
        if ok:
            audit(username, "admin", "ACCOUNT_CREATED", "first admin created in the terminal")
        return 0 if ok else 1
    if command == "reset-password" and len(args) == 2:
        if args[1] not in load_users():
            print("Account not found.")
            return 1
        ok, message = set_password(args[1], _ask_password())
        print(message)
        if ok:
            audit("terminal", "admin", "PASSWORD_RESET", f"password reset for {args[1]} in the terminal")
        return 0 if ok else 1
    if command == "list":
        users = load_users()
        if not users:
            print("No accounts yet. Run  venv/bin/python xguard_auth.py create-admin")
        for name, u in sorted(users.items()):
            print(f"{name:<20}{ROLE_TEXT.get(u.get('role'), '?'):<10}{u.get('name', '')}")
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))

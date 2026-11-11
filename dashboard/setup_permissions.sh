#!/usr/bin/env bash
# One time setup, lets the XGuard dashboard run just the three backend scripts
# with sudo and no password. Nothing else is granted. Run it once with sudo.
#   sudo bash setup_permissions.sh
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run with sudo:  sudo bash setup_permissions.sh"
  exit 1
fi

# The normal user who will run the dashboard (the one who called sudo)
RUN_USER="${SUDO_USER:-$(logname 2>/dev/null || echo kali)}"
FYP_DIR="$(cd "$(dirname "$0")/../fyp" 2>/dev/null && pwd || true)"
if [ -z "$FYP_DIR" ] || [ ! -d "$FYP_DIR" ]; then
  FYP_DIR="/home/$RUN_USER/fyp"
fi
VENV_PY="$FYP_DIR/venv/bin/python"

echo "User            $RUN_USER"
echo "Main system     $FYP_DIR"
echo "Python          $VENV_PY"

if [ ! -x "$VENV_PY" ]; then
  echo "Could not find the virtual environment Python at $VENV_PY"
  echo "Check that the main system is in $FYP_DIR, then run this again."
  exit 1
fi

CONTROLLER="$FYP_DIR/ids_controller.py"
UNBLOCK="$FYP_DIR/unblock_ip.py"
RESET="$FYP_DIR/reset_demo.py"
for f in "$CONTROLLER" "$UNBLOCK" "$RESET"; do
  if [ ! -f "$f" ]; then
    echo "Missing backend script: $f"
    exit 1
  fi
done

SUDO_FILE="/etc/sudoers.d/xguard-dashboard"
TMP_FILE="$(mktemp)"
cat > "$TMP_FILE" <<RULES
# Added by the XGuard dashboard setup. Lets $RUN_USER run only these three
# backend scripts with the project's venv Python, with no password. Remove
# this file to revoke:  sudo rm $SUDO_FILE
$RUN_USER ALL=(root) NOPASSWD: $VENV_PY -u $CONTROLLER *
$RUN_USER ALL=(root) NOPASSWD: $VENV_PY -u $UNBLOCK *
$RUN_USER ALL=(root) NOPASSWD: $VENV_PY -u $RESET *
RULES

# Check the file is valid before installing it, a broken sudoers file is dangerous
if visudo -cf "$TMP_FILE" >/dev/null 2>&1; then
  install -m 0440 "$TMP_FILE" "$SUDO_FILE"
  rm -f "$TMP_FILE"
  echo
  echo "Done. The dashboard can now run detection, release addresses and reset the demo."
  echo "Only these three scripts are allowed, nothing else."
else
  echo "The generated sudoers rule failed its safety check, so nothing was changed."
  rm -f "$TMP_FILE"
  exit 1
fi

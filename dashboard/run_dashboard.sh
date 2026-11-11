#!/usr/bin/env bash
# Start the XGuard IDS dashboard (read only). Stop it with Ctrl+C.
cd "$(dirname "$0")" || exit 1
source venv/bin/activate
exec streamlit run app.py

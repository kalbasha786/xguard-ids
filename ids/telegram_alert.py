# telegram_alert.py
# Sends alert messages to the staff Telegram chat.
# The bot token and chat ID are read from config/telegram.json,
# so they never appear in the code or in screenshots of it.
# Run this file directly to send a test message.

import json
import os

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config", "telegram.json")


def load_config():
    with open(CONFIG_FILE, encoding="utf-8") as f:
        config = json.load(f)
    return config["bot_token"].strip(), str(config["chat_id"]).strip()


def send_telegram(text):
    # Returns True if Telegram accepted the message, False otherwise
    token, chat_id = load_config()
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        response = requests.post(url, data={"chat_id": chat_id, "text": text}, timeout=10)
    except requests.RequestException as error:
        # Only the error type is printed, so the token is never shown
        print("Telegram could not be reached,", type(error).__name__)
        return False
    if response.ok and response.json().get("ok", False):
        return True
    print("Telegram refused the message, status", response.status_code)
    return False


if __name__ == "__main__":
    if send_telegram("Test from telegram_alert.py, the settings file works"):
        print("Test message sent, check your phone")
    else:
        print("Test message failed, check the token and chat ID in", CONFIG_FILE)

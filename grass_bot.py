# grass_bot.py

import os
import json
import time
import base64
import requests
import schedule
import traceback
import random
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==========================
# RESTORE ENCRYPTED FILES FROM ENV
# ==========================
def restore_file_from_env(var_name, filename):
    b64_data = os.environ.get(var_name)
    if b64_data:
        try:
            decoded = base64.b64decode(b64_data)
            with open(filename, "wb") as f:
                f.write(decoded)
            print(f"✅ Restored: {filename}")
        except Exception as e:
            print(f"❌ Error decoding {var_name}: {e}")
    else:
        print(f"⚠️ Environment variable {var_name} not found.")

# Restore encrypted files at runtime (Railway safe)
restore_file_from_env("AES_KEY_B64", "aes_key.bin")
restore_file_from_env("ACCOUNT1_B64", "account1.enc")
restore_file_from_env("ACCOUNT2_B64", "account2.enc")

# ==========================
# CONFIGURATION
# ==========================

API_BASE_URL = "https://api.getgrass.io"

PRIMARY_PROXY = {"address": "216.229.112.25", "port": 8080}
BACKUP_PROXY = {"address": "43.153.69.25", "port": 13001}

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# ==========================
# DECRYPT ENCRYPTED ACCOUNT
# ==========================
def decrypt_credentials(file_path):
    with open("aes_key.bin", "rb") as f:
        key = f.read()
    with open(file_path, "rb") as f:
        data = f.read()
        nonce, encrypted = data[:12], data[12:]
    aesgcm = AESGCM(key)
    creds = json.loads(aesgcm.decrypt(nonce, encrypted, None).decode())
    return creds["email"], creds["password"]

# ==========================
# SESSION & AUTH
# ==========================
def get_session(proxy):
    s = requests.Session()
    s.headers.update({
        "User-Agent": "GrassBot/1.0",
        "Content-Type": "application/json"
    })
    s.proxies = {
        "http": f"http://{proxy['address']}:{proxy['port']}",
        "https": f"http://{proxy['address']}:{proxy['port']}"
    }
    return s

def authenticate(session, email, password):
    try:
        r = session.post(f"{API_BASE_URL}/auth/login", json={"email": email, "password": password}, timeout=15)
        if r.status_code == 200:
            print("✅ Authenticated.")
            return r.json().get("token")
        print(f"❌ Auth failed: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"❌ Auth error: {e}")
    return None

# ==========================
# POINT TRACKING
# ==========================
def fetch_points(session, token):
    try:
        r = session.get(f"{API_BASE_URL}/user/points", headers={"Authorization": f"Bearer {token}"}, timeout=15)
        if r.status_code == 200:
            points = r.json().get("points")
            print(f"💰 Points: {points}")
            return points
        print(f"❌ Points fetch failed: {r.status_code}")
    except Exception as e:
        print(f"❌ Points error: {e}")
    return None

# ==========================
# FARMING SIMULATOR
# ==========================
def start_farming(session, token, duration=300):
    print(f"🌱 Farming for {duration} seconds...")
    time.sleep(duration)
    return True

# ==========================
# TELEGRAM NOTIFICATION
# ==========================
def send_telegram_notification(token, chat_id, message, proxy):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        r = requests.post(url, json={"chat_id": chat_id, "text": message}, proxies={
            "http": f"http://{proxy['address']}:{proxy['port']}",
            "https": f"http://{proxy['address']}:{proxy['port']}"
        }, timeout=10)
        if r.status_code == 200:
            print("📩 Telegram sent.")
        else:
            print(f"❌ Telegram error: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"❌ Telegram failed: {e}")

# ==========================
# SINGLE BOT RUN
# ==========================
def run_grass_bot(email, password):
    for proxy in [PRIMARY_PROXY, BACKUP_PROXY]:
        session = get_session(proxy)
        token = authenticate(session, email, password)
        if token:
            before = fetch_points(session, token)
            if start_farming(session, token):
                after = fetch_points(session, token)
                earned = (after or 0) - (before or 0)
                msg = f"✅ {email}\nPoints earned: {earned}\nTotal: {after}"
                send_telegram_notification(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, msg, proxy)
            return
    print(f"⚠️ {email} - Could not authenticate on any proxy.")

# ==========================
# MULTI-ACCOUNT ROTATION
# ==========================
def rotate_accounts():
    with open("accounts.json") as f:
        accounts = json.load(f)
    for path in accounts:
        print(f"\n🔁 Account: {path}")
        email, password = decrypt_credentials(path)
        run_grass_bot(email, password)
        time.sleep(random.randint(60, 180))  # 1-3 minute pause between accounts

# ==========================
# RANDOM DAILY RUN LOOP
# ==========================
def schedule_next_run():
    delay = random.randint(82800, 90000)  # 23–25 hours
    print(f"\n🕒 Next run in {delay//3600}h {(delay%3600)//60}m")
    time.sleep(delay)
    try:
        rotate_accounts()
    except Exception:
        traceback.print_exc()
        print("🔁 Retrying in 1 min...")
        time.sleep(60)
        rotate_accounts()
    schedule_next_run()

schedule_next_run()

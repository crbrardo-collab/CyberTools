import os
from datetime import datetime, timezone
import random
import time
import requests
from dotenv import load_dotenv

# Explicitly load .env from the current working directory
load_dotenv(override=True)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Safety validation to catch missing .env files
if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError(
        "Missing Supabase credentials! Check that your .env file exists and contains SUPABASE_URL and SUPABASE_KEY."
    )

# Supabase REST API endpoint
API_ENDPOINT = f"{SUPABASE_URL.rstrip('/')}/rest/v1/endpoint_logs"

HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=minimal"
}

EVENT_TYPES = [
    (4688, "Process Creation", {"process": "powershell.exe", "parent": "cmd.exe", "user": "SYSTEM"}),
    (4624, "Successful Logon", {"logon_type": 3, "ip_address": "192.168.1.15", "user": "Admin"}),
    (1102, "Audit Log Cleared", {"user": "SYSTEM", "status": "Suspicious Activity"}),
    (4625, "Failed Logon", {"logon_type": 3, "ip_address": "182.48.80.240", "user": "root"})
]

def generate_telemetry():
    print("SOC Agent Started. Pushing telemetry to Supabase SIEM...")
    while True:
        event_id, desc, details = random.choice(EVENT_TYPES)
        
        payload = {
            "hostname": "DESKTOP-SOC-01",
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details
        }
        
        try:
            res = requests.post(API_ENDPOINT, headers=HEADERS, json=payload)
            if res.status_code == 201:
                print(f"[+] Successfully sent: EID {event_id} ({desc})")
            else:
                print(f"[-] Database rejected log. Error {res.status_code}: {res.text}")
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            
        time.sleep(4)

if __name__ == "__main__":
    generate_telemetry()
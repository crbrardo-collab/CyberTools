import requests
import time
import random
from datetime import datetime
import os
from dotenv import load_dotenv

# --- CONFIGURATION ---
# Replace these with the exact URL and Publishable Key from your secrets.toml
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# The Supabase REST API endpoint for your specific table
API_ENDPOINT = f"{SUPABASE_URL}/rest/v1/endpoint_logs"

# Supabase requires both the apikey and Authorization headers for REST POSTs
HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=minimal" 
}

# --- SIMULATOR LOGIC ---
EVENT_TYPES = [
    (4688, "Process Creation", {"process": "powershell.exe", "parent": "cmd.exe", "user": "SYSTEM"}),
    (4624, "Successful Logon", {"logon_type": 3, "ip_address": "192.168.1.15", "user": "Admin"}),
    (1102, "Audit Log Cleared", {"user": "SYSTEM", "status": "Suspicious Activity"}),
    (4625, "Failed Logon", {"logon_type": 3, "ip_address": "182.48.80.240", "user": "root"})
]

def generate_telemetry():
    print("🛡️ SOC Agent Started. Pushing telemetry to Supabase SIEM...")
    while True:
        # Pick a random Windows event to simulate live endpoint activity
        event_id, desc, details = random.choice(EVENT_TYPES)
        
        payload = {
            "hostname": "DESKTOP-SOC-01",
            "event_id": event_id,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details
        }
        
        try:
            # POST the json directly to the database
            res = requests.post(API_ENDPOINT, headers=HEADERS, json=payload)
            
            # 201 Created is the standard HTTP success code for database inserts
            if res.status_code == 201:
                print(f"[+] Successfully sent: EID {event_id} ({desc})")
            else:
                print(f"[-] Database rejected log. Error {res.status_code}: {res.text}")
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            
        # Wait 4 seconds before triggering the next event
        time.sleep(4)

if __name__ == "__main__":
    generate_telemetry()
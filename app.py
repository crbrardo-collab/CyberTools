import streamlit as st
import json
import os
import re
import requests
import pandas as pd
import tempfile
import time
import socket
import hashlib
from datetime import datetime, timedelta
from evtx import PyEvtxParser
from fpdf import FPDF

# ==============================================================================
# 1. PAGE CONFIGURATION & ACCESS CONTROL
# ==============================================================================
st.set_page_config(page_title="SOC Triage & Forensics Tool", layout="wide")

APP_PASSWORD = st.secrets["APP_PASSWORD"]

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    st.title("🔒 Access Restricted")
    st.write("Please authenticate to access the SOC Triage & Forensics Tool.")
    pwd_input = st.text_input("Password", type="password")
    if st.button("Login"):
        if pwd_input == APP_PASSWORD:
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("Incorrect password.")
    st.stop()

# ==============================================================================
# 2. CONSTANTS & ATT&CK MAPPINGS
# ==============================================================================
COMMON_EVENT_DESCRIPTIONS = {
    "1102": "Audit Log Was Cleared",
    "4624": "Account Successfully Logged On",
    "4625": "Account Failed to Log On",
    "4634": "Account Logged Off",
    "4648": "Logon Attempted Using Explicit Credentials",
    "4672": "Special Privileges Assigned to New Logon (Admin)",
    "4688": "New Process Created",
    "4689": "Process Terminated",
    "4697": "Service Was Installed on the System",
    "4698": "Scheduled Task Was Created",
    "4103": "Module Logging (PowerShell Pipeline Execution)",
    "4104": "Script Block Logging (PowerShell Code Executed)",
    "1": "Sysmon: Process Creation",
    "3": "Sysmon: Network Connection",
    "11": "Sysmon: FileCreate",
    "22": "Sysmon: DNS Query"
}

MITRE_MAPPING = {
    "1102": "Defense Evasion (T1070: Indicator Removal)",
    "4624": "Initial Access / Persistence (T1078: Valid Accounts)",
    "4688": "Execution (TA0002)",
    "4697": "Privilege Escalation / Persistence (T1543.003: Windows Service)",
    "4698": "Execution / Persistence (T1053: Scheduled Task)",
    "4103": "Execution (T1059.001: PowerShell)",
    "4104": "Execution (T1059.001: PowerShell)",
    "1": "Execution (TA0002)",
    "3": "Command and Control (TA0011)",
    "22": "Command and Control (T1071.004: DNS)"
}

# ==============================================================================
# 3. HELPER FUNCTIONS
# ==============================================================================
def convert_to_pht(utc_time_str):
    if not utc_time_str or utc_time_str == "N/A":
        return "N/A"
    try:
        clean_str = str(utc_time_str).replace("Z", "").replace("T", " ")
        if "." in clean_str:
            main_part, frac = clean_str.split(".", 1)
            clean_str = f"{main_part}.{frac[:6]}"
            dt_obj = datetime.strptime(clean_str, "%Y-%m-%d %H:%M:%S.%f")
        else:
            dt_obj = datetime.strptime(clean_str, "%Y-%m-%d %H:%M:%S")
        pht_obj = dt_obj + timedelta(hours=8)
        return pht_obj.strftime("%Y-%m-%d %H:%M:%S PHT")
    except Exception:
        return f"{utc_time_str} (Raw)"

def extract_event_details(event_data):
    if not event_data:
        return "No additional details"
    data_dict = {}
    if isinstance(event_data, dict):
        if "Data" in event_data:
            data_items = event_data["Data"]
            if isinstance(data_items, list):
                for item in data_items:
                    if isinstance(item, dict):
                        key = item.get("@Name") or item.get("#attributes", {}).get("Name", "Data")
                        data_dict[str(key)] = str(item.get("#text", ""))
            elif isinstance(data_items, dict):
                data_dict = data_items
        else:
            data_dict = event_data
            
    extracted = [f"{k}: {str(v).replace(chr(10), ' ').replace(chr(13), '').strip()}" 
                 for k, v in data_dict.items() if v and str(v).strip() != "-"]
    return " | ".join(extracted) if extracted else "No specific metadata extracted"

def identify_input(user_input):
    cleaned = user_input.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", cleaned):
        return "ip"
    elif re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", cleaned):
        return "hash"
    elif re.match(r"^(http|https)://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/.*)?$", cleaned.lower()):
        return "url"
    elif re.match(r"^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$", cleaned):
        return "domain"
    return "unknown"

def unshorten_url(url):
    try:
        res = requests.head(url, allow_redirects=True, timeout=5)
        return res.url
    except Exception:
        return url

def calculate_file_hashes(file_bytes):
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha1_hash = hashlib.sha1(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    return {"MD5": md5_hash, "SHA1": sha1_hash, "SHA256": sha256_hash}

# ==============================================================================
# 4. API INTEGRATION ENGINE
# ==============================================================================
def query_abuseipdb(ip, api_key):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": api_key}
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
        res = requests.get(url, headers=headers, params=params, timeout=10)
        res.raise_for_status()
        data = res.json()["data"]
        return {"Score": data.get('abuseConfidenceScore', 0), "ISP": data.get('isp', 'N/A')}
    except Exception as e:
        return {"Score": "Error", "ISP": str(e)}

def query_virustotal(target, target_type, api_key):
    try:
        import base64
        if target_type == "ip":
            endpoint = f"ip_addresses/{target}"
        elif target_type == "domain":
            endpoint = f"domains/{target}"
        elif target_type == "url":
            b64_url = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            endpoint = f"urls/{b64_url}"
        else:
            endpoint = f"files/{target}"
            
        url = f"https://www.virustotal.com/api/v3/{endpoint}"
        headers = {"x-apikey": api_key}
        res = requests.get(url, headers=headers, timeout=15)
        
        if res.status_code == 404:
            return {"Malicious": 0, "Suspicious": 0, "Vendors": "Not found in database", "Detections": []}
        if res.status_code == 429:
            return {"Malicious": "Rate Limited", "Suspicious": "-", "Vendors": "API Quota Exceeded", "Detections": []}
            
        res.raise_for_status()
        attributes = res.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})
        
        detections = []
        for vendor, details in sorted(results.items()):
            category = details.get("category", "")
            if category in ["malicious", "suspicious"]:
                detections.append({
                    "Security Vendor": vendor,
                    "Verdict": category.capitalize(),
                    "Detection": details.get("result") or category
                })
        
        vendors_str = ", ".join([f"{d['Security Vendor']}: {d['Detection']}" for d in detections]) if detections else "Clean"
        return {
            "Malicious": stats.get('malicious', 0),
            "Suspicious": stats.get('suspicious', 0),
            "Vendors": vendors_str,
            "Detections": detections
        }
    except Exception as e:
        return {"Malicious": "Error", "Suspicious": "Error", "Vendors": str(e), "Detections": []}

def render_virustotal_results(vt_data):
    with st.container(border=True):
        st.markdown("### VirusTotal Results")
        col1, col2 = st.columns(2)
        col1.metric("Malicious", vt_data["Malicious"])
        col2.metric("Suspicious", vt_data["Suspicious"])
        
        detections = vt_data.get("Detections", [])
        if detections:
            st.markdown(f'<span style="background-color:#ff4b4b; color:white; padding:4px 8px; border-radius:4px; font-weight:bold;">🚨 Flagged by {len(detections)} vendor(s)</span><br><br>', unsafe_allow_html=True)
            with st.expander("🔎 View Vendor Detection Breakdown", expanded=True):
                det_df = pd.DataFrame(detections)
                st.dataframe(det_df, use_container_width=True, hide_index=True)
        elif vt_data["Malicious"] in ["Error", "Rate Limited"]:
            st.warning(vt_data["Vendors"])
        else:
            st.markdown('<span style="background-color:#00c853; color:white; padding:4px 8px; border-radius:4px; font-weight:bold;">✅ Clean across all engines</span><br><br>', unsafe_allow_html=True)

def scan_urlscan_io(url, api_key):
    try:
        submit_url = "https://urlscan.io/api/v1/scan/"
        headers = {"API-Key": api_key, "Content-Type": "application/json"}
        # Changed to 'unlisted' to avoid public quota restrictions on top domains
        data = {"url": url, "visibility": "unlisted"} 
        
        res = requests.post(submit_url, headers=headers, json=data, timeout=15)
        
        # Capture the EXACT error message from urlscan instead of a generic 400 error
        if res.status_code != 200:
            try:
                error_msg = res.json().get("message", res.text)
            except:
                error_msg = res.text
            return {"uuid": None, "report": None, "error": f"Code {res.status_code}: {error_msg}"}
            
        result_data = res.json()
        return {"uuid": result_data.get("uuid"), "report": result_data.get("result"), "error": None}
    except Exception as e:
        return {"uuid": None, "report": None, "error": str(e)}

def query_alienvault_otx(indicator, target_type, api_key):
    try:
        otx_type_map = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}
        otx_type = otx_type_map.get(target_type)
        if not otx_type:
            return {"error": "Unsupported OTX type"}

        headers = {"X-OTX-API-KEY": api_key}
        base_url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}"
        
        # INCREASED TIMEOUT TO 30 SECONDS
        gen_res = requests.get(f"{base_url}/general", headers=headers, timeout=60)
        gen_res.raise_for_status()
        gen_data = gen_res.json()
        
        pdns_data = {}
        if otx_type in ["IPv4", "domain"]:
            # INCREASED TIMEOUT TO 30 SECONDS
            pdns_res = requests.get(f"{base_url}/passive_dns", headers=headers, timeout=60)
            if pdns_res.status_code == 200:
                pdns_data = pdns_res.json()

        pulses = gen_data.get("pulse_info", {}).get("pulses", [])
        passive_dns = pdns_data.get("passive_dns", [])
        
        return {
            "pulse_count": gen_data.get("pulse_info", {}).get("count", 0),
            "pulses": [{"name": p.get("name"), "author": p.get("author_name"), "tags": p.get("tags", [])} for p in pulses],
            "passive_dns": [{"hostname": r.get("hostname"), "address": r.get("address"), "last": r.get("last")} for r in passive_dns[:15]], 
            "error": None
        }
    except Exception as e:
        return {"error": str(e)}

def render_otx_results(otx_data):
    if not otx_data or otx_data.get("error"):
        st.warning(f"AlienVault OTX Warning: {otx_data.get('error', 'No data returned')}")
        return

    with st.container(border=True):
        st.markdown("### 👽 AlienVault OTX (Threat Context)")
        st.metric("Associated APT Pulses (Campaigns)", otx_data.get("pulse_count", 0))
        
        if otx_data.get("pulses"):
            st.markdown("**Recent Threat Campaigns:**")
            for p in otx_data["pulses"][:5]: 
                tags = ", ".join(p["tags"]) if p["tags"] else "None"
                st.write(f"- **{p['name']}** (by *{p['author']}*) | Tags: `{tags}`")
        
        if otx_data.get("passive_dns"):
            with st.expander("🌍 View Passive DNS History", expanded=False):
                st.dataframe(pd.DataFrame(otx_data["passive_dns"]), use_container_width=True, hide_index=True)

# ==============================================================================
# 5. PDF REPORT GENERATOR
# ==============================================================================
def generate_pdf(report_data, evtx_df):
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # 1. Executive Summary
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, '1. Executive Summary', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S PHT')}", ln=True)
    pdf.multi_cell(0, 6, "Automated forensic summary compiling network intelligence, endpoint log telemetry, and MITRE ATT&CK mappings to guide triage and response decisions.")
    pdf.ln(4)

    # 2. Direct Indicator Telemetry & Threat Context
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, '2. Direct Indicator Telemetry & Threat Context', ln=True)
    pdf.set_font('Helvetica', '', 10)
    
    if not report_data["single_iocs"]:
        pdf.cell(0, 6, "No direct indicators were queried.", ln=True)
    else:
        for item in report_data["single_iocs"]:
            pdf.set_font('Helvetica', 'B', 10)
            
            # Safely truncate massive URLs or Hashes so FPDF doesn't crash
            safe_indicator = item['Indicator']
            if len(safe_indicator) > 70:
                safe_indicator = safe_indicator[:67] + "..."
                
            pdf.multi_cell(0, 6, f"Target: {safe_indicator} ({item['Type']})")
            pdf.set_font('Helvetica', '', 10)
            
            vt_hits = item.get('Malicious', 'N/A')
            otx_count = item.get('OTX_Pulses', 0)
            otx_camps = item.get('OTX_Campaigns', 'None')
            
            pdf.multi_cell(0, 6, f"VirusTotal Malicious Detections: {vt_hits}\nAlienVault OTX Associated Campaigns: {otx_count}")
            if otx_count > 0 and otx_camps != "None":
                pdf.multi_cell(0, 6, f"Top Threat Campaigns: {otx_camps}")
            
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 6, f"Queried: {item['Timestamp']}", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
    pdf.ln(4)

    # 3. Bulk Indicator Assessment
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, '3. Bulk Indicator Assessment', ln=True)
    pdf.set_font('Helvetica', '', 10)
    if not report_data["bulk_summary"]:
        pdf.cell(0, 6, "No bulk processing executed.", ln=True)
    else:
        b_data = report_data["bulk_summary"]
        pdf.cell(0, 6, f"Total IOCs Evaluated: {b_data['total_scanned']}", ln=True)
        pdf.cell(0, 6, f"Malicious Entities Flagged: {b_data['malicious_found']}", ln=True)
    pdf.ln(4)

    # 4. Endpoint Telemetry & MITRE ATT&CK Breakdown
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, '4. Endpoint Telemetry & MITRE ATT&CK Breakdown', ln=True)
    pdf.set_font('Helvetica', '', 10)
    if evtx_df is None:
        pdf.cell(0, 6, "No EVTX files were parsed.", ln=True)
    else:
        pdf.cell(0, 6, f"Total Processed Records: {len(evtx_df)}", ln=True)
        pdf.ln(2)
        mitre_events = evtx_df[evtx_df["MITRE ATT&CK"] != "None"]
        if mitre_events.empty:
            pdf.cell(0, 6, "No specific ATT&CK tactics matched queried Event IDs.", ln=True)
        else:
            pdf.set_font('Helvetica', 'I', 10)
            pdf.cell(0, 6, "Observed MITRE Tactics & Techniques:", ln=True)
            pdf.set_font('Helvetica', '', 10)
            mitre_summary = mitre_events["MITRE ATT&CK"].value_counts()
            for tactic, count in mitre_summary.items():
                pdf.multi_cell(0, 6, f"[*] {tactic} - {count} instance(s)")
    pdf.ln(4)

    # 5. Prescribed Incident Response Actions
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, '5. Prescribed Incident Response Actions', ln=True)
    pdf.set_font('Helvetica', '', 10)
    recs = (
        "- Perimeter Containment: Block malicious IPs/Domains on perimeter firewalls and sinkhole at DNS resolvers.\n"
        "- Host Isolation: Segregate endpoints exhibiting unapproved Process Execution (EID 4688) or Service Creation (EID 4697).\n"
        "- Identity Remediation: Enforce credential rotation for identities associated with abnormal Explicit Logons (EID 4648).\n"
        "- EDR Sweep: Hunt across all endpoints for hashes and artifacts discovered during this investigation."
    )
    pdf.multi_cell(0, 6, recs)
    return pdf.output()
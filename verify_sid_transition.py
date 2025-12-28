import sys
import os
import polars as pl
import datetime
import json
from pathlib import Path

# Setup path
tool_path = Path(r"c:\Users\user\.gemini\antigravity\scratch\SkiaHelios\tools")
sys.path.append(str(tool_path))

try:
    from SH_HekateWeaver import HekateWeaver
    print("[+] Import Successful.")
except Exception as e:
    print(f"[!] Import Failed: {e}")
    sys.exit(1)

def check_sid_affinity():
    print("\n[*] Testing SID Affinity Mapping (v15.35)...")
    
    # 1. Mock Session Map (hercules_sessions.json)
    # User U1 was active from 10:00 to 11:00.
    sessions = [{
        "SID": "S-1-5-21-12345-USER",
        "Start": "2025-01-01T10:00:00",
        "End": "2025-01-01T11:00:00",
        "Privileges": []
    }]
    
    json_path = Path(r"c:\Users\user\.gemini\antigravity\scratch\SkiaHelios\hercules_sessions.json")
    with open(json_path, "w") as f:
        json.dump(sessions, f)
    print(f"[+] Mock Session Map created at {json_path}")
    
    # 2. Mock Events
    events = [
        # Case A: Privilege Escalation (Time 10:30, Active User U1, File Owner SYSTEM)
        {
            "Time": "2025-01-01T10:30:00",
            "dt_obj": datetime.datetime(2025, 1, 1, 10, 30, 0),
            "Category": "DROP",
            "Summary": "File Created: Rootkit.sys",
            "Detail": "Mode: Birth | Reason: FILE_CREATE",
            "Owner_SID": "S-1-5-18", # SYSTEM
            "Criticality": 50
        },
        # Case B: Normal (Time 10:30, Active User U1, File Owner U1)
        {
            "Time": "2025-01-01T10:30:00",
            "dt_obj": datetime.datetime(2025, 1, 1, 10, 30, 0),
            "Category": "DROP",
            "Summary": "File Created: UserDoc.docx",
            "Detail": "Mode: Birth | Reason: FILE_CREATE",
            "Owner_SID": "S-1-5-21-12345-USER", # Matches Active Session
            "Criticality": 10
        },
        # Case C: Orphan Origin (Time 12:00, No Active Session)
        {
            "Time": "2025-01-01T12:00:00",
            "dt_obj": datetime.datetime(2025, 1, 1, 12, 0, 0),
            "Category": "DROP",
            "Summary": "File Created: GhostJob.exe",
            "Detail": "Mode: Birth | Reason: FILE_CREATE",
            "Owner_SID": "S-1-5-18",
            "Criticality": 50
        }
    ]
    
    # 3. Running Correlation
    # We need to instantiate HekateWeaver just to access the method, 
    # but the method is stateless regarding 'self' except for reading the JSON file.
    # So we can pass None for csvs.
    weaver = HekateWeaver(None) 
    weaver.correlate_identity(events)
    
    # 4. Verify Results
    print("\n[Results Analysis]")
    
    # Check A
    if "[PRIVILEGE ESCALATION]" in events[0]["Summary"]:
        print("[SUCCESS] Case A: Escalation Detected (SYSTEM file during User Session).")
    else:
        print(f"[FAIL] Case A: Escalation Missed. Summary: {events[0]['Summary']}")

    # Check B
    if "[PRIVILEGE ESCALATION]" not in events[1]["Summary"] and "[ORPHAN ORIGIN]" not in events[1]["Summary"]:
        print("[SUCCESS] Case B: Normal event untouched.")
    else:
        print(f"[FAIL] Case B: False Positive. Summary: {events[1]['Summary']}")

    # Check C
    if "[ORPHAN ORIGIN]" in events[2]["Summary"]:
        print("[SUCCESS] Case C: Orphan Origin Detected (No active session).")
    else:
        print(f"[FAIL] Case C: Orphan Missed. Summary: {events[2]['Summary']}")

if __name__ == "__main__":
    check_sid_affinity()

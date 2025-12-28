import sys
import os
import polars as pl
import datetime
from pathlib import Path

# Setup path
tool_path = Path(r"c:\Users\user\.gemini\antigravity\scratch\SkiaHelios\tools")
sys.path.append(str(tool_path))

try:
    from SH_HekateWeaver import NemesisTracer
    print("[+] Import Successful.")
except Exception as e:
    print(f"[!] Import Failed: {e}")
    sys.exit(1)

def noise_mock(path):
    return "System32" in str(path)

def check_execution_origin():
    print("\n[*] Testing Execution-First Origin Trace (v15.31)...")
    
    # 1. Mock Execution Event (Event ID 4104)
    # The log says "Powershell.cmd" was executed at 12:00:00.
    exec_time = datetime.datetime(2025, 1, 1, 12, 0, 0)
    exec_events = [{
        'Category': 'INIT',
        'Time': '2025-01-01T12:00:00',
        'dt_obj': exec_time,
        'Keywords': ['C:\\Users\\Public\\Powershell.cmd'] 
    }]
    
    # 2. Mock USN (File System Layer at Execution Time)
    # At 12:00:00, "Powershell.cmd" (ID 999) was active.
    # Also "noise.exe" was active at same time.
    df_usn = pl.DataFrame({
        "EntryNumber": [999, 888], 
        "FileName": ["Powershell.cmd", "noise.exe"],
        "ParentPath": ["C:\\Users\\Public", "C:\\Windows\\System32"],
        "Reason": ["FILE_Create", "FILE_CLOSE"],
        "Timestamp_UTC": [
            "2025-01-01 12:00:00.000000", 
            "2025-01-01 12:00:00.000000"
        ]
    })
    
    # 3. Mock MFT (History)
    # ID 999 was originally created as "Malware.bat" at 10:00:00.
    df_mft = pl.DataFrame({
        "EntryNumber": [999],
        "FileName": ["Malware.bat"],
        "ParentPath": ["C:\\Users\\Public"],
        "si_dt": ["2025-01-01 10:00:00"]
    })
    
    # Init Tracer
    tracer = NemesisTracer(df_mft, df_usn, noise_validator=noise_mock)
    
    print(f"[*] Input Execution Event: {exec_events[0]['Time']} | {exec_events[0]['Keywords']}")
    results = tracer.trace_origin_by_execution(exec_events)
    
    print(f"[*] Results Found: {len(results)}")
    found_origin = False
    found_noise = False
    
    for r in results:
        print(f"  - {r['Time']} | {r['Summary']} | {r['Detail']}")
        # Summary format: "Lifecycle Trace [Activity]: Malware.bat" or similar.
        # Check if the filename is present in the summary.
        if "Malware.bat" in r['Summary']: 
            found_origin = True
        if "noise.exe" in r['Summary']: 
            found_noise = True
        
    if found_origin:
        print("[SUCCESS] Found 'Malware.bat' (Birth) via Execution Match.")
    else:
        print("[FAIL] Failed to trace origin to 'Malware.bat'.")
        
    if not found_noise:
        print("[SUCCESS] Noise correctly filtered.")
    else:
        print("[FAIL] Noise NOT filtered.")

if __name__ == "__main__":
    check_execution_origin()

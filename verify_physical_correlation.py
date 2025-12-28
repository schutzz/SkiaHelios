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

def check_physical_correlation():
    print("\n[*] Testing Physical Time Correlation (Time-Based Chain Recovery)...")
    
    # 1. Mock Execution Event (e.g., PowerShell 4104)
    # The log says "Script Block Executed" at 12:00:00, but doesn't know the file's true name/origin.
    exec_time = datetime.datetime(2025, 1, 1, 12, 0, 0)
    exec_events = [{
        'Category': 'INIT',
        'Time': '2025-01-01T12:00:00',
        'dt_obj': exec_time,
        'Keywords': ['UnknownScript'] # Filename matching would fail here
    }]
    
    # 2. Mock USN (File System Layer)
    # At 12:00:00, ID 999 was active (CLOSE, READ, etc.). Name is real name "Payload.bat"
    df_usn = pl.DataFrame({
        "EntryNumber": [999, 888], # 888 is noise
        "FileName": ["Payload.bat", "calc.exe"],
        "ParentPath": ["C:\\Temp", "C:\\Windows\\System32"],
        "Reason": ["FILE_CLOSE", "FILE_CLOSE"],
        "Timestamp_UTC": [
            "2025-01-01 12:00:00.000000", # Exact match
            "2025-01-01 12:00:01.000000"  # Match but noise
        ]
    })
    
    # 3. Mock MFT (History)
    # ID 999 was created way back at 10:00:00.
    df_mft = pl.DataFrame({
        "EntryNumber": [999],
        "FileName": ["Payload.bat"],
        "ParentPath": ["C:\\Temp"],
        "si_dt": ["2025-01-01 10:00:00"]
    })
    
    # Init Tracer with Noise Validator
    tracer = NemesisTracer(df_mft, df_usn, noise_validator=noise_mock)
    
    print(f"[*] Input Execution Event: {exec_events[0]['Time']} (Targeting +/- 2s window)")
    results = tracer.trace_by_physical_time(exec_events)
    
    print(f"[*] Results Found: {len(results)}")
    found_payload = False
    found_noise = False
    
    for r in results:
        print(f"  - {r['Time']} | {r['Summary']} | {r['Detail']}")
        if "Payload.bat" in r['Summary']: found_payload = True
        if "calc.exe" in r['Summary']: found_noise = True
        
    if found_payload:
        print("[SUCCESS] Correlated Execution Time -> Physical ID 999 -> Payload.bat History.")
    else:
        print("[FAIL] Failed to correlate Payload.bat.")
        
    if not found_noise:
        print("[SUCCESS] Noise (calc.exe in System32) was correctly filtered.")
    else:
        print("[FAIL] Noise was NOT filtered.")

if __name__ == "__main__":
    check_physical_correlation()

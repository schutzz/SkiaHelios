import sys
import os
import polars as pl
from pathlib import Path

# Setup path to import the tool
tool_path = Path(r"c:\Users\user\.gemini\antigravity\scratch\SkiaHelios\tools")
sys.path.append(str(tool_path))

try:
    print("[*] Importing SH_HekateWeaver...")
    from SH_HekateWeaver import HekateWeaver, NemesisTracer
    print("[+] Import Successful.")
except Exception as e:
    print(f"[!] Import Failed: {e}")
    sys.exit(1)

def check_noise_whitelist():
    print("\n[*] Checking _is_file_noise Whitelist...")
    hw = HekateWeaver(None) # Mock init
    
    # Test Cases
    cases = [
        ("malicious.ps1", False),
        ("microsoft.powershell.cmd", False), # Whitelisted now
        ("auditpol.exe", True), # Admin tool (Noise)
        ("random.tmp", False), # .tmp is explicitly whitelisted as not noise for seeding
    ]
    
    for fn, expected in cases:
        is_noise = hw._is_file_noise(fn, "C:\\Windows\\System32\\auditpol.exe" if "auditpol" in fn else "")
        status = "PASS" if is_noise == expected else "FAIL"
        print(f"  - {fn}: Expected={expected}, Got={is_noise} [{status}]")

def check_multicolumn_harvesting():
    print("\n[*] Checking Multi-Column ID Harvesting...")
    
    # Mock MFT with Target_FileName (Simulating Link file reference or similar custom column)
    df_mft = pl.DataFrame({
        "EntryNumber": [111],
        "FileName": ["Normal.txt"],
        "Target_FileName": ["Attack.ps1"], # Seed hidden here
        "ParentPath": ["C:\\Temp"],
        "si_dt": ["2025-01-05 12:00:00"]   
    })
    
    df_usn = pl.DataFrame({
         "EntryNumber": [111],
         "Ghost_FileName": ["Normal.txt"],
         "Reason": ["FILE_CREATE"],
         "Ghost_Time_Hint": ["2025-01-05 12:00:00"]
    })

    tracer = NemesisTracer(df_mft, df_usn)
    
    seed = ["Attack.ps1"]
    print(f"[*] Tracing seed: {seed}")
    results = tracer.trace_lifecycle(seed)
    
    found_details = [r['Detail'] for r in results]
    found_summaries = [r['Summary'] for r in results]
    for s, d in zip(found_summaries, found_details): print(f"  - {s} | {d}")
    
    # Check if we found the result via Target_FileName (which implies we found 'Normal.txt' despite seed being 'Attack.ps1')
    if len(results) > 0 and any("Normal.txt" in s for s in found_summaries):
        print("[SUCCESS] Found 'Normal.txt' via Target_FileName match ('Attack.ps1').")
    else:
        print("[FAIL] Failed to find associated file.")
        
    if any("Seed Matching" in d for d in found_details): 
        print("[SUCCESS] 'Seed Matching' mode confirmed in Detail.")
    else:
        print(f"[FAIL] 'Seed Matching' mode NOT found in Details: {found_details}")

if __name__ == "__main__":
    check_noise_whitelist()
    check_multicolumn_harvesting()

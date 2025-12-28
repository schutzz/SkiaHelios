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

def check_structure():
    print("\n[*] Checking Class Structure...")
    if hasattr(HekateWeaver, "_is_file_noise"):
        print("[+] HekateWeaver._is_file_noise method FOUND on class.")
    else:
        print("[-] HekateWeaver._is_file_noise method MISSING! (CRITICAL)")

    # Check for duplicates in source text
    try:
        with open(tool_path / "SH_HekateWeaver.py", "r", encoding="utf-8") as f:
            content = f.read()
            count = content.count("def _is_file_noise(")
            if count == 1:
                print(f"[SUCCESS] _is_file_noise defined exactly once (Count: {count}).")
            else:
                print(f"[FAIL] _is_file_noise defined {count} times! (Should be 1)")
    except Exception as e:
        print(f"[!] Source read failed: {e}")

def check_nemesis_identity_shift():
    print("\n[*] Testing NemesisTracer v15.25 (Identity Shift & ID Robustness)...")
    
    # Mock Data for Rename: OldName.exe -> NewName.bin
    # ID: 12345
    
    # MFT: Has the current file (NewName.bin) with ID 12345
    # Using 'FileReferenceNumber' to test robust column handling (priority list check)
    df_mft = pl.DataFrame({
        "FileReferenceNumber": [12345], 
        "FileName": ["NewName.bin"], 
        "ParentPath": ["C:\\Temp"], 
        "si_dt": ["2025-01-05 10:00:00"]
    })
    
    # USN: Has the rename event flow
    df_usn = pl.DataFrame({
        "EntryNumber": [12345, 12345], 
        "Ghost_FileName": ["OldName.exe", "NewName.bin"],
        "OldFileName": ["OldName.exe", "OldName.exe"], # Simulating USN population
        "Reason": ["RENAME_OLD_NAME", "RENAME_NEW_NAME"],
        "ParentPath": ["C:\\Temp", "C:\\Temp"],
        "Ghost_Time_Hint": ["2025-01-05 09:59:59", "2025-01-05 10:00:00"]
    })
    
    tracer = NemesisTracer(df_mft, df_usn)
    
    try:
        # Search for the *Original* name
        seed = ["OldName.exe"]
        print(f"[*] Tracing seed: {seed}")
        results = tracer.trace_lifecycle(seed)
        
        print(f"[+] trace_lifecycle executed. Hits: {len(results)}")
        
        found_summaries = [r['Summary'] for r in results]
        
        for s in found_summaries:
            print(f"  - {s}")

        # Validation 1: Identity Shift Detection
        # We expect a summary like: "Lifecycle Trace [Identity Shift]: OldName.exe -> NewName.bin"
        shift_detected = any("Identity Shift" in s and "OldName.exe -> NewName.bin" in s for s in found_summaries)
        
        if shift_detected:
            print("[SUCCESS] 'Identity Shift' visualization confirmed.")
        else:
            print("[FAIL] 'Identity Shift' summary NOT found.")

        # Validation 2: Robust Column Handling
        if any("MFT" in r['Source'] for r in results):
             print("[SUCCESS] Robust ID handling confirmed (MFT record found).")

    except Exception as e:
        print(f"[!] Crashed: {e}")
        import traceback
        traceback.print_exc()

def check_old_filename_harvesting():
    print("\n[*] Testing Phase A: OldFileName Harvesting (v15.26)...")
    # Scenario: User only knows "Secret.doc" (Seed), but it was renamed to "Public.pdf"
    # The USN record for the rename has OldFileName="Secret.doc" and Ghost_FileName="Public.pdf"
    
    df_usn = pl.DataFrame({
        "EntryNumber": [777],
        "Ghost_FileName": ["Public.pdf"],
        "OldFileName": ["Secret.doc"],
        "Reason": ["RENAME_NEW_NAME"],
        "ParentPath": ["C:\\Docs"],
        "Ghost_Time_Hint": ["2025-01-01 10:00:00"]
    })
    
    # MFT only knows the new name "Public.pdf"
    df_mft = pl.DataFrame({
        "EntryNumber": [777],
        "FileName": ["Public.pdf"],
        "ParentPath": ["C:\\Docs"],
        "si_dt": ["2025-01-01 10:05:00"]
    })
    
    tracer = NemesisTracer(df_mft, df_usn)
    
    seed = ["Secret.doc"]
    print(f"[*] Tracing seed: {seed}")
    results = tracer.trace_lifecycle(seed)
    
    found_summaries = [r['Summary'] for r in results]
    for s in found_summaries: print(f"  - {s}")
    
    # Needs to find the USN record via OldFileName match
    if any("Secret.doc" in s for s in found_summaries):
        print("[SUCCESS] Found record via OldFileName match!")
    else:
        print("[FAIL] Failed to find record via OldFileName.")
        
    # Needs to chain to MFT via ID 777
    if any("Public.pdf" in s for s in found_summaries) and any("MFT" in r['Source'] for r in results):
        print("[SUCCESS] Chained to MFT record via ID 777!")
    else:
        print("[FAIL] Failed to chain to MFT record.")

if __name__ == "__main__":
    check_structure()
    check_nemesis_identity_shift()
    check_old_filename_harvesting()
    print("\n[*] Final Integrity Check Complete.")

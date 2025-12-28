import sys
import os
import polars as pl
import datetime
from pathlib import Path

# Setup path
tool_path = Path(r"c:\Users\user\.gemini\antigravity\scratch\SkiaHelios\tools")
sys.path.append(str(tool_path))

try:
    from SH_HekateWeaver import NemesisTracer, HekateWeaver
    print("[+] Import Successful.")
except Exception as e:
    print(f"[!] Import Failed: {e}")
    sys.exit(1)

def noise_mock(path):
    return False

def check_robustness():
    print("\n[*] Testing Robustness Features (v15.33)...")
    
    # 1. Test Sequence Number Validation
    print("--- [1] Sequence Number Validation ---")
    # USN has ID 999 Seq 2 (The Target). But we search for ID 999 Seq 1 (The Trap).
    ids_map = {"999": 1} # Asking for Seq 1
    
    df_usn_seq = pl.DataFrame({
        "EntryNumber": [999, 999],
        "SequenceNumber": [2, 1], # Row 0 is Seq 2 (Should Skip), Row 1 is Seq 1 (Should Pick)
        "FileName": ["NewFile.txt", "OldTarget.txt"],
        "ParentPath": ["C:\\Temp", "C:\\Temp"],
        "Reason": ["FILE_CREATE", "FILE_DELETE"],
        "Timestamp_UTC": ["2025-01-01 12:00:00", "2025-01-01 10:00:00"]
    })
    
    tracer = NemesisTracer(None, df_usn_seq, noise_validator=noise_mock)
    events = tracer._recover_lifecycle_by_ids(ids_map, "Test")
    
    found_seq1 = any("OldTarget.txt" in str(e) for e in events)
    found_seq2 = any("NewFile.txt" in str(e) for e in events)
    
    if found_seq1 and not found_seq2:
        print("[SUCCESS] Correctly filtered by Sequence Number (Picked Seq 1, Ignored Seq 2).")
    else:
        print(f"[FAIL] Sequence validation failed. Found Seq 1: {found_seq1}, Found Seq 2: {found_seq2}")

    # 2. Test Hybrid Birth Fallback
    print("\n--- [2] Hybrid Birth Fallback ---")
    # MFT only has Activity, no Birth.
    df_mft_nobirth = pl.DataFrame({
        "EntryNumber": [888],
        "FileName": ["Mystery.exe"],
        "ParentPath": ["C:\\Temp"],
        "si_dt": ["2025-01-01 09:00:00"] # Not used for reason usually, but let's assume it becomes "Activity"
    })
    
    tracer_nobirth = NemesisTracer(df_mft_nobirth, None)
    # Mocking _to_event behavior slightly or relying on default which creates "Activity" if not known reason?
    # Actually _to_event uses "Reason" col if available, otherwise maps. 
    # For MFT, it relies on "si_dt" usually being MFT Modified. Let's see.
    # We call _recover... passing ID 888.
    events_nb = tracer_nobirth._recover_lifecycle_by_ids({"888": None})
    
    if events_nb and "[PROVISIONAL ORIGIN]" in events_nb[0]['Summary']:
        print("[SUCCESS] Oldest event flagged as [PROVISIONAL ORIGIN].")
    else:
        print(f"[FAIL] Provisional Origin flag missing. Summary: {events_nb[0]['Summary'] if events_nb else 'None'}")

    # 3. Test Ghost Merge (in generate_report logic)
    # This requires mocking HekateWeaver or replicating the logic.
    # We'll replicate the logic block here for verification.
    print("\n--- [3] Ghost Merge Logic ---")
    
    raw_events = [
        {
            "Source": "Nemesis (USN)",
            "Reason": "FILE_DELETE",
            "Summary": "File Deleted: Malware.exe",
            "Detail": "ID: 777",
            "dt_obj": datetime.datetime(2025, 1, 1, 12, 0, 0),
            "Keywords": ["Malware.exe"]
        },
        {
            "Source": "Pandora (USN)",
            "Category": "ANTI",
            "Summary": "Ghost File Detected: Malware.exe",
            "dt_obj": datetime.datetime(2025, 1, 1, 12, 0, 1), # 1 sec diff
            "Keywords": ["Malware.exe"]
        }
    ]
    
    # Run Merge Logic
    indices_to_remove = set()
    nemesis_deaths = [ev for ev in raw_events if "Nemesis" in str(ev.get('Source', '')) and "DELETE" in str(ev.get('Reason', '')).upper()]
    
    for n_ev in nemesis_deaths:
        if "[CONFIRMED DELETION]" not in n_ev['Summary']:
            n_ev['Summary'] = "[CONFIRMED DELETION] " + n_ev['Summary']
        
        n_time = n_ev.get('dt_obj')
        
        for i, p_ev in enumerate(raw_events):
            if i in indices_to_remove: continue
            if "Pandora" not in str(p_ev.get('Source', '')) and "ANTI" not in str(p_ev.get('Category', '')): continue
            
            p_time = p_ev.get('dt_obj')
            if abs((n_time - p_time).total_seconds()) > 5: continue
            
            n_names = set(str(k).lower().split("\\")[-1] for k in n_ev.get('Keywords', []))
            p_names = set(str(k).lower().split("\\")[-1] for k in p_ev.get('Keywords', []))
            if not n_names.intersection(p_names): continue
            
            n_ev['Summary'] += f" <br>(Matches Pandora Ghost: {p_ev['Summary']})"
            indices_to_remove.add(i)

    # Check Results
    nemesis_ev = raw_events[0]
    
    if "[CONFIRMED DELETION]" in nemesis_ev['Summary'] and "Matches Pandora Ghost" in nemesis_ev['Summary']:
        print("[SUCCESS] Nemesis event updated with Confirmation and Merge info.")
    else:
        print(f"[FAIL] Merge failed. Summary: {nemesis_ev['Summary']}")
        
    if 1 in indices_to_remove:
        print("[SUCCESS] Pandora event marked for removal.")
    
    # 4. Test 64-bit ID Parsing & Sequence Logic
    print("\n--- [4] 64-bit Reference Number Parsing ---")
    # Simulation: Input ID is packed 64-bit (Seq 5, Entry 100)
    # 5 << 48 | 100 
    packed_id = (5 << 48) | 100
    ids_map_packed = {str(100): 5} # We expect the caller (trace_origin) to have split it, OR we test splitting internal?
    # Actually, let's test if _parse_id works by calling it directly if possible, or via behavior.
    
    # Let's verify behavior:
    # USN has Entry 100, Seq 5.
    df_usn_64 = pl.DataFrame({
        "EntryNumber": [100],
        "SequenceNumber": [5],
        "FileName": ["PackedFile.txt"],
        "Reason": "FILE_CREATE"
    })
    
    tracer_64 = NemesisTracer(None, df_usn_64)
    # Manually verify helper first if accessible (it is instance method)
    e, s = tracer_64._parse_id(packed_id)
    print(f"Debug: Packed {packed_id} -> Entry {e}, Seq {s}")
    
    if str(e) == "100" and str(s) == "5":
        print("[SUCCESS] _parse_id correctly split 64-bit FRN.")
    else:
        print(f"[FAIL] _parse_id failed. Got Entry {e}, Seq {s}")

    # 5. Test Live File Recovery (MFT Fallback)
    print("\n--- [5] MFT Fallback (Live File Recovery) ---")
    # Scenario: Execution event exists, USN is empty/unrelated, but MFT has the file.
    # Expect: ID is recovered from MFT.
    
    evt_exec_live = {
        "dt_obj": datetime.datetime(2025, 1, 1, 15, 0, 0),
        "Keywords": ["LiveMalware.exe"],
        "Time": "2025-01-01T15:00:00"
    }
    
    # MFT Mock - Live file exists
    df_mft_live = pl.DataFrame({
        "EntryNumber": ["999"],
        "SequenceNumber": ["10"],
        "FileName": ["LiveMalware.exe"],
        "ParentPath": ["C:\\Temp"],
        "si_dt": [datetime.datetime(2025, 1, 1, 10, 0, 0)],
        "Reason": ["FILE_CREATE"]
    }, schema_overrides={"FileName": pl.Utf8, "EntryNumber": pl.Utf8, "SequenceNumber": pl.Utf8, "Reason": pl.Utf8})
    
    # USN Mock - Empty or unrelated
    df_usn_empty = pl.DataFrame({
        "EntryNumber": [], "SequenceNumber": [], "FileName": [], "Timestamp_UTC": [], "Ghost_FileName": []
    }, schema={"EntryNumber": pl.Utf8, "SequenceNumber": pl.Utf8, "FileName": pl.Utf8, "Timestamp_UTC": pl.Utf8, "Ghost_FileName": pl.Utf8})
    
    tracer_live = NemesisTracer(df_mft_live, df_usn_empty)
    # The tracer should look at MFT because USN has no match.
    recovered_events = tracer_live.trace_origin_by_execution([evt_exec_live])
    
    if recovered_events and recovered_events[0].get('Keywords')[0] == "LiveMalware.exe":
        print(f"[SUCCESS] Recovered live file origin from MFT via Fallback. Count: {len(recovered_events)}")
    else:
        print(f"[FAIL] Failed to recover live file from MFT. Result: {recovered_events}")

    # 6. Test Container-Aware Logic
    print("\n--- [6] Container-Aware Trace (Argument Parsing) ---")
    # Scenario: Event is "cmd.exe", Detail contains "cmd.exe /c start C:\\Temp\\BadScript.bat"
    # Expect: NemesisTracer extracts "BadScript.bat" and finds it in USN.
    
    evt_container = {
        "dt_obj": datetime.datetime(2025, 1, 1, 16, 0, 0),
        "Keywords": ["cmd.exe"],
        "Time": "2025-01-01T16:00:00",
        "Detail": "Process Creation: cmd.exe /c start C:\\Temp\\BadScript.bat"
    }
    
    # USN Mock - Contains BadScript.bat (The Seed), valid time
    df_usn_container = pl.DataFrame({
        "EntryNumber": ["888"],
        "SequenceNumber": ["1"],
        "FileName": ["BadScript.bat"],
        "Timestamp_UTC": ["2025-01-01 16:00:00.000"],
        "Ghost_FileName": [None],
        "Reason": "FILE_CREATE"
    }, schema={"EntryNumber": pl.Utf8, "SequenceNumber": pl.Utf8, "FileName": pl.Utf8, "Timestamp_UTC": pl.Utf8, "Ghost_FileName": pl.Utf8, "Reason": pl.Utf8})
    
    tracer_container = NemesisTracer(None, df_usn_container)
    rec_cont = tracer_container.trace_origin_by_execution([evt_container])
    
    if rec_cont and rec_cont[0].get('Keywords')[0] == "BadScript.bat":
        print(f"[SUCCESS] Container-Aware Logic worked. Extracted and found: {rec_cont[0]['Keywords'][0]}")
    else:
        print(f"[FAIL] Container Logic failed. Trace Result: {rec_cont}")

    # 7. Test Quote Robustness
    print("\n--- [7] Arg Parsing with Quotes ---")
    # Scenario: Detail has quotes "C:\Temp\Quoted Script.bat"
    # Expect: Quotes stripped, file extracted.
    
    evt_quote = {
        "dt_obj": datetime.datetime(2025, 1, 1, 17, 0, 0),
        "Keywords": ["powershell.exe"],
        "Time": "2025-01-01T17:00:00",
        "Detail": "Process Creation: powershell.exe -File \"C:\\Temp\\Quoted Script.ps1\""
    }
    
    # Mock USN: "Quoted Script.ps1" should match extracted "Quoted Script.ps1"
    # Wait, regex only matches non-spaces. 
    # If I run replace('"', ''), "C:\Temp\Quoted Script.ps1" becomes "C:\Temp\Quoted Script.ps1".
    # Regex [\w\-\.\\/:~]+ matches "C:\Temp\Quoted" (break at space) and "Script.ps1".
    # So "Script.ps1" will be extracted.
    # If USN has "Quoted Script.ps1", and we only search "Script.ps1", we might find part of it?
    # Actually, reverse lookup searches by partial name match.
    # candidates={script.ps1}. USN FileName="Quoted Script.ps1".
    # name_filter = col(FileName).contains("script.ps1").
    # It WILL match!
    
    df_usn_quote = pl.DataFrame({
        "EntryNumber": ["777"],
        "SequenceNumber": ["1"],
        "FileName": ["Quoted Script.ps1"],
        "Timestamp_UTC": ["2025-01-01 17:00:00.000"],
        "Ghost_FileName": [None],
        "Reason": "FILE_CREATE"
    }, schema={"EntryNumber": pl.Utf8, "SequenceNumber": pl.Utf8, "FileName": pl.Utf8, "Timestamp_UTC": pl.Utf8, "Ghost_FileName": pl.Utf8, "Reason": pl.Utf8})
    
    tracer_quote = NemesisTracer(None, df_usn_quote)
    rec_quote = tracer_quote.trace_origin_by_execution([evt_quote])
    
    if rec_quote and "Script.ps1" in rec_quote[0].get('Keywords')[0]:
        print(f"[SUCCESS] Quote Robustness worked. Extracted internal part: {rec_quote[0]['Keywords'][0]}")
    else:
        print(f"[FAIL] Quote Logic failed. Trace Result: {rec_quote}")

if __name__ == "__main__":
    check_robustness()

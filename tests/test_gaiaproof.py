import sys
from pathlib import Path
import polars as pl

# Fix path to allow importing modules from parent directory
sys.path.append(str(Path(__file__).parent.parent))

from tools.SH_Gaiaproof import GaiaproofEngine

def perform_verification():
    print("[*] Starting SH_Gaiaproof Verification...")
    
    # 1. Setup Mock Data
    test_dir = Path("tests/temp_gaiaproof")
    test_dir.mkdir(parents=True, exist_ok=True)
    
    srum_path = test_dir / "Mock_Srum.csv"
    log_path = test_dir / "Mock_Log.csv"
    
    # Create Mock SRUM (Continuous Activity)
    # 10:00 - 10:30, entry every minute
    srum_data = {
        "TimeStamp": [f"2025-01-01 10:{i:02d}:00" for i in range(30)],
        "BytesReceived": [1000] * 30,
        "BytesSent": [500] * 30
    }
    pl.DataFrame(srum_data).write_csv(srum_path)
    print(f"    [+] Created Mock SRUM: {srum_path}")
    
    # Create Mock Log (Wiped Gap)
    # 10:00-10:10 OK, 10:10-10:20 MISSING, 10:20-10:30 OK
    log_times = [f"2025-01-01 10:{i:02d}:00" for i in range(10)] + \
                [f"2025-01-01 10:{i:02d}:00" for i in range(20, 30)]
    log_data = {
        "TimeCreated": log_times
    }
    pl.DataFrame(log_data).write_csv(log_path)
    print(f"    [+] Created Mock Log (Gap 10:10-10:20): {log_path}")
    
    # 2. Run Engine (Gap Detection)
    engine = GaiaproofEngine()
    
    pol_df = engine.normalize_srum(str(srum_path))
    log_df = engine.normalize_logs(str(log_path))
    
    if pol_df is None or log_df is None:
        print("    [!] Failed to normalize mock data")
        return False
    
    report = engine.detect_unnatural_blanks(pol_df, log_df)
    
    # 3. Assertions
    if report.height > 0:
        print(f"    [SUCCESS] Detected {report.height} blank windows.")
        # Check if the gap (10:10-10:20) is covered
        # Window start usually floors, so 10:10, 10:15 should be in there
        gap_starts = report["PoL_Time"].dt.strftime("%H:%M").to_list()
        print(f"    [DEBUG] Gap Windows: {gap_starts}")
        
        if "10:10" in gap_starts or "10:15" in gap_starts:
             print("    [PASS] Gap correctly identified in the wiped interval.")
        else:
             print("    [FAIL] Gap detected but not in expected interval.")
    else:
        print("    [FAIL] No blanks detected (Expected ~2 windows).")

    # 4. Anti-Forensics Verification (Mock)
    af_log_path = test_dir / "Mock_AF_Log.csv"
    af_data = {
        "TimeCreated": ["2025-01-01 12:00:00"],
        "FileName": ["sdelete64.exe"]
    }
    pl.DataFrame(af_data).write_csv(af_log_path)
    
    raw_af = pl.read_csv(af_log_path)
    hits = engine.scan_antiforensics_tools(raw_af, "Events")
    
    if hits.height > 0:
        print(f"    [SUCCESS] Anti-Forensics Tool Detected: {hits['FileName'][0]}")
    else:
        print("    [FAIL] SDelete not detected.")

    # 5. MFT/USN Gap Verification
    print("[*] Verifying USN Gaps...")
    usn_path = test_dir / "Mock_Usn.csv"
    
    # Sequence Gap: SQN 100 -> 200,000 (Jump > 100k)
    # Temporal Gap: Activity in SRUM at 10:00-10:30, but USN has nothing at 10:15
    # USN Data:
    # 10:05: SQN 100
    # 10:25: SQN 200100 (Big Jump + Time Gap)
    
    usn_data = {
        "Timestamp": ["2025-01-01 10:05:00", "2025-01-01 10:25:00"],
        "UpdateSequenceNumber": [100, 200100],
        "FileName": ["file1.txt", "file2.txt"],
        "Reason": ["DATA_EXTEND", "DATA_EXTEND"]
    }
    pl.DataFrame(usn_data).write_csv(usn_path)
    
    # Test Sequence Gaps
    seq_gaps = engine.detect_usn_sequence_gaps(str(usn_path))
    if seq_gaps.height > 0:
        print(f"    [SUCCESS] Detected {seq_gaps.height} USN Sequence Gaps.")
    else:
        print("    [FAIL] USN Sequence Gap NOT detected.")
        
    # Test FS Silence
    # SRUM is continuous 10:00-10:30. USN has nothing 10:05-10:25.
    # Should detect silence windows in between.
    srum_df = engine.normalize_srum(str(srum_path))
    usn_df = engine.normalize_usn(str(usn_path))
    
    if srum_df is not None and usn_df is not None:
        fs_silence = engine.detect_artifact_time_gaps(srum_df, usn_df)
        if fs_silence.height > 0:
             print(f"    [SUCCESS] Detected {fs_silence.height} FS Silence windows.")
        else:
             print("    [FAIL] FS Silence NOT detected.")

    # Cleanup
    import shutil
    try:
        shutil.rmtree(test_dir)
    except: pass
    
if __name__ == "__main__":
    perform_verification()

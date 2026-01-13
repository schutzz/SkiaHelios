import polars as pl
import sys
import os
from datetime import datetime

# Adjust path to import tools
sys.path.append(os.getcwd())
# Ensure Polars uses ASCII for tables to avoid cp932 errors
pl.Config.set_tbl_formatting("ASCII_FULL")

from tools.SH_ChronosSift import ChronosEngine

def test_chronos_logic():
    print("[*] Testing Chronos Logic Refinement...")
    
    # Initialize Engine
    engine = ChronosEngine(tolerance=10.0)
    
    # Create Mock Data
    # 1. Update Pattern: MFT (SI) is NEWER than FileName (FN) by more than 60s
    #    e.g. Created 10:00, Modified/Access triggers MFT update to 10:05.
    #    Wait, standard Timestomp logic compares SI Creation vs FN Creation.
    #    If SI Creation is NEWER than FN Creation -> It means file was "Created" later than its name implies? 
    #    Usually:
    #      Copying a file: SI Creation = Now, FN Creation = Original Time.
    #      SI (Now) > FN (Old) -> Diff positive (if diff = FN - SI, negative)
    #    Let's check code:
    #      diff_sec = fn_dt - si_dt
    #      
    #    Case A: Update/Movement (Scanning Logic)
    #      SI (12:00) > FN (10:00). diff = 10:00 - 12:00 = -2hours.
    #      diff < -60. -> INFO_UPDATE_PATTERN (Score 0) -> CORRECT.
    
    #    Case B: Backdating (Timestomp)
    #      Attacker changes SI Creation to 09:00. FN Creation remains 10:00 (or is also changed? usually FN is harder to change or left as artifact)
    #      If SI (09:00) < FN (10:00). diff = 10:00 - 09:00 = +1 hour.
    #      diff > tolerance (10s). -> TIMESTOMP_BACKDATE (Score 200). -> CORRECT.
    
    data = {
        "FileName": ["update_storm.exe", "timestomp_attack.exe", "normal.exe"],
        "SI_CreationTime_Raw": ["2023-01-01 12:00:00", "2023-01-01 09:00:00", "2023-01-01 10:00:00"], # SI
        "FileName_Created_Raw": ["2023-01-01 10:00:00", "2023-01-01 10:00:00", "2023-01-01 10:00:00"], # FN
        "Threat_Score": [0, 0, 0],
        "Threat_Tag": ["", "", ""]
    }
    
    df = pl.DataFrame(data)
    
    # Pre-processing similar to analyze()
    df = df.with_columns([
        pl.col("SI_CreationTime_Raw").str.to_datetime().alias("si_dt"),
        pl.col("FileName_Created_Raw").str.to_datetime().alias("fn_dt"),
        pl.lit("").alias("Anomaly_Time"),
        pl.lit("").alias("Anomaly_Extreme")
    ])
    
    # Run Detection
    result = engine._detect_mft_timestomp(df.lazy()).collect()
    
    # Verify Results
    print("\n[Results]")
    print(result.select(["FileName", "Anomaly_Time", "Chronos_Score"]))
    
    # Assertions
    # 1. Update Storm
    row_update = result.filter(pl.col("FileName") == "update_storm.exe").row(0, named=True)
    assert row_update["Anomaly_Time"] == "INFO_UPDATE_PATTERN", f"Failed Update: {row_update['Anomaly_Time']}"
    assert row_update["Chronos_Score"] == 0, f"Failed Update Score: {row_update['Chronos_Score']}"
    
    # 2. Timestomp
    row_ts = result.filter(pl.col("FileName") == "timestomp_attack.exe").row(0, named=True)
    assert row_ts["Anomaly_Time"] == "TIMESTOMP_BACKDATE", f"Failed Backdate: {row_ts['Anomaly_Time']}"
    assert row_ts["Chronos_Score"] == 200, f"Failed Backdate Score: {row_ts['Chronos_Score']}"

    # 3. Normal
    row_norm = result.filter(pl.col("FileName") == "normal.exe").row(0, named=True)
    assert row_norm["Anomaly_Time"] == "", f"Failed Normal: {row_norm['Anomaly_Time']}"
    
    print("\n[SUCCESS] All logic checks passed!")

if __name__ == "__main__":
    test_chronos_logic()

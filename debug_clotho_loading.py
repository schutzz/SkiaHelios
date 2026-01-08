
import polars as pl
from pathlib import Path
import sys

# Mock Clotho loading logic
def test_load():
    csv_path = r"c:\Users\user\.gemini\antigravity\scratch\SkiaHelios\Helios_Output\case1_v56_refined_v3_retry4_20260109_002932\AION_Persistence.csv"
    print(f"[*] Testing load of {csv_path}")
    
    try:
        df = pl.read_csv(csv_path, ignore_errors=True, infer_schema_length=0)
        print(f"[*] Loaded schema: {df.columns}")
        
        # Check specific row
        target = df.filter(pl.col("Target_FileName") == "hacker")
        if target.height > 0:
            print("[*] Found 'hacker' row:")
            row = target.row(0, named=True)
            print(row)
            print(f"[*] Entry_Location value: '{row.get('Entry_Location')}'")
        else:
            print("[-] 'hacker' row not found.")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    test_load()

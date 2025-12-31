import polars as pl
from pathlib import Path
import sys

# ==========================================
#  SH_DataProbe.py
#  Mission: Diagnose the "Janus" Split
# ==========================================

def probe(kape_dir, timeline_path):
    print(f"[*] Probing Data Integrity...")
    
    # 1. Check Registry (Source of Truth)
    print("\n>>> [1] Checking Registry ProfileList artifacts...")
    reg_files = list(Path(kape_dir).rglob("*ProfileList*.csv")) + \
                list(Path(kape_dir).rglob("*SOFTWARE*.csv"))
    
    if not reg_files:
        print("[!] No ProfileList/SOFTWARE CSVs found!")
    
    for p in reg_files:
        try:
            df = pl.read_csv(p, ignore_errors=True, infer_schema_length=0)
            # Look for the specific SID
            target_sid = "S-1-5-21-1131578693-187085323-3983606359-1001"
            
            # Print columns to check naming
            print(f"  > File: {p.name}")
            print(f"  > Columns: {df.columns}")
            
            # Simple grep-like search in the dataframe
            found = False
            for col in df.columns:
                # Check if SID exists in any column
                matches = df.filter(pl.col(col).str.contains(target_sid))
                if not matches.is_empty():
                    print(f"  [!] FOUND Target SID in column '{col}'!")
                    print(matches.head(1))
                    found = True
            
            if not found:
                print("  [-] Target SID not found in this file.")
                
        except Exception as e:
            print(f"  [!] Error reading {p.name}: {e}")

    # 2. Check Master Timeline (The Symptom)
    print(f"\n>>> [2] Checking Master Timeline: {timeline_path}")
    try:
        df = pl.read_csv(timeline_path, ignore_errors=True, infer_schema_length=0)
        print(f"  > Columns: {df.columns}")
        
        # Check 'user' rows
        print("\n  [A] Rows with User = 'user':")
        user_rows = df.filter(pl.col("User") == "user")
        if not user_rows.is_empty():
            print(user_rows.select(["User", "Subject_SID", "Source_File", "Artifact_Type"]).head(3))
        else:
            print("  [-] No rows found with User == 'user'")

        # Check SID rows
        target_sid = "S-1-5-21-1131578693-187085323-3983606359-1001"
        print(f"\n  [B] Rows with SID = '{target_sid}':")
        sid_rows = df.filter(pl.col("Subject_SID") == target_sid)
        if not sid_rows.is_empty():
            print(sid_rows.select(["User", "Subject_SID", "Source_File", "Artifact_Type"]).head(3))
        else:
            print("  [-] No rows found with Target SID")

    except Exception as e:
        print(f"  [!] Error reading Timeline: {e}")

if __name__ == "__main__":
    # Hardcoded paths based on your previous logs
    # Adjust if necessary
    KAPE_DIR = r"C:\Temp\Trigger3\out" 
    TIMELINE = r"C:\Temp\Trigger3\out\Helios_Output\Validation20_20251226_131027\Master_Timeline.csv"
    
    # Try to find the latest timeline if the hardcoded one is old
    try:
        base_out = Path(r"C:\Temp\Trigger3\out\Helios_Output")
        latest_dir = sorted([d for d in base_out.iterdir() if d.is_dir()], key=lambda x: x.stat().st_mtime)[-1]
        TIMELINE = str(latest_dir / "Master_Timeline.csv")
        print(f"[*] Targeting latest timeline: {TIMELINE}")
    except:
        pass

    probe(KAPE_DIR, TIMELINE)
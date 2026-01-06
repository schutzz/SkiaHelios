
import polars as pl
import os

def check_file(path, queries):
    if not os.path.exists(path):
        print(f"[-] File not found: {path}")
        return

    print(f"[*] Checking {os.path.basename(path)}...")
    try:
        df = pl.read_csv(path, ignore_errors=True, infer_schema_length=0) 
        # infer_schema_length=0 forces all cols to string to avoid type errors
        
        counts = len(df)
        print(f"    Total rows: {counts}")
        print(f"    Columns: {df.columns}")

        for q in queries:
            print(f"    Searching for '{q}'...")
            # Search in all string columns
            found = False
            for col in df.columns:
                try:
                    # Case insensitive search
                    matches = df.filter(pl.col(col).str.to_lowercase().str.contains(q.lower()))
                    if len(matches) > 0:
                        print(f"    [!] Found {len(matches)} matches in column '{col}':")
                        for row in matches.head(3).rows(named=True):
                            print(f"        {row}")
                        found = True
                except Exception as e:
                    # Ignore columns that can't be string searched
                    pass
            
            if not found:
                print(f"    [-] No matches for '{q}'")

    except Exception as e:
        print(f"[-] Error reading {path}: {e}")

base_dir = r"c:\Users\user\.gemini\antigravity\scratch\SkiaHelios\Helios_Output\DeepLNK_Fix_Test_20260106_151604"
files = ["Hercules_Judged_Timeline.csv", "Master_Timeline.csv"]
queries = ["Kitties", "teamviewer", "pip-7.1.2"]

for f in files:
    check_file(os.path.join(base_dir, f), queries)

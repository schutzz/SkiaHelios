
import polars as pl
import os
import glob

def check_file(path, queries):
    if not os.path.exists(path):
        print(f"[-] File not found: {path}")
        return

    print(f"[*] Checking {os.path.basename(path)}...")
    try:
        # Load only necessary columns if possible, but schema inference is tricky
        df = pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
        
        print(f"    Total rows: {len(df)}")
        
        for q in queries:
            # Case insensitive search in all columns
            found = False
            for col in df.columns:
                try:
                    res = df.filter(pl.col(col).str.to_lowercase().str.contains(q.lower()))
                    if not res.is_empty():
                        print(f"    [!] Found '{q}' in {col} ({len(res)} matches)")
                        print(res.head(1))
                        found = True
                        break # Found in one column is enough for existence check
                except:
                    pass
            if not found:
                print(f"    [-] '{q}' NOT found")

    except Exception as e:
        print(f"[-] Error: {e}")

# Check Master Timeline
base_dir = r"c:\Users\user\.gemini\antigravity\scratch\SkiaHelios\Helios_Output\DeepLNK_Fix_Test_20260106_151604"
master_path = os.path.join(base_dir, "Master_Timeline.csv")
check_file(master_path, ["Kitties", "teamviewer", "pip-7.1.2"])

# Check History CSVs (Input)
history_dir = r"C:\Temp\dfir-case2\out"
print(f"\n[*] Searching for history files in {history_dir}...")
history_files = glob.glob(os.path.join(history_dir, "**", "*History*.csv"), recursive=True)
for hf in history_files:
    check_file(hf, ["pip", "teamviewer", "github"])

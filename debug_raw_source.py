
import polars as pl
import os

def check_file(path, queries):
    if not os.path.exists(path):
        print(f"[-] File not found: {path}")
        return

    print(f"[*] Checking {os.path.basename(path)}...")
    try:
        # Load all as string
        df = pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
        
        print(f"    Total rows: {len(df)}")
        print(f"    Columns: {df.columns}")
        
        for q in queries:
            print(f"    Searching for '{q}'...")
            found = False
            for col in df.columns:
                try:
                    res = df.filter(pl.col(col).str.to_lowercase().str.contains(q.lower()))
                    if not res.is_empty():
                        print(f"    [!] Found '{q}' in column '{col}' ({len(res)} matches)")
                        for row in res.head(1).rows(named=True):
                            print(f"        {row}")
                        found = True
                        break 
                except:
                    pass
            if not found:
                print(f"    [-] '{q}' NOT found")

    except Exception as e:
        print(f"[-] Error: {e}")

# Check LECmd Output (LNKs)
lnk_csv = r"C:\Temp\dfir-case2\out\FileFolderAccess\20260102141635_LECmd_Output.csv"
check_file(lnk_csv, ["Kitties", "teamviewer"])

# Check Browser History
hist_csv = r"C:\Temp\dfir-case2\out\Browser_Artifacts\Browser_History_Chrome_Hunter_Default.csv"
check_file(hist_csv, ["pip", "python", "teamviewer"])

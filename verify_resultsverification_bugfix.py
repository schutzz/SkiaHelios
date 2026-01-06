
import polars as pl
from pathlib import Path
import os
import glob

base_dir = Path("Helios_Output")

# Helper to find latest folder matching pattern
def get_latest(pattern):
    try:
        return sorted(list(base_dir.glob(pattern)))[-1].name
    except: return "N/A"

old_std = "Case2_Std_20260105_162955"
verdict_tri = get_latest("Case2_Verdict_Triage_*")
sieve_tri = get_latest("Case2_Sieve_Triage_*") # Latest run

dirs = {
    "TRI_VERDICT": verdict_tri,
    "TRI_SIEVE": sieve_tri
}

print(f"{'MODE':<10} | {'TOTAL':<10} | {'SYSTEM EVENTS':<15} | {'CHRONOS REPORT?'}")
print("-" * 65)

for tag, dname in dirs.items():
    if dname == "N/A": 
        print(f"{tag:<10} | {'PENDING':<10} | {'-':<15} | -")
        continue

    dpath = base_dir / dname
    herc_path = dpath / "Hercules_Judged_Timeline.csv"
    report_path = dpath / f"Grimoire_{dname}_jp.md"
    
    h_total = "N/A"
    sys_count = "N/A"
    chronos_ok = "NO"

    if herc_path.exists():
        try: 
            df = pl.read_csv(herc_path, ignore_errors=True)
            h_total = df.height
            if "Subject_SID" in df.columns:
                # Count lingering System SIDs
                sys_count = df.filter(pl.col("Subject_SID").str.contains("S-1-5-18")).height
        except: pass
        
    if report_path.exists():
        try:
            content = report_path.read_text(encoding="utf-8")
            if "[CHRONOS]" in content or "TIMESTOMP" in content:
                chronos_ok = "YES"
        except: pass
        
    print(f"{tag:<10} | {str(h_total):<10} | {str(sys_count):<15} | {chronos_ok}")

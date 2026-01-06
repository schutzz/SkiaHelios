
import polars as pl
from pathlib import Path
import os
import glob

base_dir = Path("Helios_Output")

# Helper to find latest folder matching pattern
def get_latest(pattern):
    try:
        return sorted(list(base_dir. glob(pattern)))[-1].name
    except: return "N/A"

old_std = "Case2_Std_20260105_162955"
old_tri = "Case2_Triage_20260105_163036"
new_std = get_latest("Case2_Refined_Std_*")
new_tri = get_latest("Case2_Refined_Triage_*")

dirs = {
    "STD_OLD": old_std,
    "TRI_OLD": old_tri,
    "STD_NEW": new_std,
    "TRI_NEW": new_tri
}

print(f"{'MODE':<10} | {'HERCULES':<10} | {'GHOSTS':<10} | {'TARGETS DETECTED'}")
print("-" * 80)

# Targets to check for in Ghost Report
targets = ["adorable-kitties", "extension_0_52", ".crx", "notifications"]

for tag, dname in dirs.items():
    if dname == "N/A": 
        print(f"{tag:<10} | {'NOT FOUND':<10} | {'-':<10} | -")
        continue

    dpath = base_dir / dname
    herc_path = dpath / "Hercules_Judged_Timeline.csv"
    ghost_path = dpath / "Ghost_Report.csv"
    
    h_count = "N/A"
    g_count = "N/A"
    detected = []
    
    if herc_path.exists():
        try: h_count = pl.read_csv(herc_path, ignore_errors=True).height
        except: pass
        
    if ghost_path.exists():
        try: 
            df_g = pl.read_csv(ghost_path, ignore_errors=True)
            g_count = df_g.height
            if "FileName" in df_g.columns:
                fn = df_g["FileName"].str.to_lowercase()
                pp = df_g["ParentPath"].str.to_lowercase() if "ParentPath" in df_g.columns else pl.lit("")
                
                # Check 1: Kitties LNK
                if fn.str.contains("adorable-kitties").any(): detected.append("LNK_PHISH")
                
                # Check 2: CRX
                if fn.str.contains("extension_0_52").any() or fn.str.ends_with(".crx").any(): detected.append("CRX_MASQ")
                
                # Check 3: Notifications
                if pp.str.contains("notifications").any(): detected.append("NOTIF_TIME")
                
        except: pass
        
    print(f"{tag:<10} | {str(h_count):<10} | {str(g_count):<10} | {detected}")

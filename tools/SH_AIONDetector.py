import polars as pl
import argparse
from pathlib import Path
import sys
import io

# ============================================================
#  SH_AIONDetector v10.11 [Clean Sweep]
#  Fix: Target specific WindowsApps noise (triggerTrees).
# ============================================================

def print_logo():
    print(r"""
        / \
       / _ \     (The Eye of Truth)
      / | | \    "Timestamps are the ultimate evidence."
     /_/   \_\

      [ SH_AIONDetector v10.11 ]
    """)

class AIONEngine:
    def __init__(self, target_dir=None, file_path=None, mft_csv=None):
        self.target_dir = target_dir
        self.file_path = file_path
        self.mft_csv = mft_csv
        self.signatures = {
            "High_Risk": {"keywords": ["powershell", "cmd.exe", "wscript", "mshta", "rundll32", "certutil"], "score": 10},
            "User_Persistence": {"keywords": ["hkey_current_user", "hkcu", "software\\microsoft\\windows\\currentversion\\run"], "score": 9},
            "Suspicious_Path": {"keywords": ["temp", "appdata\\local", "users\\public", "perflogs", "downloads"], "score": 15}, 
            "WMI_Persistence": {"keywords": ["wmi", "eventfilter", "eventconsumer", "binding"], "score": 12},
            "Atomic_Red_Team": {"keywords": ["atomic", "art-", "redteam", "t10"], "score": 15}
        }

    def load_mft(self):
        if self.mft_csv and Path(self.mft_csv).exists():
            df = pl.read_csv(self.mft_csv, ignore_errors=True, infer_schema_length=0)
            cols = df.columns
            if "ParentPath" in cols and "FileName" in cols:
                df = df.with_columns(
                    (pl.col("ParentPath") + "\\" + pl.col("FileName")).alias("Target_Path")
                )
                if "Created0x10" in cols:
                    df = df.with_columns(pl.col("Created0x10").alias("Timestamp_UTC"))
            elif "Target_Path" in cols:
                df = df.with_columns([
                    pl.col("Target_Path").str.extract(r"^(.*)\\([^\\]+)$", 1).alias("ParentPath"),
                    pl.col("Target_Path").str.extract(r"^(.*)\\([^\\]+)$", 2).alias("FileName")
                ])
            return df
        return None

    def hunt_persistence(self, mft_df, suspects_list):
        PERSISTENCE_HOTSPOTS = [r"(?i)Tasks", r"(?i)Startup"]
        RISKY_EXTENSIONS = r"(?i)\.(exe|lnk|bat|ps1|vbs|xml|dll|jar|hta)$"

        if "ParentPath" not in mft_df.columns: return []

        hotspot_filter = pl.col("ParentPath").str.contains("|".join(PERSISTENCE_HOTSPOTS))
        hotspot_files = mft_df.filter(hotspot_filter)
        suspect_files = hotspot_files.filter(pl.col("FileName").str.contains(RISKY_EXTENSIONS))
        
        detected = []

        SAFE_ZONES = [
            "winsxs", "catroot", "windowsapps", "inf", "assembly", 
            "servicing", "microsoft.net", "wbem",
            "system32\\wdi", "microsoft\\diagnosis"
        ]

        if not suspect_files.is_empty():
             for row in suspect_files.iter_rows(named=True):
                path_lower = str(row.get('ParentPath') or "").lower()
                fname_lower = str(row.get('FileName') or "").lower()
                
                if any(z in path_lower for z in SAFE_ZONES): continue
                if "onedrive" in fname_lower: continue

                detected.append({
                    "Last_Executed_Time": row.get("Timestamp_UTC") or row.get("Created0x10"),
                    "AION_Score": 15, 
                    "AION_Tags": "FILE_PERSISTENCE (HOTSPOT)",
                    "Target_FileName": row.get("FileName"),
                    "Entry_Location": row.get("ParentPath"),
                    "Full_Path": row.get("Target_Path") or f"{row.get('ParentPath')}\\{row.get('FileName')}"
                })

        WANTED_FILES = ["Windows_Security_Audit", "win_optimizer.lnk", "SunShadow", "Trigger"]
        
        TRIGGER_BLACKLIST = [
            "msmq-triggers", "vpnconnectiontrigger", "jobtrigger", 
            "sbservicetrigger", "servicetrigger", "trigger.js", 
            "trigger.dat", "etw", "wdi", "box",
            "triggertrees" # [Fix] Added triggerTrees specifically
        ]
        
        for wanted in WANTED_FILES:
            hits = mft_df.filter(pl.col("FileName").str.contains(f"(?i){wanted}"))
            if not hits.is_empty():
                for row in hits.iter_rows(named=True):
                    fname = str(row.get('FileName') or "")
                    path = str(row.get('ParentPath') or "")
                    fname_lower = fname.lower()
                    path_lower = path.lower()

                    if wanted == "Trigger":
                        if any(b in fname_lower for b in TRIGGER_BLACKLIST): continue
                        if any(z in path_lower for z in SAFE_ZONES): continue
                        if "adaptive-expressions" in path_lower: continue # [Fix] Block path context
                        if fname_lower.endswith(".dat") or fname_lower.endswith(".xml"): continue

                    detected.append({
                        "Last_Executed_Time": row.get("Timestamp_UTC") or row.get("Created0x10"),
                        "AION_Score": 20, 
                        "AION_Tags": "NAMED_PERSISTENCE (WANTED)",
                        "Target_FileName": fname,
                        "Entry_Location": path,
                        "Full_Path": row.get("Target_Path") or f"{path}\\{fname}"
                    })
        return detected

    def analyze(self):
        targets = self._find_autoruns_csv()
        df_mft = self.load_mft()
        final_list = []
        suspects_list = set()

        for t in targets:
            df_auto = self.load_csv_robust(str(t))
            if df_auto is None or df_auto.is_empty(): continue
            cols = df_auto.columns
            signer_col = next((c for c in cols if "Signer" in c), None)
            df_str = df_auto.select(pl.all().cast(pl.Utf8))
            
            for row in df_str.iter_rows(named=True):
                row_score = 0
                row_tags = []
                full_text = " ".join([str(v).lower() for v in row.values() if v is not None])
                img_path = str(row.get('Image Path') or "").strip()
                
                is_winsxs = "winsxs" in img_path.lower()
                signer = str(row.get(signer_col) or "") if signer_col else ""
                is_verified = "microsoft" in signer.lower() or "windows" in signer.lower()
                if is_winsxs and is_verified: continue 

                for tag, rule in self.signatures.items():
                    for k in rule['keywords']:
                        if k in full_text:
                            row_score += rule['score']
                            if tag not in row_tags: row_tags.append(tag)
                
                if any(bp in img_path.lower() for bp in ["\\temp\\", "\\downloads\\", "\\public\\"]):
                    row_score += 20 
                    if "Suspicious_Path" not in row_tags: row_tags.append("Suspicious_Path")

                if row_score > 0:
                    fname = str(row.get('Entry') or "").strip()
                    if fname: suspects_list.add(fname)
                    mft_time = None
                    if df_mft is not None and img_path:
                        match = df_mft.filter(pl.col("Target_Path").str.to_lowercase().str.contains(img_path.lower(), literal=True))
                        if not match.is_empty():
                            mft_time = match.get_column("Timestamp_UTC")[0]

                    final_list.append({
                        "Last_Executed_Time": mft_time,
                        "AION_Score": row_score,
                        "AION_Tags": ", ".join(row_tags),
                        "Target_FileName": fname or "Unknown",
                        "Entry_Location": str(row.get('Entry Location') or ""),
                        "Full_Path": img_path,
                    })
        
        if df_mft is not None:
             hotspot_hits = self.hunt_persistence(df_mft, list(suspects_list))
             if hotspot_hits:
                 print(f"[*] AION Deep Scan: Found {len(hotspot_hits)} artifacts in hotspots/wanted lists.")
                 final_list.extend(hotspot_hits)

        if not final_list: return None
        return pl.DataFrame(final_list).sort("AION_Score", descending=True).unique(subset=["Full_Path", "AION_Tags"])

    def _find_autoruns_csv(self):
        if self.file_path and Path(self.file_path).exists(): return [Path(self.file_path)]
        if not self.target_dir: return []
        return list(Path(self.target_dir).rglob("*autoruns*.csv"))

    def load_csv_robust(self, path):
        try:
            with open(path, "rb") as f: raw = f.read()
            enc = "utf-16" if raw.startswith(b'\xff\xfe') else "utf-8"
            content = raw.decode(enc, errors="ignore")
            lines = content.splitlines()
            start = next((i for i, l in enumerate(lines[:30]) if "Entry Location" in l or "Image Path" in l), 0)
            return pl.read_csv(io.StringIO("\n".join(lines[start:])), ignore_errors=True)
        except Exception as e:
            print(f" [!] Load failed {path}: {e}")
            return None

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", help="Artifacts Directory (containing autoruns CSVs)")
    parser.add_argument("--mft", help="Master_Timeline.csv (from Chaos/Chronos)")
    parser.add_argument("-o", "--out", default="Persistence_Report.csv")
    args = parser.parse_args(argv)

    engine = AIONEngine(target_dir=args.dir, mft_csv=args.mft)
    df = engine.analyze()

    if df is not None:
        print(f"\n[+] PERSISTENCE CORRELATED: {len(df)} entries mapped to MFT timeline.")
        df.write_csv(args.out)
    else:
        print("[-] No persistence identified.")

if __name__ == "__main__":
    main()
import polars as pl
import argparse
from pathlib import Path
import sys
import io
import re
import hashlib

# ============================================================
#  SH_AIONDetector v13.3 [Mock & Autoruns Friendly]
#  Mission: Detect Persistence & Calculate Evidence Hash
#  Update: Support for Mock Autoruns.csv & Missing Files
# ============================================================

def print_logo():
    print(r"""
        / \
       / _ \     (The Eye of Truth v13.3)
      / | | \    "No persistence hides forever."
     /_/   \_\

      [ SH_AIONDetector ]
    """)

class AIONEngine:
    def __init__(self, target_dir=None, mft_csv=None, mount_point=None):
        self.target_dir = Path(target_dir) if target_dir else None
        self.mft_csv = mft_csv
        self.mount_point = Path(mount_point) if mount_point else None
        
        self.reg_targets = [
            r"Microsoft\\Windows\\CurrentVersion\\Run",
            r"Microsoft\\Windows\\CurrentVersion\\RunOnce",
            r"Services",
            r"ScheduledTasks"
        ]

        self.safe_paths = [
            r"\\Windows\\WinSxS",
            r"\\Windows\\Servicing",
            r"\\Windows\\SoftwareDistribution",
            r"\\Windows\\CbsTemp",
            r"\\Windows\\Assembly",
            r"\\Windows\\Microsoft.NET\\Framework",
            r"\\Windows\\System32\\DriverStore"
        ]

    def _calculate_file_hash(self, relative_path):
        if not self.mount_point or not relative_path: return "N/A", "N/A"
        clean_path = str(relative_path).lstrip(".\\").lstrip("\\")
        if ":" in clean_path:
            try: clean_path = clean_path.split(":", 1)[1].lstrip("\\")
            except: pass
        full_path = self.mount_point / clean_path
        if not full_path.exists(): return "FILE_NOT_FOUND_ON_MOUNT", "FILE_NOT_FOUND_ON_MOUNT"
        try:
            sha256_hash = hashlib.sha256()
            sha1_hash = hashlib.sha1()
            with open(full_path, "rb") as f:
                for byte_block in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(byte_block)
                    sha1_hash.update(byte_block)
            return sha256_hash.hexdigest(), sha1_hash.hexdigest()
        except: return "HASH_ERROR", "HASH_ERROR"

    def _is_safe_path(self, path_str):
        if not path_str: return False
        path_norm = str(path_str).replace("/", "\\")
        for safe in self.safe_paths:
            if re.search(safe, path_norm, re.IGNORECASE): return True
        return False

    def _is_known_noise(self, filename, path):
        fn = str(filename).lower()
        fp = str(path).lower()
        if re.match(r"(?i)^(amd64|x86|wow64)_", fn): return True
        if fn.endswith((".manifest", ".mum", ".cat")): return True
        if "gac_msil" in fp or "assembly" in fp: return True
        if fn.startswith("system.") and fn.endswith(".dll"): return True
        if "microsoft.build" in fn: return True
        return False

    def hunt_registry_persistence(self):
        print("[*] Phase 1: Scanning Registry Hives (Run/RunOnce/Services/Autoruns)...")
        detected = []
        reg_files = list(self.target_dir.rglob("*Registry*.csv")) + list(self.target_dir.rglob("*RECmd*.csv"))
        
        # [FIX] Explicitly add Autoruns.csv (Common in Sysinternals or Mocks)
        autoruns = list(self.target_dir.rglob("Autoruns.csv"))
        reg_files.extend(autoruns)
        
        if not reg_files: return []

        for reg in reg_files:
            try:
                df = pl.read_csv(reg, ignore_errors=True, infer_schema_length=0)
                cols = df.columns
                
                # Dynamic Column Mapping
                key_col = next((c for c in cols if "Key" in c and "Path" in c), None)
                val_col = next((c for c in cols if "Value" in c and "Name" in c), None)
                data_col = next((c for c in cols if "Value" in c and "Data" in c), None)
                time_col = next((c for c in cols if "Time" in c), None)

                # Map for Mock/Autoruns format
                if "Location" in cols and "Item" in cols and "ImagePath" in cols:
                    key_col = "Location"
                    val_col = "Item"
                    data_col = "ImagePath"
                    time_col = None # Mock Autoruns often lacks timestamp in same row

                if not key_col or not data_col: continue
                
                # Filter logic: Standard Registry vs Autoruns
                if "Location" in cols:
                    hits = df # Autoruns is all relevant
                else:
                    regex_pattern = "|".join([re.escape(k) for k in self.reg_targets])
                    hits = df.filter(pl.col(key_col).str.contains(r"(?i)" + regex_pattern))

                for row in hits.iter_rows(named=True):
                    k_path = str(row.get(key_col, ""))
                    v_name = str(row.get(val_col, ""))
                    v_data = str(row.get(data_col, ""))
                    ts = str(row.get(time_col, "Unknown_Time"))

                    if not v_data or len(v_data) < 3: continue
                    if self._is_safe_path(v_data): continue
                    
                    fname = "Unknown"
                    full_path_candidate = v_data
                    
                    full_path_match = re.search(r'"?([a-zA-Z]:\\[^"]+\.(?:exe|bat|ps1|vbs|dll|sys))"?', v_data, re.IGNORECASE)
                    if full_path_match:
                        full_path_candidate = full_path_match.group(1)
                        fname = full_path_candidate.split("\\")[-1]
                    else:
                         temp_fname = v_data.split("\\")[-1] if "\\" in v_data else v_data
                         fname = temp_fname

                    if self._is_known_noise(fname, v_data): continue
                    if "ctfmon.exe" in fname.lower() or "onedrive.exe" in fname.lower(): continue

                    score = 0
                    tags = []
                    
                    if "RunOnce" in k_path:
                        score += 30; tags.append("REG_RUNONCE")
                    elif "Run" in k_path: 
                        score += 10; tags.append("REG_RUN_KEY")
                    
                    # [FIX] Suspicious keywords in DATA (e.g. powershell command)
                    suspicious_keywords = ["powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "encodedcommand"]
                    if any(s in v_data.lower() for s in suspicious_keywords):
                        score += 25
                        tags.append("SUSPICIOUS_CMD_PERSISTENCE")

                    if re.search(r"(?i)\.(bat|ps1|vbs|hta)", fname):
                        score += 20
                        tags.append("SCRIPT_PERSISTENCE")

                    # If source is Autoruns.csv, assume high confidence
                    if "Autoruns.csv" in str(reg):
                        score += 50
                        tags.append("AUTORUNS_ENTRY")

                    if score >= 10:
                        sha256, sha1 = self._calculate_file_hash(full_path_candidate)
                        detected.append({
                            "Last_Executed_Time": ts,
                            "AION_Score": score,
                            "AION_Tags": ", ".join(tags),
                            "Target_FileName": fname,
                            "Entry_Location": f"Reg: {k_path}",
                            "Full_Path": full_path_candidate,
                            "File_Hash_SHA256": sha256, 
                            "File_Hash_SHA1": sha1
                        })

            except Exception as e: pass
        
        return detected

    def hunt_mft_persistence(self, mft_df):
        print("[*] Phase 2: Scanning MFT for Hotspots...")
        PERSISTENCE_HOTSPOTS = [r"(?i)Tasks", r"(?i)Startup"]
        RISKY_EXTENSIONS = r"(?i)\.(exe|lnk|bat|ps1|vbs|xml|dll|jar|hta)$"
        detected = []
        if "ParentPath" in mft_df.columns:
            hotspot_files = mft_df.filter(
                pl.col("ParentPath").str.contains("|".join(PERSISTENCE_HOTSPOTS)) &
                pl.col("FileName").str.contains(RISKY_EXTENSIONS)
            )
            for row in hotspot_files.iter_rows(named=True):
                path = str(row.get('ParentPath') or "")
                fname = row.get('FileName')
                if self._is_safe_path(path): continue
                if self._is_known_noise(fname, path): continue
                
                full_path_str = f"{path}\\{fname}"
                sha256, sha1 = self._calculate_file_hash(full_path_str)
                detected.append({
                    "Last_Executed_Time": row.get("Timestamp_UTC") or row.get("Created0x10"),
                    "AION_Score": 15, 
                    "AION_Tags": "FILE_PERSISTENCE (HOTSPOT)",
                    "Target_FileName": fname,
                    "Entry_Location": path,
                    "Full_Path": full_path_str,
                    "File_Hash_SHA256": sha256,
                    "File_Hash_SHA1": sha1
                })
        return detected

    def analyze(self):
        reg_hits = self.hunt_registry_persistence()
        mft_hits = []
        if self.mft_csv and Path(self.mft_csv).exists():
             try:
                 df_mft = pl.read_csv(self.mft_csv, ignore_errors=True, infer_schema_length=0)
                 if "Target_Path" in df_mft.columns:
                     df_mft = df_mft.with_columns([
                        pl.col("Target_Path").str.extract(r"^(.*)\\([^\\]+)$", 1).alias("ParentPath"),
                        pl.col("Target_Path").str.extract(r"^(.*)\\([^\\]+)$", 2).alias("FileName")
                     ])
                 mft_hits = self.hunt_mft_persistence(df_mft)
             except: pass

        final_list = reg_hits + mft_hits
        if not final_list: return None
        return pl.DataFrame(final_list).sort("AION_Score", descending=True).unique(subset=["Full_Path", "Entry_Location"])

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, help="KAPE Artifacts Dir (CSV)")
    parser.add_argument("--mft", help="Master_Timeline.csv")
    parser.add_argument("--mount", help="OPTIONAL: Path to Mounted Disk Image (e.g. E:\) for Hashing")
    parser.add_argument("-o", "--out", default="Persistence_Report.csv")
    args = parser.parse_args(argv)

    engine = AIONEngine(target_dir=args.dir, mft_csv=args.mft, mount_point=args.mount)
    df = engine.analyze()

    if df is not None:
        print(f"\n[+] PERSISTENCE DETECTED: {len(df)} artifacts.")
        df.write_csv(args.out)
    else:
        print("[-] No persistence identified (Clean).")

if __name__ == "__main__":
    main()
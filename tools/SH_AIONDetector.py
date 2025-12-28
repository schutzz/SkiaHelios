import polars as pl
import argparse
from pathlib import Path
import sys
import io
import re
import hashlib

# ============================================================
#  SH_AIONDetector v13.1 [Hybrid Hash Hunter]
#  Mission: Detect Persistence & Calculate Evidence Hash (Optional).
#  Fix: Handle "Artifact Only" scenarios gracefully.
# ============================================================

def print_logo():
    print(r"""
        / \
       / _ \     (The Eye of Truth v13.1)
      / | | \    "Context aware verification."
     /_/   \_\

      [ SH_AIONDetector ]
    """)

class AIONEngine:
    def __init__(self, target_dir=None, mft_csv=None, mount_point=None):
        self.target_dir = Path(target_dir) if target_dir else None
        self.mft_csv = mft_csv
        # If mount_point is provided, we try to hash. If not, we skip.
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
        """Calculates SHA256 if image is mounted. Returns status string otherwise."""
        if not self.mount_point:
            return "ARTIFACT_ONLY (No Image)"
        
        if not relative_path:
            return "N/A"
        
        # Normalize path
        clean_path = str(relative_path).lstrip(".\\").lstrip("\\")
        if ":" in clean_path:
            try:
                clean_path = clean_path.split(":", 1)[1].lstrip("\\")
            except: pass
            
        full_path = self.mount_point / clean_path
        
        if not full_path.exists():
            return "FILE_NOT_FOUND_ON_MOUNT"
        
        try:
            sha256_hash = hashlib.sha256()
            with open(full_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return f"Error: {str(e)[:15]}"

    def _is_safe_path(self, path_str):
        if not path_str: return False
        path_norm = str(path_str).replace("/", "\\")
        for safe in self.safe_paths:
            if re.search(safe, path_norm, re.IGNORECASE):
                return True
        return False

    def _is_known_noise(self, filename, path):
        fn = str(filename).lower()
        fp = str(path).lower()

        # 1. Windows Update / WinSxS Patterns (Hash-prefixed names)
        # Example: amd64_updateservices-database...
        if re.match(r"(?i)^(amd64|x86|wow64)_", fn): return True
        if fn.endswith((".manifest", ".mum", ".cat")): return True

        # 2. .NET GAC / Assembly Artifacts
        # Example: system.threading.tasks.dll in weird paths
        if "gac_msil" in fp or "assembly" in fp: return True
        if fn.startswith("system.") and fn.endswith(".dll"): return True
        if "microsoft.build" in fn: return True

        # 3. Specific Path Noise
        # "PathUnknown" often points to unmapped system areas in MFT parsers
        if "pathunknown" in fp and ("microsoft" in fp or "windows" in fp): return True

        return False

    def _load_registry_csvs(self):
        if not self.target_dir: return []
        return list(self.target_dir.rglob("*Registry*.csv")) + list(self.target_dir.rglob("*RECmd*.csv"))

    def hunt_registry_persistence(self):
        print("[*] Phase 1: Scanning Registry Hives (Dead Disk)...")
        detected = []
        reg_files = self._load_registry_csvs()
        
        if not reg_files: return []

        for reg in reg_files:
            try:
                df = pl.read_csv(reg, ignore_errors=True, infer_schema_length=0)
                cols = df.columns
                
                key_col = next((c for c in cols if "Key" in c and "Path" in c), None)
                val_col = next((c for c in cols if "Value" in c and "Name" in c), None)
                data_col = next((c for c in cols if "Value" in c and "Data" in c), None)
                time_col = next((c for c in cols if "Time" in c), None)
                
                if not key_col or not data_col: continue
                
                regex_pattern = "|".join([re.escape(k) for k in self.reg_targets])
                hits = df.filter(pl.col(key_col).str.contains(r"(?i)" + regex_pattern))

                if hits.is_empty(): continue

                for row in hits.iter_rows(named=True):
                    k_path = str(row.get(key_col, ""))
                    v_name = str(row.get(val_col, ""))
                    v_data = str(row.get(data_col, ""))
                    ts = str(row.get(time_col, ""))

                    if not v_data or len(v_data) < 3: continue
                    if self._is_safe_path(v_data): continue
                    
                    # Calculate potential filename from v_data
                    temp_fname = v_data.split("\\")[-1] if "\\" in v_data else v_data
                    if self._is_known_noise(temp_fname, v_data): continue
                    if "ctfmon.exe" in v_data.lower() and "windows" in v_data.lower(): continue
                    if "onedrive.exe" in v_data.lower() and "program files" in v_data.lower(): continue

                    score = 0
                    tags = []
                    
                    if "Run" in k_path: 
                        score += 10
                        tags.append("REG_RUN_KEY")
                    
                    suspicious_paths = ["appdata", "temp", "public", "users", "powershell", "cmd", "wscript"]
                    if any(s in v_data.lower() for s in suspicious_paths):
                        score += 5
                        tags.append("SUSPICIOUS_PATH")

                    if re.search(r"(?i)\.(exe|bat|ps1|vbs|hta|dll)", v_data):
                        score += 5
                    
                    if "updateservice" in v_data.lower() or "onedriveupdate" in v_name.lower():
                        score += 20
                        tags.append("TARGET_MATCH")

                    if score >= 10:
                        fname_match = re.search(r"([^\\]+\.(exe|bat|ps1|dll|vbs))", v_data, re.IGNORECASE)
                        fname = fname_match.group(1) if fname_match else "Unknown"
                        
                        # Hash Check (Conditional)
                        f_hash = self._calculate_file_hash(v_data)

                        detected.append({
                            "Last_Executed_Time": ts,
                            "AION_Score": score,
                            "AION_Tags": ", ".join(tags),
                            "Target_FileName": fname,
                            "Entry_Location": f"Reg: {k_path}",
                            "Full_Path": v_data,
                            "File_Hash": f_hash
                        })

            except Exception as e:
                pass
        
        return detected

    def hunt_mft_persistence(self, mft_df):
        print("[*] Phase 2: Scanning MFT for Hotspots...")
        PERSISTENCE_HOTSPOTS = [r"(?i)Tasks", r"(?i)Startup"]
        RISKY_EXTENSIONS = r"(?i)\.(exe|lnk|bat|ps1|vbs|xml|dll|jar|hta)$"

        detected = []

        if "ParentPath" in mft_df.columns:
            # 1. Hotspot Scan
            hotspot_files = mft_df.filter(
                pl.col("ParentPath").str.contains("|".join(PERSISTENCE_HOTSPOTS)) &
                pl.col("FileName").str.contains(RISKY_EXTENSIONS)
            )
            
            for row in hotspot_files.iter_rows(named=True):
                path = str(row.get('ParentPath') or "")
                if self._is_safe_path(path): continue
                if self._is_known_noise(row.get('FileName'), path): continue
                if "onedrive" in str(row.get('FileName',"")).lower() and "program files" in path.lower(): continue

                full_path_str = f"{path}\\{row.get('FileName')}"
                f_hash = self._calculate_file_hash(full_path_str)

                detected.append({
                    "Last_Executed_Time": row.get("Timestamp_UTC") or row.get("Created0x10"),
                    "AION_Score": 15, 
                    "AION_Tags": "FILE_PERSISTENCE (HOTSPOT)",
                    "Target_FileName": row.get("FileName"),
                    "Entry_Location": row.get("ParentPath"),
                    "Full_Path": full_path_str,
                    "File_Hash": f_hash
                })

            # 2. Wanted List Scan
            WANTED = ["UpdateService", "OneDriveUpdateHelper", "Confidential", "Project_Chaos"]
            for w in WANTED:
                hits = mft_df.filter(pl.col("FileName").str.contains(f"(?i){w}"))
                for row in hits.iter_rows(named=True):
                    path = str(row.get('ParentPath') or "")
                    if self._is_safe_path(path): continue

                    full_path_str = f"{path}\\{row.get('FileName')}"
                    f_hash = self._calculate_file_hash(full_path_str)

                    detected.append({
                        "Last_Executed_Time": row.get("Timestamp_UTC") or row.get("Created0x10"),
                        "AION_Score": 20, 
                        "AION_Tags": "NAMED_PERSISTENCE (WANTED)",
                        "Target_FileName": row.get("FileName"),
                        "Entry_Location": path,
                        "Full_Path": full_path_str,
                        "File_Hash": f_hash
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
import polars as pl
import argparse
from pathlib import Path
import sys
import io
import re
import hashlib
import yaml # [v14.4] Added for keyword config
from tools.SH_ThemisLoader import ThemisLoader # ⚖️ Themis召喚
from tools.SH_ChainScavenger import ChainScavenger # [v5.6] Chain Scavenger

# ============================================================
#  SH_AIONDetector v14.4 [Selective Scavenger]
#  Mission: Detect Persistence via External Logic
#  Update: Limited Scavenger Release via Keyword Matching
# ============================================================

def print_logo():
    print(r"""
        / \
       / _ \     (The Eye of Truth v14.4)
      / | | \    "Themis guides the hunt."
     /_/   \_\

      [ SH_AIONDetector ]
    """)

class AIONEngine:
    def __init__(self, target_dir=None, mft_csv=None, mount_point=None, raw_dir=None):
        self.target_dir = Path(target_dir) if target_dir else None
        self.mft_csv = mft_csv
        self.mount_point = Path(mount_point) if mount_point else None
        self.raw_dir = Path(raw_dir) if raw_dir else None  # [v5.6] For ChainScavenger
        
        # ⚖️ Themis Initialization
        print("[*] Initializing AION with Themis Rules...")
        self.loader = ThemisLoader()
        
        # Load Scan Targets from YAML
        raw_targets = self.loader.get_persistence_targets("Registry")
        self.reg_targets = []
        for t in raw_targets:
            if isinstance(t, dict):
                self.reg_targets.append(t.get("pattern", ""))
            else:
                self.reg_targets.append(str(t))
        
        self.reg_targets = [t for t in self.reg_targets if t]

        if not self.reg_targets:
            print("[!] Warning: No Registry targets found in rules. Using fallback.")
            self.reg_targets = [r"Run", r"Services"]

        # [v14.4] Load Scavenger Keywords from YAML
        self.scavenger_keywords = []
        try:
            if Path("rules/intel_signatures.yaml").exists():
                with open("rules/intel_signatures.yaml", "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f)
                    self.scavenger_keywords = config.get("aion_tuning", {}).get("scavenger_keywords", [])
                    print(f"    [+] Loaded {len(self.scavenger_keywords)} Scavenger Keywords (Selective Mode).")
        except Exception as e:
            print(f"    [!] Failed to load Scavenger Keywords: {e}")

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

    def hunt_registry_persistence(self):
        print("[*] Phase 1: Scanning Registry Hives (Themis Scope)...")
        detected = []
        reg_files = list(self.target_dir.rglob("*Registry*.csv")) + list(self.target_dir.rglob("*RECmd*.csv"))
        autoruns = list(self.target_dir.rglob("Autoruns.csv"))
        reg_files.extend(autoruns)
        
        if not reg_files: return []

        # Regex pre-compilation for targets
        target_pattern = "|".join([re.escape(k) for k in self.reg_targets])

        for reg in reg_files:
            try:
                df = pl.read_csv(reg, ignore_errors=True, infer_schema_length=0)
                cols = df.columns
                
                # Dynamic Column Mapping
                key_col = next((c for c in cols if "Key" in c and "Path" in c), None)
                val_col = next((c for c in cols if "Value" in c and "Name" in c), None)
                data_col = next((c for c in cols if "Value" in c and "Data" in c), None)
                time_col = next((c for c in cols if "Time" in c), None)

                # Mock/Autoruns format
                if "Location" in cols and "Item" in cols and "ImagePath" in cols:
                    key_col, val_col, data_col, time_col = "Location", "Item", "ImagePath", None

                if not key_col or not data_col: continue
                
                # Target Filtering (Based on YAML)
                if "Location" in cols:
                    hits = df # Autoruns is all trusted
                else:
                    hits = df.filter(pl.col(key_col).str.contains(r"(?i)" + target_pattern))

                for row in hits.iter_rows(named=True):
                    k_path = str(row.get(key_col, ""))
                    v_data = str(row.get(data_col, ""))
                    ts = str(row.get(time_col, "Unknown_Time"))

                    if not v_data or len(v_data) < 3: continue
                    
                    # Filename Extraction
                    fname = "Unknown"
                    full_path_candidate = v_data
                    full_path_match = re.search(r'"?([a-zA-Z]:\\[^"]+\.(?:exe|bat|ps1|vbs|dll|sys))"?', v_data, re.IGNORECASE)
                    if full_path_match:
                        full_path_candidate = full_path_match.group(1)
                        fname = full_path_candidate.split("\\")[-1]
                    else:
                         fname = v_data.split("\\")[-1] if "\\" in v_data else v_data

                    # Base Score (Detection Logic)
                    score = 0
                    tags = []
                    
                    # Basic Location Scoring
                    if "RunOnce" in k_path: score += 30; tags.append("REG_RUNONCE")
                    elif "Run" in k_path: score += 10; tags.append("REG_RUN_KEY")
                    if "Autoruns.csv" in str(reg): score += 50; tags.append("AUTORUNS_ENTRY")

                    # Note: Noise Filtering & Threat Scoring will be done by Themis later!
                    # Here we just collect candidates.
                    
                    # Calculate Hash if plausible
                    sha256, sha1 = "N/A", "N/A"
                    if score > 0 or len(tags) > 0: # Only hash if somewhat interesting
                         sha256, sha1 = self._calculate_file_hash(full_path_candidate)

                    detected.append({
                        "Last_Executed_Time": ts,
                        "AION_Score": score, # Base score
                        "AION_Tags": ", ".join(tags),
                        "Target_FileName": fname,
                        "Entry_Location": f"Reg: {k_path}",
                        "Full_Path": full_path_candidate,
                        "File_Hash_SHA256": sha256, 
                        "File_Hash_SHA1": sha1,
                        "Threat_Score": 0, # Placeholder for Themis
                        "Threat_Tag": ""   # Placeholder for Themis
                    })

            except Exception as e: pass
        
        return detected

    # ============================================================
    # [v5.6] SAM Hive User Creation Detection
    # ============================================================
    def hunt_sam_user_creation(self):
        """
        Detect user creation from SAM registry and ProfileList.
        Suspicious usernames: hacker, user1, admin, test, etc.
        """
        print("[*] Phase 1.5: Scanning SAM/ProfileList for User Creation...")
        detected = []
        
        # Suspicious username patterns
        suspicious_usernames = [
            r"(?i)^hacker", r"(?i)^user\d+", r"(?i)^admin\d+", r"(?i)^test",
            r"(?i)^backup", r"(?i)^support", r"(?i)^svc_", r"(?i)^service",
            r"(?i)^guest\d+", r"(?i)^temp", r"(?i)^new_", r"(?i)^root",
        ]
        suspicious_pattern = "|".join(suspicious_usernames)
        
        # SAM Registry patterns
        sam_patterns = [
            r"(?i)SAM\\Domains\\Account\\Users\\Names",
            r"(?i)SAM\\SAM\\Domains\\Account\\Users",
        ]
        sam_pattern = "|".join(sam_patterns)
        
        # ProfileList patterns
        profile_patterns = [
            r"(?i)ProfileList",
            r"(?i)ProfileImagePath",
        ]
        profile_pattern = "|".join(profile_patterns)
        
        # Find Registry CSVs
        reg_files = list(self.target_dir.rglob("*Registry*.csv")) + list(self.target_dir.rglob("*RECmd*.csv"))
        
        for reg in reg_files:
            try:
                df = pl.read_csv(reg, ignore_errors=True, infer_schema_length=0)
                cols = df.columns
                
                # Column detection
                key_col = next((c for c in cols if "Key" in c or "Path" in c), None)
                val_col = next((c for c in cols if "Value" in c and "Name" in c), None)
                data_col = next((c for c in cols if "Value" in c and "Data" in c), None)
                time_col = next((c for c in cols if "Time" in c), None)
                
                if not key_col: continue
                
                # Detect SAM User entries
                sam_hits = df.filter(pl.col(key_col).str.contains(sam_pattern))
                for row in sam_hits.iter_rows(named=True):
                    k_path = str(row.get(key_col, ""))
                    v_data = str(row.get(data_col, "") or row.get(val_col, ""))
                    ts = str(row.get(time_col, "Unknown_Time"))
                    
                    # Extract username from path or value
                    username = ""
                    if "Names\\" in k_path:
                        username = k_path.split("Names\\")[-1].split("\\")[0]
                    elif v_data:
                        username = v_data
                    
                    if not username: continue
                    
                    # Check if suspicious
                    is_suspicious = bool(re.search(suspicious_pattern, username))
                    score = 400 if is_suspicious else 100
                    tags = ["SAM_USER_FOUND"]
                    if is_suspicious:
                        tags.append("SUSPICIOUS_USERNAME")
                        tags.append("NEW_USER_CREATED")
                    
                    detected.append({
                        "Last_Executed_Time": ts,
                        "AION_Score": score,
                        "AION_Tags": ", ".join(tags),
                        "Target_FileName": username,
                        "Entry_Location": f"SAM: {k_path}",
                        "Full_Path": username,
                        "File_Hash_SHA256": "N/A",
                        "File_Hash_SHA1": "N/A",
                        "Threat_Score": score,
                        "Threat_Tag": "NEW_USER_CREATED" if is_suspicious else "USER_ACCOUNT"
                    })
                
                # Detect ProfileList entries
                profile_hits = df.filter(pl.col(key_col).str.contains(profile_pattern))
                for row in profile_hits.iter_rows(named=True):
                    k_path = str(row.get(key_col, ""))
                    v_data = str(row.get(data_col, "") or "")
                    ts = str(row.get(time_col, "Unknown_Time"))
                    
                    # Extract username from ProfileImagePath
                    username = ""
                    if "Users\\" in v_data:
                        username = v_data.split("Users\\")[-1].split("\\")[0]
                    
                    if not username or username in ["Default", "Public", "All Users"]: continue
                    
                    # Check if suspicious
                    is_suspicious = bool(re.search(suspicious_pattern, username))
                    if is_suspicious:
                        detected.append({
                            "Last_Executed_Time": ts,
                            "AION_Score": 400,
                            "AION_Tags": "PROFILELIST_USER, SUSPICIOUS_USERNAME, NEW_USER_CREATED",
                            "Target_FileName": username,
                            "Entry_Location": f"ProfileList: {k_path}",
                            "Full_Path": v_data,
                            "File_Hash_SHA256": "N/A",
                            "File_Hash_SHA1": "N/A",
                            "Threat_Score": 400,
                            "Threat_Tag": "NEW_USER_CREATED,PRIVILEGE_ESCALATION"
                        })
                    
            except Exception as e: pass
        
        if detected:
            print(f"    [!] CRITICAL: {len(detected)} user accounts detected from SAM/ProfileList!")
        
        return detected

    def hunt_mft_persistence(self, mft_df):
        print("[*] Phase 2: Scanning MFT for Hotspots...")
        # Note: MFT Hotspots could also be moved to YAML, but for now we keep structural logic here
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
                    "File_Hash_SHA1": sha1,
                    "Threat_Score": 0,
                    "Threat_Tag": ""
                })
        return detected

    def analyze(self):
        reg_hits = self.hunt_registry_persistence()
        sam_hits = self.hunt_sam_user_creation()  # [v5.6] SAM/ProfileList analysis
        
        # [v14.4] Selective ChainScavenger (Limited Release)
        scavenge_hits = []
        if self.raw_dir and self.scavenger_keywords:
            print(f"    -> [AION] Activating Selective Chain Scavenger (Keywords: {len(self.scavenger_keywords)})...")
            try:
                scavenger = ChainScavenger(self.raw_dir)
                # We use the existing scavenge method but filter strictly
                raw_results = scavenger.scavenge()
                
                resurrected_count = 0
                for r in raw_results:
                    # Create a composite string for keyword matching
                    # (Username often holds the key name in Scavenger results)
                    item_str = (str(r.get("Username", "")) + str(r.get("Entry_Location", "")) + str(r.get("AION_Tags", ""))).lower()
                    
                    is_match = False
                    for kw in self.scavenger_keywords:
                        if kw.lower() in item_str:
                            is_match = True
                            break
                    
                    if is_match:
                        # Map Scavenger result structure to AION expected format
                        ctx_hex = r.get("Context_Hex", "N/A")
                        location_info = r.get("Entry_Location", "")
                        if ctx_hex != "N/A":
                            location_info += f" [HEX: {ctx_hex}]"

                        scavenge_hits.append({
                            "Last_Executed_Time": r.get("Timestamp", ""),
                            "AION_Score": r.get("AION_Score", 400),
                            "AION_Tags": f"{r.get('AION_Tags', 'SAM_SCAVENGE')} (RESURRECTED)",
                            "Target_FileName": r.get("Username", ""),
                            "Entry_Location": location_info,
                            "Full_Path": r.get("Username", ""),
                            "File_Hash_SHA256": "N/A",
                            "File_Hash_SHA1": "N/A",
                            "Threat_Score": r.get("Threat_Score", 400),
                            "Threat_Tag": r.get("Threat_Tag", "PERSISTENCE_ARTIFACT"),
                            "RID": r.get("RID", ""),
                            "SID": r.get("SID", ""),
                            "Hash_State": r.get("Hash_State", ""),
                        })
                        resurrected_count += 1
                
                print(f"    [+] Scavenger Resurrected {resurrected_count} artifacts matching keywords!")

            except Exception as e:
                print(f"    [-] Scavenger error: {e}")
        
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

        raw_list = reg_hits + sam_hits + scavenge_hits + mft_hits  # Include scavenge hits
        if not raw_list: return None
        
        # --- ⚖️ THEMIS JUDGMENT DAY ---
        print("    -> Applying Themis Laws (Noise Filter & Threat Scoring)...")
        lf = pl.DataFrame(raw_list).lazy()
        cols = lf.collect_schema().names()
        
        # [v5.6.3] Ensure optional columns exist (RID/SID/Hash_State)
        for opt_col in ["RID", "SID", "Hash_State"]:
            if opt_col not in cols:
                lf = lf.with_columns(pl.lit("").alias(opt_col))
        
        # 1. Apply Threat Scoring (Overrides AION_Score logic)
        lf = self.loader.apply_threat_scoring(lf)
        
        # 2. Merge Scores (Base AION + Themis Threat)
        lf = lf.with_columns(
            (pl.col("AION_Score") + pl.col("Threat_Score")).alias("Final_Score"),
            pl.concat_str([pl.col("AION_Tags"), pl.col("Threat_Tag")], separator=", ").str.strip_chars(", ").alias("Final_Tags")
        )

        # 3. Apply Noise Filters (Golden Rule: High Threat survives Noise)
        noise_expr = self.loader.get_noise_filter_expr(cols)
        lf = lf.filter((~noise_expr) | (pl.col("Threat_Score") > 0))
        
        # 4. Clean up columns for output
        lf = lf.select([
            pl.col("Last_Executed_Time"),
            pl.col("Final_Score").alias("AION_Score"),
            pl.col("Final_Tags").alias("AION_Tags"),
            pl.col("Target_FileName"),
            pl.col("Entry_Location"),
            pl.col("Full_Path"),
            pl.col("File_Hash_SHA256"),
            pl.col("File_Hash_SHA1"),
            pl.col("Threat_Score"), 
            pl.col("Threat_Tag"),
            pl.col("RID"),
            pl.col("SID"),
            pl.col("Hash_State")
        ])

        df_result = lf.sort("AION_Score", descending=True).unique(subset=["Full_Path", "Entry_Location"]).collect()
        
        # 5. Meddlesome Suggestion (Osekkay)
        suggestions = self.loader.suggest_new_noise_rules(df_result)
        if suggestions:
            print("\n[?] Themis Suggestions to reduce noise:")
            for s in suggestions: print(s)

        return df_result

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, help="KAPE Artifacts Dir (CSV)")
    parser.add_argument("--mft", help="Master_Timeline.csv")
    parser.add_argument("--mount", help="OPTIONAL: Path to Mounted Disk Image (e.g. E:\) for Hashing")
    parser.add_argument("--raw", help="[v5.6] Raw Artifacts Dir (for ChainScavenger)")
    parser.add_argument("-o", "--out", default="Persistence_Report.csv")
    args = parser.parse_args(argv)

    engine = AIONEngine(target_dir=args.dir, mft_csv=args.mft, mount_point=args.mount, raw_dir=args.raw)
    df = engine.analyze()

    if df is not None and df.height > 0:
        print(f"\n[+] PERSISTENCE DETECTED: {df.height} artifacts.")
        df.write_csv(args.out)
    else:
        print("[-] No persistence identified (Clean).")

if __name__ == "__main__":
    main()
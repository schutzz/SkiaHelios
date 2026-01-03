import polars as pl
import json
from pathlib import Path
import sys
import re

# ============================================================
#  SH_ClothoReader v2.5 [Identity Anchor]
#  Mission: Read inputs and resolve identities (Host/User/OS).
#  Update: Fixed Hostname loss by prioritizing JSON/Registry.
# ============================================================

class ClothoReader:
    def __init__(self, args):
        self.args = args
        self.dfs = {}
        self.siren_data = []
        self.hostname = "Unknown_Host"
        self.os_info = "Unknown OS"
        self.primary_user = "Unknown_User"
        self.sid_map = {} 

    def spin_thread(self):
        print("[*] Clotho v2.5 is spinning the threads...")
        self.dfs['Hercules'] = self._safe_load(self.args.input)
        
        # Load other CSVs
        self.dfs['Chronos'] = self._safe_load(getattr(self.args, 'chronos', None))
        self.dfs['Pandora'] = self._safe_load(getattr(self.args, 'pandora', None))
        self.dfs['AION'] = self._safe_load(getattr(self.args, 'aion', None))
        self.dfs['Plutos'] = self._safe_load(getattr(self.args, 'plutos', None))
        self.dfs['PlutosNet'] = self._safe_load(getattr(self.args, 'plutos_net', None))
        self.dfs['Sphinx'] = self._safe_load(getattr(self.args, 'sphinx', None))
        
        self.siren_data = self._load_json(getattr(self.args, 'siren', None))

        self._identify_host_and_environment()
        
        # 5W1H Enrichment
        for key, df in self.dfs.items():
            if df is not None:
                self.dfs[key] = self._enrich_5w1h(df, key)

        return self.dfs, self.siren_data, self.hostname, self.os_info, self.primary_user

    def _safe_load(self, path):
        try: return pl.read_csv(path, ignore_errors=True, infer_schema_length=0) if path else None
        except: return None

    def _load_json(self, path):
        try: 
            with open(path, 'r', encoding='utf-8') as f: return json.load(f)
        except: return []

    def _identify_host_and_environment(self):
        # 1. External JSON (Highest Priority)
        # Search in input dir (Hercules output dir) and parent (Case dir)
        search_paths = []
        if self.args.input:
            search_paths.append(Path(self.args.input).parent / "Host_Identity.json")
            search_paths.append(Path(self.args.input).parent.parent / "Host_Identity.json")
        
        for p in search_paths:
            if p.exists():
                try:
                    with open(p, "r") as f:
                        data = json.load(f)
                        if data.get("Hostname") and data.get("Hostname") != "Unknown_Host":
                            self.hostname = data.get("Hostname")
                        self.os_info = data.get("OS", self.os_info) 
                except: pass

        # 2. Registry Analysis (OS & SID Map & Hostname Fallback)
        search_dirs = []
        if getattr(self.args, 'kape', None): search_dirs.append(Path(self.args.kape))
        if self.args.input: search_dirs.append(Path(self.args.input).parent)

        patterns = ["*SOFTWARE*.csv", "*Software*.csv", "*Registry*.csv", "*SystemInfo*.csv", "*BasicSystemInfo*.csv", "*SYSTEM*.csv"]
        
        for base_dir in search_dirs:
            if not base_dir.exists(): continue
            
            reg_files = []
            for p in patterns: reg_files.extend(list(base_dir.rglob(p)))
            
            for csv in set(reg_files):
                try:
                    df_reg = pl.read_csv(csv, ignore_errors=True, infer_schema_length=0)
                    cols = df_reg.columns
                    key_col = next((c for c in cols if "Key" in c and "Path" in c), None)
                    val_col = next((c for c in cols if "Value" in c and "Name" in c), None)
                    data_col = next((c for c in cols if "Value" in c and "Data" in c), None)
                    
                    if not (key_col and val_col and data_col): continue

                    # SID Map (ProfileList)
                    if "SOFTWARE" in csv.name.upper() or "REGISTRY" in csv.name.upper():
                        profiles = df_reg.filter(pl.col(key_col).str.contains(r"ProfileList\\S-1-5-21"))
                        for row in profiles.iter_rows(named=True):
                            key_path = row[key_col]
                            sid = key_path.split("\\")[-1]
                            path_val = row[data_col] # Fix: Use data_col for path
                            if path_val and "Users" in str(path_val):
                                user = str(path_val).split("\\")[-1]
                                self.sid_map[sid] = user

                    # OS Info (CurrentVersion)
                    os_row = df_reg.filter(
                        (pl.col(key_col).str.contains(r"Microsoft\\Windows NT\\CurrentVersion")) &
                        (pl.col(val_col).str.contains("ProductName"))
                    )
                    if os_row.height > 0: self.os_info = os_row[data_col][0]

                    # [NEW] Hostname from SYSTEM Hive (ComputerName)
                    # HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName
                    if self.hostname == "Unknown_Host" and ("SYSTEM" in csv.name.upper() or "REGISTRY" in csv.name.upper()):
                        host_row = df_reg.filter(
                            (pl.col(key_col).str.contains(r"Control\\ComputerName\\ComputerName")) &
                            (pl.col(val_col).str.contains("ComputerName"))
                        )
                        if host_row.height > 0: self.hostname = host_row[data_col][0]

                except: continue

        # 3. Hercules (Event Logs) - Fallback
        if self.dfs.get('Hercules') is not None:
            df = self.dfs['Hercules']
            
            # Hostname Fallback
            if "Computer" in df.columns and self.hostname == "Unknown_Host":
                try:
                    top = df.select("Computer").drop_nulls().group_by("Computer").count().sort("count", descending=True).head(1)
                    if top.height > 0: self.hostname = top["Computer"][0]
                except: pass
            
            # User Identification
            if self.primary_user == "Unknown_User":
                # Direct User column
                if "User" in df.columns:
                    try:
                        ignore_users = ["system", "network service", "local service", "n/a", "", "none"]
                        user_counts = df.filter(
                            (~pl.col("User").str.to_lowercase().is_in(ignore_users)) &
                            (pl.col("User").is_not_null())
                        ).group_by("User").count().sort("count", descending=True)
                        if user_counts.height > 0: self.primary_user = user_counts["User"][0]
                    except: pass
                
                # SID Fallback
                if self.primary_user == "Unknown_User" and "Subject_SID" in df.columns:
                     try:
                        sid_counts = df.filter(pl.col("Subject_SID").str.contains("S-1-5-21")).group_by("Subject_SID").count().sort("count", descending=True)
                        if sid_counts.height > 0:
                            top_sid = sid_counts["Subject_SID"][0]
                            if top_sid in self.sid_map:
                                self.primary_user = self.sid_map[top_sid]
                                print(f"   > User Resolved via SID Map: {self.primary_user}")
                            else:
                                self.primary_user = f"Unknown ({top_sid})"
                     except: pass

        print(f"   > Host: {self.hostname}, User: {self.primary_user}, OS: {self.os_info}")

    def _enrich_5w1h(self, df, source_name):
        if "Src_Host" not in df.columns: df = df.with_columns(pl.lit(self.hostname).alias("Src_Host"))
        
        # User Enrichment
        if "User" in df.columns:
             df = df.with_columns(
                 pl.when(pl.col("User").is_in(["", "N/A", "Unknown_User", None]))
                 .then(pl.lit(self.primary_user))
                 .otherwise(pl.col("User"))
                 .alias("User")
             )
        else:
             df = df.with_columns(pl.lit(self.primary_user).alias("User"))
        
        return df
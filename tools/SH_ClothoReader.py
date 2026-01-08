import polars as pl
import json
from pathlib import Path
import sys
import re

# ============================================================
#  SH_ClothoReader v2.9 [Full Artifact Loader]
#  Mission: Read inputs and resolve identities (Host/User/OS).
#  Update: Load ALL UserAssist/Prefetch files (not just one).
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
        print("[*] Clotho v2.9 is spinning the threads...")
        self.dfs['Hercules'] = self._safe_load(self.args.input)
        
        self.dfs['Chronos'] = self._safe_load(getattr(self.args, 'chronos', None))
        
        pandora_path = getattr(self.args, 'pandora', None)
        if not pandora_path:
            pandora_path = getattr(self.args, 'ghosts', None)
        self.dfs['Pandora'] = self._safe_load(pandora_path)

        self.dfs['AION'] = self._safe_load(getattr(self.args, 'aion', None))
        
        # [CRITICAL FIX] Load ALL supporting artifacts
        self._load_supporting_artifacts()

        self.siren_data = self._load_json(getattr(self.args, 'siren', None))

        self._identify_host_and_environment()
        
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

    def _load_supporting_artifacts(self):
        """KAPE CSVフォルダから全てのPrefetchとUserAssistをロードして結合する"""
        csv_dir = getattr(self.args, 'csv', None)
        if not csv_dir: return

        csv_path = Path(csv_dir)
        if not csv_path.exists(): return

        print(f"    [*] Clotho searching for enrichment artifacts in: {csv_path}")

        # 1. Prefetch (Load ALL files)
        pf_files = list(csv_path.rglob("*PECmd*.csv")) + list(csv_path.rglob("*Prefetch*.csv"))
        if pf_files:
            dfs = []
            for f in pf_files:
                try: dfs.append(pl.read_csv(f, ignore_errors=True, infer_schema_length=0))
                except: pass
            if dfs:
                try:
                    # カラム不一致を防ぐため、共通カラムのみで結合するか、diagonalで結合
                    self.dfs['Prefetch'] = pl.concat(dfs, how="diagonal")
                    print(f"       + Loaded {len(dfs)} Prefetch files (Merged).")
                except Exception as e:
                    print(f"       [!] Prefetch Merge Error: {e}")

        # 2. UserAssist (Load ALL files - Critical for per-user stats)
        ua_files = list(csv_path.rglob("*UserAssist*.csv"))
        if ua_files:
            dfs = []
            for f in ua_files:
                try: dfs.append(pl.read_csv(f, ignore_errors=True, infer_schema_length=0))
                except: pass
            if dfs:
                try:
                    self.dfs['UserAssist'] = pl.concat(dfs, how="diagonal")
                    print(f"       + Loaded {len(dfs)} UserAssist files (Merged).")
                except Exception as e:
                    print(f"       [!] UserAssist Merge Error: {e}")

    def _identify_host_and_environment(self):
        # (ロジック変更なし)
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

        search_dirs = []
        if getattr(self.args, 'kape', None): search_dirs.append(Path(self.args.kape))
        if getattr(self.args, 'csv', None): search_dirs.append(Path(self.args.csv))
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

                    if "SOFTWARE" in csv.name.upper() or "REGISTRY" in csv.name.upper():
                        profiles = df_reg.filter(pl.col(key_col).str.contains(r"ProfileList\\S-1-5-21"))
                        for row in profiles.iter_rows(named=True):
                            key_path = row[key_col]
                            sid = key_path.split("\\")[-1]
                            path_val = row[data_col]
                            if path_val and "Users" in str(path_val):
                                user = str(path_val).split("\\")[-1]
                                self.sid_map[sid] = user

                    os_row = df_reg.filter(
                        (pl.col(key_col).str.contains(r"Microsoft\\Windows NT\\CurrentVersion")) &
                        (pl.col(val_col).str.contains("ProductName"))
                    )
                    if os_row.height > 0: self.os_info = os_row[data_col][0]

                    if self.hostname == "Unknown_Host" and ("SYSTEM" in csv.name.upper() or "REGISTRY" in csv.name.upper()):
                        host_row = df_reg.filter(
                            (pl.col(key_col).str.contains(r"Control\\ComputerName\\ComputerName")) &
                            (pl.col(val_col).str.contains("ComputerName"))
                        )
                        if host_row.height > 0: self.hostname = host_row[data_col][0]
                except: continue

        if self.dfs.get('Hercules') is not None:
            df = self.dfs['Hercules']
            if "Computer" in df.columns and self.hostname == "Unknown_Host":
                try:
                    top = df.select("Computer").drop_nulls().group_by("Computer").count().sort("count", descending=True).head(1)
                    if top.height > 0: self.hostname = top["Computer"][0]
                except: pass
            
            if self.primary_user == "Unknown_User":
                if "User" in df.columns:
                    try:
                        ignore_users = ["system", "network service", "local service", "n/a", "", "none"]
                        user_counts = df.filter(
                            (~pl.col("User").str.to_lowercase().is_in(ignore_users)) &
                            (pl.col("User").is_not_null())
                        ).group_by("User").count().sort("count", descending=True)
                        if user_counts.height > 0: self.primary_user = user_counts["User"][0]
                    except: pass
                
                if self.primary_user == "Unknown_User" and "Subject_SID" in df.columns:
                     try:
                        sid_counts = df.filter(pl.col("Subject_SID").str.contains("S-1-5-21")).group_by("Subject_SID").count().sort("count", descending=True)
                        if sid_counts.height > 0:
                            top_sid = sid_counts["Subject_SID"][0]
                            if top_sid in self.sid_map:
                                self.primary_user = self.sid_map[top_sid]
                            else:
                                self.primary_user = f"Unknown ({top_sid})"
                     except: pass

        print(f"   > Host: {self.hostname}, User: {self.primary_user}, OS: {self.os_info}")

    def _enrich_5w1h(self, df, source_name):
        if "Src_Host" not in df.columns: df = df.with_columns(pl.lit(self.hostname).alias("Src_Host"))
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
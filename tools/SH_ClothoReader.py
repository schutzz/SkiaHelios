import polars as pl
import json
from pathlib import Path
import sys
import re

class ClothoReader:
    def __init__(self, args):
        self.args = args
        self.dfs = {}
        self.siren_data = []
        self.hostname = "Unknown_Host"
        self.os_info = "Unknown OS"
        self.primary_user = "Unknown_User"

    def spin_thread(self):
        print("[*] Clotho v2.1 is spinning the threads...")
        self.dfs['Hercules'] = self._safe_load(self.args.input)
        # (Load other CSVs - omitted for brevity, keep existing loading logic)
        self.dfs['Chronos'] = self._safe_load(getattr(self.args, 'chronos', None))
        self.dfs['Pandora'] = self._safe_load(getattr(self.args, 'pandora', None))
        self.dfs['AION'] = self._safe_load(getattr(self.args, 'aion', None))
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
        if self.args.input:
            host_info_path = Path(self.args.input).parent / "Host_Identity.json"
            if host_info_path.exists():
                try:
                    with open(host_info_path, "r") as f:
                        data = json.load(f)
                        self.hostname = data.get("Hostname", self.hostname)
                        self.os_info = data.get("OS", self.os_info)
                        return
                except: pass

        # 2. [NEW] SOFTWARE Hive Analysis for OS Info
        # 入力ディレクトリ周辺から *SOFTWARE*.csv を探す
        if self.args.input:
            base_dir = Path(self.args.input).parent if Path(self.args.input).is_file() else Path(self.args.input)
            software_csvs = list(base_dir.rglob("*SOFTWARE*.csv")) + list(base_dir.rglob("*Software*.csv"))
            
            for csv in software_csvs:
                try:
                    df_soft = pl.read_csv(csv, ignore_errors=True, infer_schema_length=0)
                    # 一般的なRegRipper/KAPEのカラム名を想定
                    # 'KeyPath' or 'RegPath' and 'ValueName', 'ValueData'
                    cols = df_soft.columns
                    key_col = next((c for c in cols if "Path" in c), None)
                    val_col = next((c for c in cols if "ValueName" in c or "Value Name" in c), None)
                    data_col = next((c for c in cols if "ValueData" in c or "Value Data" in c), None)

                    if key_col and data_col:
                        # ProductNameを探す
                        # Pathには "Microsoft\Windows NT\CurrentVersion" が含まれるはず
                        os_row = df_soft.filter(
                            (pl.col(key_col).str.contains(r"Microsoft\\Windows NT\\CurrentVersion")) &
                            (pl.col(val_col).str.contains("ProductName") if val_col else pl.lit(True)) &
                            (pl.col(data_col).str.len() > 3)
                        )
                        
                        if os_row.height > 0:
                            # 最初のヒットを採用
                            if val_col:
                                # ValueNameがある場合はピンポイントで
                                hit = os_row.filter(pl.col(val_col) == "ProductName")
                                if hit.height > 0:
                                    self.os_info = hit[data_col][0]
                            else:
                                # なければデータカラムからそれっぽいものを探す（簡易）
                                self.os_info = os_row[data_col][0]
                            break # Found
                except: pass

        # 3. Hercules (Event Logs) for Hostname/User
        if self.dfs.get('Hercules') is not None:
            df = self.dfs['Hercules']
            if "Computer" in df.columns and self.hostname == "Unknown_Host":
                try:
                    top = df.select("Computer").drop_nulls().group_by("Computer").count().sort("count", descending=True).head(1)
                    if top.height > 0: self.hostname = top["Computer"][0]
                except: pass
            
            if self.hostname == "Unknown_Host" and "Action" in df.columns:
                try:
                    extracted = df.select(pl.col("Action").str.extract(r"Target: ([^\\]+)\\", 1).alias("Host")).drop_nulls()
                    top_host = extracted.group_by("Host").count().sort("count", descending=True).head(1)
                    if top_host.height > 0:
                        candidate = top_host["Host"][0]
                        if candidate.lower() not in ["nt authority", "workgroup", "domain"]: self.hostname = candidate
                except: pass

            if "User" in df.columns and self.primary_user == "Unknown_User":
                try:
                    users = df.filter(~pl.col("User").str.contains(r"(?i)^N/A$|^System$|^Local Service$|^Network Service$|AUTHORITY|Window Manager")).select("User").drop_nulls()
                    top_user = users.group_by("User").count().sort("count", descending=True).head(1)
                    if top_user.height > 0: self.primary_user = top_user["User"][0]
                except: pass

    def _enrich_5w1h(self, df, source_name):
        # (Keep existing 5W1H logic)
        if "Src_Host" not in df.columns: df = df.with_columns(pl.lit(self.hostname).alias("Src_Host"))
        return df
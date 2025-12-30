import polars as pl
import json
from pathlib import Path
import sys
import re

# ============================================================
#  SH_ClothoReader v1.9.2 [Session Aware]
#  Mission: Normalize & Ingest all forensic artifacts.
#  Update: Load 'hercules_sessions.json' for Privilege Escalation checks.
# ============================================================

class ClothoReader:
    """
    [Clotho: The Spinner]
    運命の糸（ログ）を紡ぎ出し、解析可能な状態（DataFrame）に正規化するクラス。
    全てのデータソースの読み込みと、ホスト名・ユーザー属性の特定を担当する。
    """
    def __init__(self, args):
        self.args = args
        self.dfs = {}
        self.siren_data = []
        self.hostname = "Unknown_Host"

    def spin_thread(self):
        """
        全てのデータソースをロードし、以下のタプルを返す:
        (DataFramesDict, SirenDataList, HostnameString)
        """
        print("[*] Clotho is spinning the threads of logs...")
        
        # 1. Primary Timeline (Hercules)
        self.dfs['Hercules'] = self._safe_load(self.args.input)
        
        # 2. Network
        self.dfs['Network'] = self._safe_load(self.args.input)

        # 3. Dedicated Artifacts
        aion_path = getattr(self.args, 'aion', None) or getattr(self.args, 'persistence', None)
        self.dfs['AION'] = self._safe_load(aion_path)
        
        self.dfs['Pandora']   = self._safe_load(getattr(self.args, 'pandora', None))
        self.dfs['Plutos']    = self._safe_load(getattr(self.args, 'plutos', None))
        self.dfs['PlutosNet'] = self._safe_load(getattr(self.args, 'plutos_net', None))
        self.dfs['Sphinx']    = self._safe_load(getattr(self.args, 'sphinx', None))
        self.dfs['Chronos']   = self._safe_load(getattr(self.args, 'chronos', None))
        self.dfs['Prefetch']  = self._safe_load(getattr(self.args, 'prefetch', None))

        # [NEW] 4. Session Map (from Hercules)
        # 権限昇格検知のためにセッション情報をロードする
        if self.args.input:
            session_path = Path(self.args.input).parent / "hercules_sessions.json"
            if session_path.exists():
                try:
                    with open(session_path, 'r', encoding='utf-8') as f:
                        # JSONをPolars DataFrameに変換して保持
                        self.dfs['Sessions'] = pl.DataFrame(json.load(f))
                    print(f"   -> Session Map Loaded: {len(self.dfs['Sessions'])} sessions.")
                except Exception as e:
                    print(f"[!] Warning: Failed to load Session Map: {e}")

        # 5. JSON Data (SirenHunt)
        self.siren_data = self._load_json(getattr(self.args, 'siren', None))

        # 6. Identify Host
        self._identify_host()

        # 7. 5W1H Enrichment
        print(f"[*] Clotho is weaving 5W1H attributes for host: {self.hostname}...")
        for key, df in self.dfs.items():
            if df is not None and key != 'Sessions': # Sessionsは正規化対象外
                self.dfs[key] = self._enrich_5w1h(df, key)

        return self.dfs, self.siren_data, self.hostname

    def _safe_load(self, path):
        if path and Path(path).exists():
            try:
                return pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
            except Exception as e:
                print(f"[!] Clotho Warning: Failed to load CSV {path}: {e}")
                return None
        return None

    def _load_json(self, path):
        if path and Path(path).exists():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Clotho Warning: Failed to load JSON {path}: {e}")
                pass
        return []

    def _identify_host(self):
        if self.args.input:
            host_info_path = Path(self.args.input).parent / "Host_Identity.json"
            if host_info_path.exists():
                try:
                    with open(host_info_path, "r") as f:
                        data = json.load(f)
                        self.hostname = data.get("Hostname", "Unknown_Host")
                    print(f"   -> Host Identity Found (from JSON): {self.hostname}")
                    return
                except: pass

    def _enrich_5w1h(self, df, source_name):
        target_cols = ["Auth_Domain", "Auth_User", "Src_Host", "Logon_Type"]
        for col in target_cols:
            if col not in df.columns:
                df = df.with_columns(pl.lit(None).cast(pl.Utf8).alias(col))

        df = df.with_columns(pl.col("Src_Host").fill_null(self.hostname))

        if "User" in df.columns:
            df = df.with_columns([
                pl.when(pl.col("User").str.contains(r"\\"))
                .then(pl.col("User").str.extract(r"^([^\\]+)\\", 1))
                .otherwise(pl.lit("Local"))
                .alias("Extracted_Domain"),
                
                pl.when(pl.col("User").str.contains(r"\\"))
                .then(pl.col("User").str.extract(r"\\(.+)$", 1))
                .otherwise(pl.col("User"))
                .alias("Extracted_User")
            ])
            
            df = df.with_columns([
                pl.coalesce(["Auth_Domain", "Extracted_Domain"]).alias("Auth_Domain"),
                pl.coalesce(["Auth_User", "Extracted_User"]).alias("Auth_User")
            ]).drop(["Extracted_Domain", "Extracted_User"])

        df = df.with_columns([
            pl.col("Auth_Domain").fill_null("Local"),
            pl.col("Auth_User").fill_null("System/Unknown")
        ])

        return df
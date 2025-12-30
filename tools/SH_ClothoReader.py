import polars as pl
import json
from pathlib import Path
import sys

# ============================================================
#  SH_ClothoReader v1.0 [The Spinner]
#  Mission: Normalize & Ingest all forensic artifacts.
# ============================================================

class ClothoReader:
    """
    [Clotho: The Spinner]
    運命の糸（ログ）を紡ぎ出し、解析可能な状態（DataFrame）に正規化するクラス。
    全てのデータソースの読み込みと、ホスト名の特定を担当する。
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
        
        # 2. Network (Often derived from Hercules Timeline in Legacy Hekate)
        # ネットワーク分析用にTimelineと同じデータを保持、またはPlutosNetを優先
        self.dfs['Network'] = self._safe_load(self.args.input)

        # 3. Dedicated Artifacts
        # AION (Persistence) - Support legacy arg name 'persistence' too
        aion_path = getattr(self.args, 'aion', None) or getattr(self.args, 'persistence', None)
        self.dfs['AION'] = self._safe_load(aion_path)
        
        self.dfs['Pandora']   = self._safe_load(getattr(self.args, 'pandora', None))
        
        # Plutos (Lateral/Internal) & PlutosNet
        self.dfs['Plutos']    = self._safe_load(getattr(self.args, 'plutos', None))
        self.dfs['PlutosNet'] = self._safe_load(getattr(self.args, 'plutos_net', None))
        
        self.dfs['Sphinx']    = self._safe_load(getattr(self.args, 'sphinx', None))
        self.dfs['Chronos']   = self._safe_load(getattr(self.args, 'chronos', None))
        self.dfs['Prefetch']  = self._safe_load(getattr(self.args, 'prefetch', None))

        # 4. JSON Data (SirenHunt)
        self.siren_data = self._load_json(getattr(self.args, 'siren', None))

        # 5. Identify Host
        self._identify_host()

        return self.dfs, self.siren_data, self.hostname

    def _safe_load(self, path):
        """CSVを安全に読み込む（型推論エラー回避のため全カラム文字列として読む場合あり）"""
        if path and Path(path).exists():
            try:
                # infer_schema_length=0 で全カラムを文字列として読み込み、パースエラーを防ぐ
                return pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
            except Exception as e:
                print(f"[!] Clotho Warning: Failed to load CSV {path}: {e}")
                return None
        return None

    def _load_json(self, path):
        """JSONを安全に読み込む"""
        if path and Path(path).exists():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Clotho Warning: Failed to load JSON {path}: {e}")
                pass
        return []

    def _identify_host(self):
        """
        ホスト名を特定する。
        1. 入力CSVディレクトリにある 'Host_Identity.json' (Herculesが生成) を優先
        2. Timeline CSVの中身から推測 (Fallback)
        """
        # Strategy 1: Host_Identity.json
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
        
        # Strategy 2: Extract from HERCULES Timeline (Target Host column often exists in reports but not raw CSV)
        # ここでは簡易的なフォールバックとして、ファイル名や親フォルダ名を使う手もあるが、
        # HerculesRefereeが必ずJSONを吐くようになったので、基本はStrategy 1でカバーできるはず。
        pass
import polars as pl
from pathlib import Path
import argparse
import re
import sys
import os
import datetime

# ==========================================
#  SH_ChaosGrasp v9.3 [Coin Slayer Edition]
#  Mission: Devour All Artifacts & Expose Lies
#  Updated: 2025-12-24 (Grok-Review Patch + NetworkPath)
# ==========================================

def print_logo():
    print(r"""
   (  )   (   )  )
    ) (   )  (  (
    ( )  (    ) )
    _____________
   <  ChaosGrasp >  v9.3
    -------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
    "Order out of Chaos."
    """)

# ==========================================
#  The Iron Schema v1.1 (Target Output)
# ==========================================
REQUIRED_SCHEMA = {
    "Timestamp_UTC": pl.Datetime("ns"),
    "Timestamp_Local": pl.Datetime("ns"),
    "Timezone_Bias": pl.Int64,
    "Time_Type": pl.Utf8,
    "Artifact_Type": pl.Utf8,
    "Action": pl.Utf8,
    "User": pl.Utf8,
    "Target_Path": pl.Utf8,
    "Source_File": pl.Utf8,
    "Evidence_ID": pl.Utf8,    # Hekateで発番するが、枠だけ作る
    "Verify_Cmd": pl.Utf8,     # Plan B用
    "Tag": pl.Utf8             # [EXEC]等
}

class ChaosGrasp:
    def __init__(self, target_dir, chronos_csv=None):
        self.target_dir = Path(target_dir)
        self.chronos_csv = chronos_csv
        self.lazy_plans = []
        self.timezone_offset = 0 # Default UTC (0 min)
        # Polars設定: 文字列省略なし
        pl.Config.set_fmt_str_lengths(100)

    def identify_artifact(self, file_path):
        """
        Identify artifact type by Filename OR Header.
        """
        fname = file_path.name.lower()
        
        # 1. Filename Match (Strong Indicators)
        if "userassist" in fname: return "USER_ASSIST"
        if "prefetch" in fname: return "PREFETCH"
        if "amcache" in fname: return "AMCACHE"
        if "recentdocs" in fname: return "RECENT_DOCS"
        
        # [Grok-Fix] Registry系はファイル名で強制判定（ヘッダ欠損対策）
        if "registry" in fname or "system" in fname or "ntuser" in fname:
            return "REGISTRY"

        # 2. Header Match (Fallback)
        try:
            with open(file_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
                header = f.readline().strip()
            
            if "ValueDataRaw" in header and "BatchKeyPath" in header: return "REGISTRY"
            if ("RunCounter" in header or "Count" in header) and ("ProgramName" in header or "ValueName" in header): return "USER_ASSIST"
            if ("SourceFilename" in header or "ExecutableName" in header) and "RunCount" in header: return "PREFETCH"
            if "KeyLastWriteTimestamp" in header or "FileKeyLastWriteTimestamp" in header: return "AMCACHE"
            # [Fix] LECmd header variation
            if "TargetName" in header or "LnkName" in header or ("SourceFile" in header and "TargetCreated" in header): return "RECENT_DOCS"
            
            return None
        except: return None

    def scan_environment(self):
        print("[*] Scanning for Environment Config (Timezone)...")
        # Registryファイルを探してActiveTimeBiasを取得
        # ※簡易実装: Registry_System*.csv を探す
        reg_files = list(self.target_dir.rglob("*Registry*.csv"))
        for p in reg_files:
            if "TimeZoneInformation" in str(p) or "System" in str(p):
                try:
                    # Registryは通常小さいのでread_csvでOK
                    df = pl.read_csv(p, ignore_errors=True)
                    # ValueNameがActiveTimeBiasの行を探す
                    bias_row = df.filter(pl.col("ValueName") == "ActiveTimeBias")
                    if not bias_row.is_empty():
                        # ValueDataは通常文字列だが、数値の場合もある
                        val = bias_row["ValueData"][0]
                        self.timezone_offset = int(val)
                        print(f"[+] Timezone Bias Detected: {self.timezone_offset} min")
                        return
                except: pass
        
        print("[!] Warning: Timezone Registry not found. Assuming UTC (Bias: 0).")

    def plan_artifacts(self):
        print(f"[*] Scanning artifacts in: {self.target_dir}")
        # ファイル単体指定への対応はargparse側で行う前提とし、ここはrglobで回す
        for csv_path in self.target_dir.rglob("*.csv"):
            artifact_type = self.identify_artifact(csv_path)
            if not artifact_type: continue
            
            # Lazy Scan
            lf = pl.scan_csv(csv_path, infer_schema_length=0, ignore_errors=True)

            # 各アーティファクト処理（エラーハンドリング強化）
            try:
                if artifact_type == "USER_ASSIST": self._add_user_assist(lf, csv_path)
                elif artifact_type == "PREFETCH": self._add_prefetch(lf, csv_path)
                elif artifact_type == "AMCACHE": self._add_amcache(lf, csv_path)
                elif artifact_type == "RECENT_DOCS": self._add_recent_docs(lf, csv_path)
                # Registry全般は個別にハンドラを書くか、汎用ハンドラへ（今回は省略）
            except Exception as e:
                print(f"[!] Failed to plan {csv_path.name}: {e}")

        print(f"[+] {len(self.lazy_plans)} artifacts queued for timeline.")

    def _get_col(self, lf, candidates, default=None):
        """Helper to find available column from candidates"""
        schema = lf.collect_schema().names()
        for c in candidates:
            if c in schema:
                return pl.col(c)
        return pl.lit(default) if default else None

    def _common_transform(self, lf, time_col_name, user_val, type_val, action_expr, filename_expr, time_type_str):
        # Time column check
        schema = lf.collect_schema().names()
        if time_col_name not in schema: return None

        # [Grok-Fix] Robust Time Parsing
        raw_time = pl.col(time_col_name)
        parsed_time = pl.coalesce([
            raw_time.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
            raw_time.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
            raw_time.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
            raw_time.str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False)
        ])
        
        # [Schema v1.1] Timezone Logic
        # バイアス(分)を保持
        bias_val = self.timezone_offset
        
        # UTC計算 (ローカル時間からバイアスを引く/足す処理だが、ここでは「入力はUTCかLocalか」問題がある)
        # 仮定: KAPE出力は基本的にUTCが多いが、Biasを使ってLocalを算出する
        # ここでは「パースされた時間はUTC」と仮定し、そこからLocalを算出するロジックとする
        # Local = UTC - Bias (BiasはUTCからの差分。JSTは-540。UTC - (-540) = UTC+9h ? )
        # WindowsのActiveTimeBiasは "UTC = Local + Bias" なので "Local = UTC - Bias"
        
        utc_time = parsed_time
        local_time = parsed_time - pl.duration(minutes=bias_val)

        # Target_FileNameを小文字化
        target_fname = filename_expr.str.to_lowercase().alias("Target_Path")
        fname_only = filename_expr.str.split("\\").list.last().alias("File_Name")

        return lf.filter(parsed_time.is_not_null()).select([
            utc_time.alias("Timestamp_UTC"),
            local_time.alias("Timestamp_Local"),
            pl.lit(bias_val).alias("Timezone_Bias"),
            pl.lit(time_type_str).alias("Time_Type"),
            pl.lit(type_val).alias("Artifact_Type"),
            action_expr.alias("Action"),
            pl.lit(user_val).alias("User"),
            target_fname,
            fname_only,
            pl.lit(str(self.target_dir)).alias("Source_File"), # 実際はcsv_pathを入れたい
            pl.lit(None).cast(pl.Utf8).alias("Evidence_ID"),
            pl.lit(None).cast(pl.Utf8).alias("Verify_Cmd"),
            pl.lit(None).cast(pl.Utf8).alias("Tag")
        ])

    def _add_user_assist(self, lf, path):
        m = re.search(r'Users_([^_]+)_NTUSER', str(path), re.IGNORECASE)
        user = m.group(1) if m else "Unknown"
        
        # [Grok-Fix] カラム名柔軟化
        name_col = self._get_col(lf, ["ProgramName", "ValueName"], "Unknown_Program")
        count_col = self._get_col(lf, ["RunCounter", "Count"], "0")
        time_col = self._get_col(lf, ["LastExecuted", "LastExecutionTime", "LastUpdated"], None)
        
        if time_col is None: return # 時刻なしはスキップ

        # Colオブジェクトから文字列名を取得するのは面倒なので、_get_colが返したColの名前を知る必要がある
        # 簡易的に、スキーマから探して文字列として渡す
        schema = lf.collect_schema().names()
        t_name = "LastExecuted"
        for c in ["LastExecuted", "LastExecutionTime", "LastUpdated"]:
            if c in schema: t_name = c; break

        filename_expr = name_col
        action = name_col + pl.lit(" (Run: ") + count_col.cast(pl.Utf8) + pl.lit(")")
        
        # csv_pathをSource_Fileに入れるためにwith_columnsで上書き
        plan = self._common_transform(lf, t_name, user, "UserAssist", action, filename_expr, "Execution")
        if plan is not None:
            plan = plan.with_columns(pl.lit(str(path)).alias("Source_File"))
            self.lazy_plans.append(plan)

    def _add_prefetch(self, lf, path):
        name_col = self._get_col(lf, ["ExecutableName", "SourceFilename"], "Unknown.exe")
        count_col = self._get_col(lf, ["RunCount"], "0")
        
        filename_expr = name_col
        action = name_col + pl.lit(" (Run: ") + count_col.cast(pl.Utf8) + pl.lit(")")
        
        plan = self._common_transform(lf, "LastRun", "System", "Prefetch", action, filename_expr, "Execution")
        if plan is not None:
            plan = plan.with_columns([
                pl.lit(str(path)).alias("Source_File"),
                (pl.lit("[EXEC] ") + pl.col("Action")).alias("Tag") # Tag付け
            ])
            self.lazy_plans.append(plan)

    def _add_recent_docs(self, lf, path):
        m = re.search(r'Users_([^_]+)_NTUSER', str(path), re.IGNORECASE)
        user = m.group(1) if m else "Unknown"
        
        schema = lf.collect_schema().names()
        
        # [Fix] LECmd NetworkPath Support (Coalesce)
        name_expr = pl.coalesce([
            pl.col("TargetName") if "TargetName" in schema else None,
            pl.col("LocalPath") if "LocalPath" in schema else None,
            pl.col("NetworkPath") if "NetworkPath" in schema else None,
            pl.col("SourceFile") # Fallback
        ]).fill_null("Unknown_Target")
        
        filename_expr = name_expr
        action = pl.lit("Opened: ") + name_expr
        
        if "Arguments" in schema:
            action = action + pl.lit(" [Args: ") + pl.col("Arguments").fill_null("") + pl.lit("]")

        if "SourceAccessed" in schema: time_col = "SourceAccessed"
        elif "LastAccessed" in schema: time_col = "LastAccessed"
        else: time_col = "LastAccessed"

        plan = self._common_transform(lf, time_col, user, "RecentDocs", action, filename_expr, "File_Access")
        if plan is not None:
            plan = plan.with_columns(pl.lit(str(path)).alias("Source_File"))
            self.lazy_plans.append(plan)

    def _add_amcache(self, lf, path):
        cols = lf.collect_schema().names()
        time_col = "FileKeyLastWriteTimestamp" if "FileKeyLastWriteTimestamp" in cols else "KeyLastWriteTimestamp"
        
        name_col = self._get_col(lf, ["Name", "FileName", "ProgramName"], "Unknown_App")
        filename_expr = name_col
        
        plan = self._common_transform(lf, time_col, "System", "Amcache", name_col, filename_expr, "Artifact_Write")
        if plan is not None:
            plan = plan.with_columns(pl.lit(str(path)).alias("Source_File"))
            self.lazy_plans.append(plan)

    def _enforce_schema(self, lf):
        """Final Schema Enforcement"""
        # 必要なカラムがなければnullで作成、型キャスト、並び順統一
        exprs = []
        schema = lf.collect_schema().names()
        
        for col, dtype in REQUIRED_SCHEMA.items():
            if col in schema:
                exprs.append(pl.col(col).cast(dtype))
            else:
                exprs.append(pl.lit(None).cast(dtype).alias(col))
        
        return lf.select(exprs)

    def _merge_chronos(self, master_lf):
        # ... (Previous ChronosSift logic - kept simple for v9.3)
        # 今回はスキーマが変わったのでActionへの注入ロジックのみ維持
        try:
            if not self.chronos_csv: return master_lf
            print(f"[*] Linking ChronosSift result: {self.chronos_csv}")
            # Note: ChronosSiftの出力形式に合わせて調整が必要
            # ここでは簡易的にスキップ（Hekate側でやるのが正解かも）
            return master_lf
        except: return master_lf

    def execute(self, output_path):
        if not self.lazy_plans:
            print("[-] No artifacts found to process.")
            return

        print("[*] Igniting Chaos Engine (v9.3)...")
        try:
            # 1. Concat & Unique
            master_lf = pl.concat(self.lazy_plans)
            
            # 2. Schema Enforcement
            master_lf = self._enforce_schema(master_lf)
            
            # 3. Chronos Merge (Optional)
            master_lf = self._merge_chronos(master_lf)

            # 4. Sort
            master_lf = master_lf.sort("Timestamp_UTC", descending=True)

            # 5. Sink
            master_lf.sink_csv(output_path)
            print(f"[+] Timeline materialized: {output_path}")
        except Exception as e:
            print(f"[!] Processing failed ({e}).")
            import traceback
            traceback.print_exc()

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", required=True, help="KAPE Output Directory")
    parser.add_argument("-c", "--chronos", help="ChronosSift Result CSV (Optional)")
    parser.add_argument("-o", "--out", default="Chaos_MasterTimeline_v9.3.csv")
    args = parser.parse_args(argv)
    
    grasper = ChaosGrasp(args.dir, args.chronos)
    grasper.scan_environment()
    grasper.plan_artifacts()
    grasper.execute(args.out)

if __name__ == "__main__":
    main()
import polars as pl
import argparse
import sys
import os
import re
from tools.SH_ThemisLoader import ThemisLoader
from tools.SH_HestiaCensorship import Hestia

# ============================================================
#  SH_ChronosSift v3.2 [Time Lord Edition]
#  Mission: Detect Time Anomalies & Contextualize Time Changes
#  Update: Fix ColumnNotFoundError & Logic Order for VBoxService.
# ============================================================

def print_logo():
    print(r"""
       (   )
      (  :  )   < CHRONOS SIFT >
       (   )     v3.2 - Time Lord
        " "      "Time bows to the Law."
    """)

class ChronosEngine:
    def __init__(self, tolerance=10.0):
        self.tolerance = tolerance
        self.hestia = Hestia()
        
        # 正規の時刻同期プロセス定義 (プロセス名: [許可されるパスの正規表現リスト])
        self.ALLOWED_TIME_AGENTS = {
            "vboxservice.exe": [r"program files.*oracle.*virtualbox", r"system32"],
            "vmtoolsd.exe": [r"program files.*vmware", r"system32"],
            "w32tm.exe": [r"system32"],
            "svchost.exe": [r"system32"] 
        }

    def _ensure_columns(self, lf):
        """カラムの存在を保証する（Threat_Tagの初期化を含む）"""
        cols = lf.collect_schema().names()
        
        if "ParentPath" not in cols and "Target_Path" in cols:
            print("    -> [Chronos] Splitting Target_Path into ParentPath/FileName...")
            lf = lf.with_columns(
                pl.col("Target_Path").str.replace_all(r"/", "\\") 
            )
            lf = lf.with_columns([
                pl.col("Target_Path").str.split("\\").list.get(-1).alias("FileName"),
                pl.col("Target_Path").str.split("\\").list.slice(0, -1).list.join("\\").alias("ParentPath")
            ])
        
        # [CRITICAL FIX] Threat_Tag を事前に作成してクラッシュを防ぐ
        expected = ["ParentPath", "FileName", "Action", "Tag", "Threat_Score", "Threat_Tag", "Anomaly_Time"]
        
        cols = lf.collect_schema().names()
        for c in expected:
            if c not in cols: 
                if c == "Threat_Score":
                    lf = lf.with_columns(pl.lit(0).alias(c))
                else:
                    lf = lf.with_columns(pl.lit("").alias(c))
            
        return lf

    def _detect_usn_rollback(self, lf):
        """USNジャーナルの「時間の逆行」を検知する"""
        cols = lf.collect_schema().names()
        if "UpdateSequenceNumber" not in cols or "UpdateTimestamp" not in cols:
            return lf

        print("    -> [Chronos] USN Journal detected. Scanning for Time Paradoxes (System Rollback)...")
        
        lf = lf.with_columns(
            pl.col("UpdateSequenceNumber").cast(pl.Int64, strict=False).alias("UpdateSequenceNumber_Int")
        )
        lf = lf.with_columns(
            pl.col("UpdateTimestamp").str.replace("T", " ").str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("_dt")
        )

        lf = lf.sort("UpdateSequenceNumber_Int")
        lf = lf.with_columns([
            pl.col("_dt").shift(1).alias("_prev_dt"),
        ])

        rollback_threshold = -1.0 * 60 

        lf = lf.with_columns(
            (pl.col("_dt") - pl.col("_prev_dt")).dt.total_seconds().alias("_time_diff")
        )

        lf = lf.with_columns(
            pl.when(pl.col("_time_diff") < rollback_threshold)
              .then(pl.lit("CRITICAL_SYSTEM_ROLLBACK")) 
              .otherwise(pl.col("Anomaly_Time"))
              .alias("Anomaly_Time")
        )

        lf = lf.with_columns(
            pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK")
              .then(300) 
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score")
        )
        
        lf = lf.with_columns(
            pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK")
              .then(pl.format("{} (Rollback: {} sec)", pl.col("FileName"), pl.col("_time_diff")))
              .otherwise(pl.col("FileName"))
              .alias("FileName")
        )

        return lf.drop(["_dt", "_prev_dt", "_time_diff", "UpdateSequenceNumber_Int"])

    def _detect_system_time_context(self, lf):
        """
        Themisスコアリングの「後」に実行。
        正規のVBoxServiceなどを救済（Score 0化）し、未知のツールを断罪（Score 300維持/付与）する。
        """
        print("    -> [Chronos] Contextualizing System Time Changes (VM Sync vs Attack)...")
        
        is_time_event = (
            pl.col("Action").str.to_lowercase().str.contains("system time|change") |
            pl.col("Tag").str.contains("4616|TIME")
        )

        # デフォルトは「黒（攻撃）」
        base_score = pl.lit(300)
        base_tag = pl.lit("CRITICAL_TIMESTOMP_ATTEMPT")

        # ホワイトリスト判定
        is_legit = pl.lit(False)
        for agent, paths in self.ALLOWED_TIME_AGENTS.items():
            name_match = pl.col("FileName").str.to_lowercase().str.contains(agent)
            path_match = pl.lit(False)
            for p in paths:
                path_match = path_match | pl.col("ParentPath").str.to_lowercase().str.contains(p)
            
            is_legit = is_legit | (name_match & path_match)

        # スコア書き換え（正規なら0点、それ以外は300点または維持）
        lf = lf.with_columns([
            pl.when(is_time_event)
              .then(
                  pl.when(is_legit)
                    .then(0) # 正規なら0点
                    .otherwise(300) # 偽装or不明なら300点
              )
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score"),
            
            pl.when(is_time_event)
              .then(
                  pl.when(is_legit)
                    .then(pl.lit("INFO_VM_TIME_SYNC"))
                    .otherwise(pl.lit("CRITICAL_TIMESTOMP_ATTEMPT"))
              )
              .otherwise(pl.col("Threat_Tag"))
              .alias("Threat_Tag")
        ])

        return lf

    def _apply_safety_filters(self, df):
        print("    -> [Chronos] Applying Safety Filters (Brutal Mode)...")
        
        df = df.with_columns([
            pl.col("ParentPath").fill_null("").str.to_lowercase().alias("_pp"),
            pl.col("FileName").fill_null("").str.to_lowercase().alias("_fn")
        ])
        
        kill_keywords = [
            "ccleaner", "jetico", "bcwipe", "dropbox", 
            "skype", "onedrive", "google", "adobe", 
            "mozilla", "firefox", 
            # "vbox", "virtualbox", <--- 削除！Context判定に任せるためここでは消さない
            "notepad++", "intel", "mcafee", "true key",
            "microsoft analysis services", "as oledb",
            "windows defender", "windows media player",
            "windows journal", "winsat", "toastdata",
            "package repository", "installshield",
            "assembly", "servicing", "winsxs", "microsoft.net",
            "windows/installer", "windows\\installer",
            "programdata/microsoft/windows", "programdata\\microsoft\\windows",
            "appdata/local/temp", "appdata\\local\\temp",
            "appdata/local/microsoft/windows", "appdata\\local\\microsoft\\windows",
            "windows/system32/config", "windows\\system32\\config"
        ]
        
        file_kill_list = ["desktop.ini", "thumbs.db", "ntuser.dat", "usrclass.dat", "iconcache.db"]
        dual_use_folders = ["nmap", "wireshark", "python", "perl", "ruby", "tor browser"]
        protected_binaries = ["nmap.exe", "zenmap.exe", "ncat.exe", "python.exe", "pythonw.exe", "tor.exe"]

        is_noise = pl.lit(False)
        for kw in kill_keywords:
            is_noise = is_noise | pl.col("_pp").str.contains(kw, literal=True)
        for kw in file_kill_list:
            is_noise = is_noise | pl.col("_fn").str.contains(kw, literal=True)

        is_tool_folder = pl.lit(False)
        for tool in dual_use_folders:
            is_tool_folder = is_tool_folder | pl.col("_pp").str.contains(tool, literal=True)
            
        is_protected = pl.col("_fn").is_in(protected_binaries)
        is_noise = is_noise | (is_tool_folder & (~is_protected))

        # CRITICALタグがついているものはノイズ判定を強制キャンセル
        is_critical_context = pl.col("Threat_Tag").str.contains("CRITICAL")

        df = df.with_columns([
            pl.when(is_noise & (~is_critical_context)) 
              .then(pl.lit("NOISE_ARTIFACT"))
              .otherwise(pl.col("Threat_Tag"))
              .alias("Threat_Tag"),
            
            pl.when(is_noise & (~is_critical_context))
              .then(0)
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score")
        ])

        return df.drop(["_pp", "_fn"])

    def analyze(self, args):
        mode_str = "LEGACY" if args.legacy else "STANDARD"
        print(f"[*] Chronos v3.2 awakening... Mode: {mode_str}")
        try:
            loader = ThemisLoader(["rules/triage_rules.yaml", "rules/sigma_file_event.yaml"])
            lf = pl.scan_csv(args.file, ignore_errors=True, infer_schema_length=0)
            
            # 1. カラム保証 (Threat_Tag作成)
            lf = self._ensure_columns(lf)

            # 2. USN ロールバック検知
            lf = self._detect_usn_rollback(lf)
            
            # 3. Themis脅威スコアリング (ルールベース)
            print("    -> Applying Themis Threat Scoring...")
            lf = loader.apply_threat_scoring(lf)
            
            if "Threat_Score" in lf.collect_schema().names():
                lf = lf.with_columns(pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0))

            # 4. [CRITICAL] コンテキスト判定 (Themisの結果を上書き修正)
            # これで VBoxService=0点 に訂正される
            lf = self._detect_system_time_context(lf)

            # 5. 安全フィルタ (ノイズ削除)
            lf = self._apply_safety_filters(lf)
            
            # 6. MFT Timestomp 検知
            cols = lf.collect_schema().names()
            si_cr, fn_cr = "Created0x10", "Created0x30"
            
            if si_cr in cols and fn_cr in cols:
                for col_name in [si_cr, fn_cr]:
                    lf = lf.with_columns(pl.col(col_name).str.replace("T", " "))
                
                lf = lf.with_columns([
                    pl.col(si_cr).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("si_dt"),
                    pl.col(fn_cr).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("fn_dt"),
                ]).drop_nulls(["si_dt", "fn_dt"])

                lf = lf.with_columns((pl.col("fn_dt") - pl.col("si_dt")).dt.total_seconds().alias("diff_sec"))

                lf = lf.with_columns([
                    pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK")
                      .then(pl.lit("CRITICAL_SYSTEM_ROLLBACK"))
                    .when(pl.col("Threat_Tag").str.contains("CRITICAL_TIMESTOMP")) # Context判定の結果を優先
                      .then(pl.lit("CRITICAL_TIMESTOMP_ATTEMPT"))
                    .when((pl.col("Threat_Score") >= 80) & (pl.col("Threat_Tag") != "NOISE_ARTIFACT"))
                      .then(pl.lit("CRITICAL_ARTIFACT"))
                    .when(pl.col("diff_sec") < -60)
                      .then(pl.lit("TIMESTOMP_BACKDATE"))
                    .when(pl.col("diff_sec") > self.tolerance)
                      .then(pl.lit("FALSIFIED_FUTURE"))
                    .otherwise(pl.lit("")).alias("Anomaly_Time"),
                    
                    pl.when(pl.col("si_dt").dt.microsecond() == 0)
                      .then(pl.lit("ZERO_PRECISION"))
                      .otherwise(pl.lit("")).alias("Anomaly_Zero")
                ])
                
                score_expr = (
                    pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK").then(300)
                    .when(pl.col("Threat_Tag") == "NOISE_ARTIFACT").then(0)
                    .when(pl.col("Threat_Tag") == "INFO_VM_TIME_SYNC").then(0) # 正規同期は0点
                    .when(pl.col("Threat_Tag").str.contains("CRITICAL")).then(300) 
                    .when(pl.col("Anomaly_Time") == "CRITICAL_ARTIFACT").then(200)
                    .when(pl.col("Anomaly_Time") == "TIMESTOMP_BACKDATE").then(100)
                    .otherwise(0)
                )
                lf = lf.with_columns(score_expr.alias("Chronos_Score"))
            else:
                print("    [!] MFT Timestamps not found. Skipping Standard Timestomp detection.")
                lf = lf.with_columns([
                    pl.col("Anomaly_Time").fill_null("").alias("Anomaly_Time"),
                    pl.col("Threat_Score").alias("Chronos_Score")
                ])

            df = lf.filter(pl.col("Chronos_Score") > 0).collect()

            if "ParentPath" in df.columns:
                df = self.hestia.apply_censorship(df, "ParentPath", "FileName")
            
            if df.height > 0:
                df = df.sort("Chronos_Score", descending=True)
                df.write_csv(args.out)
                print(f"[+] Anomalies detected: {df.height}")
            else:
                print("\n[*] Clean: No significant anomalies found.")
                pl.DataFrame({"Chronos_Score": [], "Anomaly_Time": [], "FileName": [], "ParentPath": []}).write_csv(args.out)

        except Exception as e:
            print(f"[!] Chronos Error: {e}")
            import traceback
            traceback.print_exc()

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-o", "--out", default="Chronos_Results.csv")
    parser.add_argument("-t", "--tolerance", type=float, default=10.0)
    parser.add_argument("--legacy", action="store_true")
    parser.add_argument("--targets-only", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--start", help="Ignored")
    parser.add_argument("--end", help="Ignored")
    args = parser.parse_args(argv)
    
    engine = ChronosEngine(args.tolerance)
    engine.analyze(args)

if __name__ == "__main__":
    main()
import polars as pl
import argparse
import sys
import os
from tools.SH_ThemisLoader import ThemisLoader
from tools.SH_HestiaCensorship import Hestia

# ============================================================
#  SH_ChronosSift v23.18 [Time Paradox]
#  Mission: Detect Time Anomalies & System Rollbacks.
#  Update: Added USN Journal Rollback Detection logic.
# ============================================================

def print_logo():
    print(r"""
       (   )
      (  :  )   < CHRONOS SIFT >
       (   )     v23.18 - Time Paradox
        " "      "Time bows to the Law."
    """)

class ChronosEngine:
    def __init__(self, tolerance=10.0):
        self.tolerance = tolerance
        self.hestia = Hestia()

    def _ensure_columns(self, lf):
        """Target_PathからParentPathとFileNameを生成する"""
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
        
        cols = lf.collect_schema().names()
        if "ParentPath" not in cols: lf = lf.with_columns(pl.lit("UNKNOWN").alias("ParentPath"))
        if "FileName" not in cols: lf = lf.with_columns(pl.lit("UNKNOWN").alias("FileName"))
            
        return lf

    # [NEW] USNジャーナルの「時間の逆行」を検知するメソッド
    def _detect_usn_rollback(self, lf):
        cols = lf.collect_schema().names()
        
        # USNジャーナルの必須カラムがあるか確認 ($J CSVなど)
        if "UpdateSequenceNumber" not in cols or "UpdateTimestamp" not in cols:
            return lf

        print("    -> [Chronos] USN Journal detected. Scanning for Time Paradoxes (System Rollback)...")
        
        # [FIX] USNをInt64にキャスト！これがないと文字列ソートになって時系列が壊れる！
        lf = lf.with_columns(
            pl.col("UpdateSequenceNumber").cast(pl.Int64, strict=False).alias("UpdateSequenceNumber_Int")
        )

        # 時刻変換
        lf = lf.with_columns(
            pl.col("UpdateTimestamp").str.replace("T", " ").str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("_dt")
        )

        # [FIX] Int化したUSNでソート
        lf = lf.sort("UpdateSequenceNumber_Int")
        lf = lf.with_columns([
            pl.col("_dt").shift(1).alias("_prev_dt"),
            # pl.col("UpdateSequenceNumber").shift(1).alias("_prev_usn")
        ])

        # 判定ロジック: 
        # tolerance (default 10.0s) よりも大きく「マイナス」になった場合を検知
        # 誤検知回避のため、-60秒以上の巻き戻しを異常とみなす
        rollback_threshold = -1.0 * 60 

        lf = lf.with_columns(
            (pl.col("_dt") - pl.col("_prev_dt")).dt.total_seconds().alias("_time_diff")
        )

        # Anomaly_Time カラムがなければ作成
        if "Anomaly_Time" not in cols:
            lf = lf.with_columns(pl.lit("").alias("Anomaly_Time"))
        
        if "Threat_Score" not in cols:
            lf = lf.with_columns(pl.lit(0).alias("Threat_Score"))

        lf = lf.with_columns(
            pl.when(pl.col("_time_diff") < rollback_threshold)
              .then(pl.lit("CRITICAL_SYSTEM_ROLLBACK")) # 時間遡行検知タグ
              .otherwise(pl.col("Anomaly_Time"))
              .alias("Anomaly_Time")
        )

        # スコアリングの更新（ROLLBACKは最重要 = 300点）
        lf = lf.with_columns(
            pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK")
              .then(300) 
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score")
        )
        
        # 証跡として「どれくらい戻ったか」をFileName列などに追記
        lf = lf.with_columns(
            pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK")
              .then(pl.format("{} (Rollback: {} sec)", pl.col("FileName"), pl.col("_time_diff")))
              .otherwise(pl.col("FileName"))
              .alias("FileName")
        )

        return lf.drop(["_dt", "_prev_dt", "_time_diff", "UpdateSequenceNumber_Int"])

    def _apply_safety_filters(self, df):
        print("    -> [Chronos] Applying Safety Filters (Brutal Mode)...")
        
        df = df.with_columns([
            pl.col("ParentPath").fill_null("").str.to_lowercase().alias("_pp"),
            pl.col("FileName").fill_null("").str.to_lowercase().alias("_fn")
        ])
        
        kill_keywords = [
            "ccleaner", "jetico", "bcwipe", "dropbox", 
            "skype", "onedrive", "google", "adobe", 
            "mozilla", "firefox", "vbox", "virtualbox",
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
        
        dual_use_folders = [
            "nmap", "wireshark", "python", "tcl", "ruby", "perl", "java", "jdk", "jre",
            "tor browser"
        ]
        
        protected_binaries = [
            "nmap.exe", "zenmap.exe", "ncat.exe", 
            "wireshark.exe", "tshark.exe", "capinfos.exe", "dumpcap.exe",
            "python.exe", "pythonw.exe", "pip.exe",
            "java.exe", "javaw.exe", "javac.exe",
            "ruby.exe", "perl.exe",
            "tor.exe", "firefox.exe"
        ]

        file_kill_list = [
            "fm20.dll", "ven2232.olb", "mofygdvh.mcp", 
            "shatbbms.dif", "vkorppvhkxuvqcvj",
            "desktop.ini", "thumbs.db", "iconcache.db",
            "ntuser.dat", "usrclass.dat", 
            "edb.log", "edb.chk", "edb0",
            "gdipfontcache"
        ]

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

        df = df.with_columns([
            pl.when(is_noise).then(pl.lit("NOISE_ARTIFACT")).otherwise(pl.col("Threat_Tag")).alias("Threat_Tag"),
            pl.when(is_noise).then(0).otherwise(pl.col("Threat_Score")).alias("Threat_Score")
        ])

        return df.drop(["_pp", "_fn"])

    def analyze(self, args):
        mode_str = "LEGACY" if args.legacy else "STANDARD"
        print(f"[*] Chronos v23.18 awakening... Mode: {mode_str}")
        try:
            loader = ThemisLoader(["rules/triage_rules.yaml", "rules/sigma_file_event.yaml"])
            lf = pl.scan_csv(args.file, ignore_errors=True, infer_schema_length=0)
            
            # [FIX] Ensure columns exist before processing
            lf = self._ensure_columns(lf)

            # [NEW] USN Rollback Check (Detect Time Paradox BEFORE filtering)
            lf = self._detect_usn_rollback(lf)
            
            # [FIX] Ensure Anomaly_Time exists even if USN logic skipped it
            if "Anomaly_Time" not in lf.collect_schema().names():
                lf = lf.with_columns(pl.lit("").alias("Anomaly_Time"))
            
            print("    -> Applying Themis Threat Scoring...")
            lf = loader.apply_threat_scoring(lf)
            
            if "Threat_Score" in lf.collect_schema().names():
                lf = lf.with_columns(pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0))

            lf = self._apply_safety_filters(lf)
            
            cols = lf.collect_schema().names()
            
            si_cr = "Created0x10"
            fn_cr = "Created0x30"
            
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
                
                is_legacy_date = (
                    (pl.col("fn_dt").dt.year() < 2012) |
                    (pl.col("fn_dt").dt.year().is_in([1601, 1980, 2000, 1986])) |
                    (pl.col("fn_dt").dt.strftime("%m-%d") == "04-30")
                )
                lf = lf.with_columns(
                    pl.when(is_legacy_date & (pl.col("Anomaly_Time") == "FALSIFIED_FUTURE"))
                    .then(pl.lit("LEGACY_BUILD"))
                    .otherwise(pl.col("Anomaly_Time"))
                    .alias("Anomaly_Time")
                )
                
                score_expr = (
                    pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK").then(300)
                    .when(pl.col("Threat_Tag") == "NOISE_ARTIFACT").then(0)
                    .when(pl.col("Anomaly_Time") == "LEGACY_BUILD").then(10)
                    .when(pl.col("Anomaly_Time") == "CRITICAL_ARTIFACT").then(200)
                    .when(pl.col("Anomaly_Time") == "TIMESTOMP_BACKDATE").then(100)
                    .when(pl.col("Anomaly_Time") == "FALSIFIED_FUTURE").then(80)
                    .when(pl.col("Anomaly_Zero") == "ZERO_PRECISION").then(50)
                    .otherwise(0)
                )
                lf = lf.with_columns(score_expr.alias("Chronos_Score"))
            else:
                print("    [!] MFT Timestamps (Created0x10/30) not found. Skipping Standard Timestomp detection.")
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
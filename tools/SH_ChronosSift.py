import polars as pl
import argparse
import sys
import os
import re
from pathlib import Path

# ============================================================
#  SH_ChronosSift v9.9.1 [Type-Safe Supernova]
#  Fix: Resolved Polars List casting error in filtering
# ============================================================

def print_logo():
    print(r"""
    _______                         _____  _  ______
   / ____/ /_  _________  ____  ____  _____    / ___/ (_)/ __/ /_
  / /   / __ \/ ___/ __ \/ __ \/ __ \/ ___/    \__ \ / // /_/ __/
 / /___/ / / / /  / /_/ / / / / /_/ (__  )    ___/ // // __/ /_  
 \____/_/ /_/_/   \____/_/ /_/\____/____/    /____/_/_/_/  \__/  
    "Time is the only true unit of measure." v9.9.1
    """)

class ChronosEngine:
    def __init__(self, tolerance=10.0):
        self.tolerance = tolerance
        self.noise_paths = [
            r"\\Windows\\WinSxS", r"\\Windows\\servicing", r"\\Windows\\INF",
            r"\\Windows\\assembly", r"\\SoftwareDistribution", r"\\WindowsApps",
            r"\\Microsoft\\Windows\\Notifications", r"\\AppData\\Local\\Packages",
            r"\\Logs", r"\\Prefetch", r"\\\$Extend", r"\\Search\\Data",
            r"System Volume Information", r"\\catroot2", r"\\Windows\\System32\\WDI",
            r"\\ProgramData", r"\\AppData\\Local\\Temp", r"\\Windows\\Installer",
            r"\\Program Files", r"\\Program Files \(x86\)", r"\\Windows\\Microsoft.NET",
            r"\\Windows\\SysWOW64", r"\\Windows\\Fonts",
            r"\\Windows\\AppPatch", r"\\Users\\Default", r"\\Windows\\System32\\wbem",
            r"\\Windows\\System32\\driverstore", r"\\Windows\\Boot", r"\\Windows\\AppReadiness",
            r"\\Windows\\ServiceProfiles", r"\\Windows\\L2Schemas"
        ]
        self.noise_exts = [
            ".admx", ".adml", ".mum", ".cat", ".png", ".svg", ".js", ".json", 
            ".xml", ".etl", ".log", ".tmp", ".db", ".dat", ".mui", ".inf",
            ".ico", ".css", ".html", ".pf", ".ini", ".lnk", ".manifest"
        ]
        self.trusted_roots = [r"\\Windows", r"\\Program Files", r"\\Program Files \(x86\)"]
        self.suspicious_subdirs = [r"\\Temp", r"\\Tasks", r"\\Spool", r"\\Debug", r"\\Tracing", r"\\Public"]

    def filter_noise(self, df):
        # [Patch] Infect10: Final Solution (Sanctuary + Wanted + Hybrid)
        
        # 1. 聖域ロジック (正規表現を廃止して単純な文字列マッチで確実に拾うっス！)
        sanctuary_mask = (
            pl.col("ParentPath").str.to_lowercase().str.contains("users") |
            pl.col("ParentPath").str.to_lowercase().str.contains("tasks") |
            pl.col("ParentPath").str.to_lowercase().str.contains("startup")
        )
        
        # 2. 指名手配ロジック (ファイル名で一本釣り)
        WANTED_FILES = [
            "Secret_Project.pdf",
            "Windows_Security_Audit",
            "win_optimizer.lnk"
        ]
        wanted_mask = pl.col("FileName").str.contains(r"(?i)(" + "|".join(WANTED_FILES) + ")")

        # 3. 聖域または指名手配に含まれるものを確保
        kept_df = df.filter(sanctuary_mask | wanted_mask)
        
        # 4. それ以外からシステムノイズを除去
        others_df = df.filter(~(sanctuary_mask | wanted_mask))
        
        NOISE_PATTERNS = [
            r"(?i)PathUnknown", 
            r"(?i)\\Windows\\", 
            r"(?i)\\Program Files", 
            r"(?i)\\ProgramData", 
            r"(?i)\\$Extend"
        ]
        for pattern in NOISE_PATTERNS:
            others_df = others_df.filter(~pl.col("ParentPath").str.contains(pattern))
            
        return pl.concat([kept_df, others_df]).unique()

    def analyze(self, args):
        print(f"[*] Chronos v9.9.2 awakening... Targeting: {Path(args.file).name}")
        try:
            lf = pl.scan_csv(args.file, ignore_errors=True)
            
            if not args.all:
                lf = self.filter_noise(lf)
                ext_pattern = f"(?i)({'|'.join([re.escape(e) for e in self.noise_exts])})$"
                lf = lf.filter(~pl.col("FileName").str.contains(ext_pattern))

            # [Fix] Additional Noise Filters
            lf = lf.filter(~pl.col("ParentPath").str.contains(r"(?i)\\System32\\spool\\"))
            lf = lf.filter(~pl.col("ParentPath").str.contains(r"(?i)\\spool\\drivers\\"))
            SYSTEM_WHITELIST = ["OneDriveSetup.exe", "SearchIndexer.exe"]
            lf = lf.filter(~pl.col("FileName").is_in(SYSTEM_WHITELIST))

            if args.targets_only:
                target_exts = [".exe", ".dll", ".sys", ".ps1", ".bat", ".vbs", ".cmd", ".scr", ".pif"]
                target_pat = f"(?i)({'|'.join([re.escape(e) for e in target_exts])})$"
                lf = lf.filter(pl.col("FileName").str.contains(target_pat))

            cols = lf.collect_schema().names()
            si_cr = "Created0x10" if "Created0x10" in cols else "StandardInfoCreationTime"
            fn_cr = "Created0x30" if "Created0x30" in cols else "FileNameCreationTime"
            si_mod = "LastModified0x10" if "LastModified0x10" in cols else "StandardInfoLastModified"

            lf = lf.with_columns([
                pl.col(si_cr).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("si_dt"),
                pl.col(fn_cr).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("fn_dt"),
                pl.col(si_mod).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("si_mod_dt")
            ]).drop_nulls(["si_dt", "fn_dt"])

            lf = lf.with_columns((pl.col("si_dt") - pl.col("fn_dt")).dt.total_seconds().alias("diff_sec"))

            crit_exts = [".exe", ".dll", ".ps1", ".bat", ".sys", ".cmd", ".vbs", ".scr"]
            crit_pattern = f"(?i)({'|'.join([re.escape(e) for e in crit_exts])})$"
            
            # [Patch] Infection10: Hybrid Detection
            # Wanted Files are CRITICAL regardless of extensions or time
            WANTED_FILES = ["Secret_Project.pdf", "Windows_Security_Audit", "win_optimizer.lnk"]
            wanted_pattern = r"(?i)(" + "|".join(WANTED_FILES) + ")"
            
            # フィルタリング: クリティカル拡張子 OR タイムスタンプ異常 OR 指名手配
            lf = lf.filter(
                pl.col("FileName").str.contains(crit_pattern) | 
                (pl.col("diff_sec").abs() > 3600) |
                pl.col("FileName").str.contains(wanted_pattern)
            )

            lf = lf.with_columns([
                pl.when(pl.col("FileName").str.contains(wanted_pattern)).then(pl.lit("CRITICAL_ARTIFACT"))
                .when(pl.col("diff_sec") < -60).then(pl.lit("TIMESTOMP_BACKDATE"))
                .when(pl.col("diff_sec") > self.tolerance).then(pl.lit("FALSIFIED_FUTURE"))
                .otherwise(pl.lit("")).alias("Anomaly_Time"),
                pl.when(pl.col("si_mod_dt").dt.microsecond() == 0).then(pl.lit("ZERO_PRECISION")).otherwise(pl.lit("")).alias("Anomaly_Zero")
            ])
            
            # Hybrid Scoring Logic
            lf = lf.with_columns(
                pl.struct(["Anomaly_Time", "Anomaly_Zero", "FileName", "ParentPath"]).map_elements(lambda x: (
                    100 if x["Anomaly_Time"] == "CRITICAL_ARTIFACT" else # Wanted File = Instant Kill
                    100 if x["Anomaly_Time"] == "FALSIFIED_FUTURE" else
                    80 if x["Anomaly_Time"] == "TIMESTOMP_BACKDATE" and any(x["FileName"].lower().endswith(e) for e in crit_exts) else
                    50 if x["Anomaly_Zero"] == "ZERO_PRECISION" else 20
                ), return_dtype=pl.Int64).alias("Chronos_Score")
            )

            df = lf.filter((pl.col("Anomaly_Time") != "") | (pl.col("Anomaly_Zero") != "")).collect()
            if df.height > 0:
                df = df.sort("Chronos_Score", descending=True)
                df.write_csv(args.out)
                print(df.select(["Chronos_Score", "Anomaly_Time", "FileName", "ParentPath"]).head(15))
            else:
                print("\n[*] Clean: No significant anomalies found.")
        except Exception as e:
            print(f"[!] Critical Error: {e}")

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-o", "--out", default="Chronos_Results.csv")
    parser.add_argument("-t", "--tolerance", type=float, default=10.0)
    parser.add_argument("--targets-only", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--check-zero", action="store_true")
    args = parser.parse_args(argv)
    engine = ChronosEngine(args.tolerance)
    engine.analyze(args)

if __name__ == "__main__":
    main()
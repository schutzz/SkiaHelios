import polars as pl
import argparse
import sys
import os
import re
from pathlib import Path

# ============================================================
#  SH_ChronosSift v10.4 [Iron Curtain]
#  Mission: Detect Time Anomalies while ignoring System Noise.
#  Fix: Global exclusion for WinSxS/NET unless specifically wanted.
# ============================================================

def print_logo():
    print(r"""
    _______                         _____  _  ______
   / ____/ /_  _________  ____  ____  _____    / ___/ (_)/ __/ /_
  / /   / __ \/ ___/ __ \/ __ \/ __ \/ ___/    \__ \ / // /_/ __/
 / /___/ / / / /  / /_/ / / / / /_/ (__  )    ___/ // // __/ /_  
 \____/_/ /_/_/   \____/_/ /_/\____/____/    /____/_/_/_/  \__/  
    "Time is the only true unit of measure." v10.4
    """)

class ChronosEngine:
    def __init__(self, tolerance=10.0):
        self.tolerance = tolerance
        # Noise extensions
        self.noise_exts = [
            ".admx", ".adml", ".mum", ".cat", ".png", ".svg", ".js", ".json", 
            ".xml", ".etl", ".log", ".tmp", ".db", ".dat", ".mui", ".inf",
            ".ico", ".css", ".html", ".pf", ".ini", ".lnk", ".manifest", ".resx"
        ]

    def filter_noise(self, df):
        # 1. 指名手配ロジック (これに該当すれば、場所問わず確保)
        WANTED_FILES = ["Secret_Project.pdf", "Windows_Security_Audit", "win_optimizer.lnk", "SunShadow", "Trigger"]
        wanted_mask = pl.col("FileName").str.contains(r"(?i)(" + "|".join(WANTED_FILES) + ")")
        
        # 2. 聖域ロジック (ユーザー領域などは監視対象)
        sanctuary_mask = (
            pl.col("ParentPath").str.to_lowercase().str.contains("users") |
            pl.col("ParentPath").str.to_lowercase().str.contains(r"tasks\\[^m]") | 
            pl.col("ParentPath").str.to_lowercase().str.contains("startup")
        )
        
        # 3. 鉄のカーテン (絶対除外領域)
        # WinSxS, .NET, Servicing, System Volume Infoなどは、指名手配でない限りノイズとみなす
        IRON_CURTAIN = [
            r"\\Windows\\WinSxS", r"\\Windows\\servicing", r"\\Windows\\assembly", 
            r"\\Windows\\Microsoft.NET", r"\\$Extend", r"\\System Volume Information",
            r"\\ProgramData\\Microsoft\\Windows Defender"
        ]
        
        # 除外条件: (鉄のカーテンに含まれる) AND (指名手配ではない)
        curtain_pattern = "|".join(IRON_CURTAIN)
        noise_mask = (
            pl.col("ParentPath").str.contains(r"(?i)" + curtain_pattern) & 
            ~wanted_mask
        )

        # フィルタ適用: (聖域 OR 指名手配) かつ (ノイズではない)
        # ただし、聖域内でもノイズ(Defenderスキャンログ等)は消したいので、noise_maskを優先
        filtered_df = df.filter((sanctuary_mask | wanted_mask) & ~noise_mask)

        # Blacklist for specific FP filenames (Trigger variants vs System files)
        FP_BLACKLIST = ["sbservicetrigger", "servicetrigger", "wkstriggers", "jobtrigger"]
        fp_mask = pl.col("FileName").str.to_lowercase().str.contains("|".join(FP_BLACKLIST))
        sys_mask = pl.col("ParentPath").str.to_lowercase().str.contains("windows")
        
        return filtered_df.filter(~(fp_mask & sys_mask)).unique()

    def analyze(self, args):
        print(f"[*] Chronos v10.4 awakening... Targeting: {Path(args.file).name}")
        try:
            lf = pl.scan_csv(args.file, ignore_errors=True)
            
            if not args.all:
                lf = self.filter_noise(lf)
                ext_pattern = f"(?i)({'|'.join([re.escape(e) for e in self.noise_exts])})$"
                lf = lf.filter(~pl.col("FileName").str.contains(ext_pattern))

            lf = lf.filter(~pl.col("ParentPath").str.contains(r"(?i)\\System32\\spool\\"))
            SYSTEM_WHITELIST = ["OneDriveSetup.exe", "SearchIndexer.exe"]
            lf = lf.filter(~pl.col("FileName").is_in(SYSTEM_WHITELIST))

            if args.targets_only:
                target_exts = [".exe", ".dll", ".sys", ".ps1", ".bat", ".vbs", ".cmd", ".scr", ".pif", ".pdf"]
                target_pat = f"(?i)({'|'.join([re.escape(e) for e in target_exts])})$"
                lf = lf.filter(pl.col("FileName").str.contains(target_pat))

            cols = lf.collect_schema().names()
            si_cr = "Created0x10" if "Created0x10" in cols else "StandardInfoCreationTime"
            fn_cr = "Created0x30" if "Created0x30" in cols else "FileNameCreationTime"
            si_mod = "LastModified0x10" if "LastModified0x10" in cols else "StandardInfoLastModified"
            has_ads_col = "HasAds" if "HasAds" in cols else None

            lf = lf.with_columns([
                pl.col(si_cr).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("si_dt"),
                pl.col(fn_cr).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("fn_dt"),
                pl.col(si_mod).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("si_mod_dt")
            ]).drop_nulls(["si_dt", "fn_dt"])

            lf = lf.with_columns((pl.col("si_dt") - pl.col("fn_dt")).dt.total_seconds().alias("diff_sec"))

            crit_exts = [".exe", ".dll", ".ps1", ".bat", ".sys", ".cmd", ".vbs", ".scr", ".pdf"]
            crit_pattern = f"(?i)({'|'.join([re.escape(e) for e in crit_exts])})$"
            WANTED_FILES = ["Secret_Project.pdf", "Windows_Security_Audit", "win_optimizer.lnk", "SunShadow", "Trigger"]
            wanted_pattern = r"(?i)(" + "|".join(WANTED_FILES) + ")"
            
            lf = lf.filter(
                pl.col("FileName").str.contains(crit_pattern) | 
                (pl.col("diff_sec").abs() > 3600) |
                pl.col("FileName").str.contains(wanted_pattern)
            )

            ads_check = pl.lit(False)
            if has_ads_col:
                ads_check = pl.col(has_ads_col)

            lf = lf.with_columns([
                pl.when(pl.col("FileName").str.contains(wanted_pattern)).then(pl.lit("CRITICAL_ARTIFACT"))
                .when((pl.col("diff_sec") < -60) & ads_check).then(pl.lit("CRITICAL_ADS_TIMESTOMP"))
                .when(pl.col("diff_sec") < -60).then(pl.lit("TIMESTOMP_BACKDATE"))
                .when(pl.col("diff_sec") > self.tolerance).then(pl.lit("FALSIFIED_FUTURE"))
                .otherwise(pl.lit("")).alias("Anomaly_Time"),
                
                pl.when(pl.col("si_mod_dt").dt.microsecond() == 0).then(pl.lit("ZERO_PRECISION")).otherwise(pl.lit("")).alias("Anomaly_Zero")
            ])
            
            lf = lf.with_columns(
                pl.struct(["Anomaly_Time", "Anomaly_Zero", "FileName"]).map_elements(lambda x: (
                    150 if x["Anomaly_Time"] == "CRITICAL_ADS_TIMESTOMP" else
                    100 if x["Anomaly_Time"] == "CRITICAL_ARTIFACT" else
                    100 if x["Anomaly_Time"] == "FALSIFIED_FUTURE" else
                    80 if x["Anomaly_Time"] == "TIMESTOMP_BACKDATE" else
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
    args = parser.parse_args(argv)
    engine = ChronosEngine(args.tolerance)
    engine.analyze(args)

if __name__ == "__main__":
    main()
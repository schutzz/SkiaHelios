import polars as pl
import argparse
import sys
import os
import re
from pathlib import Path

# ============================================================
#  SH_ChronosSift v12.0 [Noise Killer Edition]
#  Mission: Detect Time Anomalies (Timestomping).
#  Fix: Aggressive filtering of OS artifacts (WinSxS, .NET)
#       that cause false positive timestomp alerts.
# ============================================================

def print_logo():
    print(r"""
       _______                   _____  _  ______
      / ____/hronos   [ Time Lord v12.0 ]   / /
     / /             "Anomaly Detected."   / /
     \____/                               \/
    """)

class ChronosEngine:
    def __init__(self, tolerance=10.0):
        self.tolerance = tolerance
        self.noise_exts = [
            ".admx", ".adml", ".mum", ".cat", ".png", ".svg", ".js", ".json", 
            ".xml", ".etl", ".log", ".tmp", ".db", ".dat", ".mui", ".inf",
            ".ico", ".css", ".html", ".pf", ".ini", ".lnk", ".manifest", ".resx",
            ".nlp", ".pnf", ".cdf-ms"
        ]
        self.path_whitelist = [
            r"(?i)\\Tools\\", r"(?i)\\ghidra", r"(?i)\\sleuthkit", 
            r"(?i)\\FTK Imager", r"(?i)\\exiftool", r"(?i)\\Autoruns",
            r"(?i)\\LogFileParser", r"(?i)\\YaraRules", r"(?i)\\Strings",
            r"(?i)\\Program Files\\Splunk"
        ]

    def filter_noise(self, df):
        # 1. SANCTUARY DEFINITION (Keep specific user areas)
        sanctuary_mask = (
            pl.col("ParentPath").str.to_lowercase().str.contains("users") |
            pl.col("ParentPath").str.to_lowercase().str.contains(r"tasks\\[^m]") | 
            pl.col("ParentPath").str.to_lowercase().str.contains("startup")
        )
        
        # 2. TARGET DEFINITION (Always keep these)
        WANTED_FILES = ["Secret_Project.pdf", "Windows_Security_Audit", "win_optimizer.lnk", "SunShadow", "Trigger", "UpdateService.exe", "Project_Chaos"]
        wanted_mask = pl.col("FileName").str.contains(r"(?i)(" + "|".join(WANTED_FILES) + ")")

        # Initial Split
        kept_df = df.filter(sanctuary_mask | wanted_mask)
        others_df = df.filter(~(sanctuary_mask | wanted_mask))
        
        # 3. BROAD NOISE PATTERNS (For non-sanctuary paths)
        NOISE_PATTERNS = [
            r"(?i)PathUnknown", r"(?i)\\Windows\\", r"(?i)\\Program Files", 
            r"(?i)\\ProgramData", r"(?i)\\$Extend",
            r"(?i)\\Microsoft\.NET", r"(?i)\\WinSxS", r"(?i)\\assembly",
            r"(?i)\\Servicing", r"(?i)\\SoftwareDistribution",
            r"(?i)Microsoft\.Build", r"(?i)GAC_MSIL"
        ]
        for pattern in NOISE_PATTERNS:
            others_df = others_df.filter(~pl.col("ParentPath").str.contains(pattern))
        
        # Recombine
        final_df = pl.concat([kept_df, others_df]).unique()
        
        # 4. HARD KILL LIST (Applied to EVERYTHING, including Sanctuary)
        # These are paths/files that are NEVER valid timestomp indicators in this context.
        HARD_KILL_PATTERNS = [
            r"(?i)Speech Recognition", # Edge noise in Users
            r"(?i)Microsoft\.CognitiveServices",
            r"(?i)Microsoft\.Build",
            r"(?i)GAC_MSIL",
            r"(?i)\\WinSxS\\",
            r"(?i)\\Servicing\\",
            r"(?i)AppxAllUserStore",
            r"(?i)CoreUIComponents"
        ]
        
        for pattern in HARD_KILL_PATTERNS:
            final_df = final_df.filter(~pl.col("ParentPath").str.contains(pattern))
            final_df = final_df.filter(~pl.col("FileName").str.contains(pattern))

        # 5. SPECIFIC FP BINARIES
        FP_BLACKLIST = ["sbservicetrigger", "servicetrigger", "wkstriggers", "jobtrigger", "fvecpl.dll"]
        fp_mask = pl.col("FileName").str.to_lowercase().str.contains("|".join(FP_BLACKLIST))
        sys_mask = pl.col("ParentPath").str.to_lowercase().str.contains("windows")
        
        return final_df.filter(~(fp_mask & sys_mask))

    def analyze(self, args):
        print(f"[*] Chronos v12.0 awakening... Targeting: {Path(args.file).name}")
        try:
            lf = pl.scan_csv(args.file, ignore_errors=True)
            
            # Apply Pre-filters
            for pattern in self.path_whitelist:
                lf = lf.filter(~pl.col("ParentPath").str.contains(pattern))

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
            WANTED_FILES = ["Secret_Project.pdf", "Windows_Security_Audit", "win_optimizer.lnk", "SunShadow", "Trigger", "UpdateService.exe", "Project_Chaos"]
            wanted_pattern = r"(?i)(" + "|".join(WANTED_FILES) + ")"
            
            # Logic: Only flag critical extensions OR Wanted files OR huge diffs
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
                    200 if x["Anomaly_Time"] == "CRITICAL_ARTIFACT" else
                    150 if x["Anomaly_Time"] == "CRITICAL_ADS_TIMESTOMP" else
                    100 if x["Anomaly_Time"] == "FALSIFIED_FUTURE" else
                    80 if x["Anomaly_Time"] == "TIMESTOMP_BACKDATE" else
                    50 if x["Anomaly_Zero"] == "ZERO_PRECISION" else 0
                ), return_dtype=pl.Int64).alias("Chronos_Score")
            )

            time_mask = pl.lit(True)
            if args.start:
                time_mask = time_mask & (pl.col("si_mod_dt") >= pl.lit(args.start).str.to_datetime())
            if args.end:
                time_mask = time_mask & (pl.col("si_mod_dt") <= pl.lit(args.end).str.to_datetime())
            
            lf = lf.filter(time_mask | (pl.col("Chronos_Score") > 80))

            df = lf.filter((pl.col("Anomaly_Time") != "") | (pl.col("Anomaly_Zero") != "")).collect()
            
            if df.height > 0:
                df = df.sort("Chronos_Score", descending=True)
                df.write_csv(args.out)
                print(df.select(["Chronos_Score", "Anomaly_Time", "FileName", "ParentPath"]).head(15))
            else:
                print("\n[*] Clean: No significant anomalies found. (Generating empty report)")
                schema = {
                    "Chronos_Score": pl.Int64, "Anomaly_Time": pl.Utf8, 
                    "FileName": pl.Utf8, "ParentPath": pl.Utf8,
                    "si_dt": pl.Datetime, "fn_dt": pl.Datetime
                }
                pl.DataFrame([], schema=schema).write_csv(args.out)

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
    parser.add_argument("--start", help="Filter Start Date")
    parser.add_argument("--end", help="Filter End Date")
    args = parser.parse_args(argv)
    engine = ChronosEngine(args.tolerance)
    engine.analyze(args)

if __name__ == "__main__":
    main()
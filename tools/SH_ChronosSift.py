import polars as pl
import argparse
import sys
import os
import re
from pathlib import Path

# ============================================================
#  SH_ChronosSift v17.1 [Hybrid Edition]
#  Mission: Detect Time Anomalies (Timestomping).
#  Base: v12.2 + Legacy/Standard Mode Switch
# ============================================================

def print_logo():
    print(r"""
       (   )
      (  :  )   < CHRONOS SIFT >
       (   )     v17.1 - Hybrid
        " "      "Adaptive Time Logic."
    """)

class ChronosEngine:
    def __init__(self, tolerance=10.0):
        self.tolerance = tolerance
        # [MERGED] Extended Noise Extensions from v16.4/v17.1
        self.noise_exts = [
            ".admx", ".adml", ".mum", ".cat", ".png", ".svg", ".js", ".json", 
            ".xml", ".etl", ".log", ".tmp", ".db", ".dat", ".mui", ".inf",
            ".ico", ".css", ".html", ".pf", ".ini", ".lnk", ".manifest", ".resx",
            ".nlp", ".pnf", ".cdf-ms", ".nls", ".tlb", ".xrm-ms"
        ]
        self.path_whitelist = [
            r"(?i)\\Tools\\", r"(?i)\\ghidra", r"(?i)\\sleuthkit", 
            r"(?i)\\FTK Imager", r"(?i)\\exiftool", r"(?i)\\Autoruns",
            r"(?i)\\LogFileParser", r"(?i)\\YaraRules", r"(?i)\\Strings",
            r"(?i)\\Program Files\\Splunk"
        ]

    def analyze(self, args):
        mode_str = "LEGACY (Aggressive Filter)" if args.legacy else "STANDARD (Balanced)"
        print(f"[*] Chronos v17.1 awakening... Mode: {mode_str}")
        print(f"    Targeting: {Path(args.file).name}")
        
        try:
            lf = pl.scan_csv(args.file, ignore_errors=True)
            
            # ---------------------------------------------------------
            # 0. Pre-Filter (Global Whitelist)
            # ---------------------------------------------------------
            for pattern in self.path_whitelist:
                lf = lf.filter(~pl.col("ParentPath").str.contains(pattern))

            # ---------------------------------------------------------
            # 1. Scope Definition (Legacy vs Standard)
            # ---------------------------------------------------------
            if args.legacy:
                # --- [LEGACY MODE] ---
                # 古いOS用。Windowsフォルダ等は「仕様」で矛盾するため全無視。
                print("    -> Applying Legacy Filters (Ignoring System/Program Files)...")
                target_scope = r"(users|inetpub|xampp|wamp|apache|nginx|temp|perflogs|recycler)"
                ignore_scope = r"(windows|program files|programdata\\microsoft)"
                
                lf = lf.filter(
                    pl.col("ParentPath").str.to_lowercase().str.contains(target_scope) &
                    ~pl.col("ParentPath").str.to_lowercase().str.contains(ignore_scope)
                )
            else:
                # --- [STANDARD MODE] ---
                # 現代OS用。OSノイズは消すが、System32への攻撃は検知したい。
                
                # Sanctuary (守るべき場所)
                sanctuary_mask = (
                    pl.col("ParentPath").str.to_lowercase().str.contains("users") |
                    pl.col("ParentPath").str.to_lowercase().str.contains(r"tasks\\[^m]") | 
                    pl.col("ParentPath").str.to_lowercase().str.contains("startup") |
                    pl.col("ParentPath").str.to_lowercase().str.contains("inetpub") |
                    pl.col("ParentPath").str.to_lowercase().str.contains("xampp") |
                    pl.col("ParentPath").str.to_lowercase().str.contains("wamp")
                )
                
                # Noise Patterns (OS Garbage)
                NOISE_PATTERNS = [
                    r"(?i)PathUnknown", 
                    r"(?i)\\Windows\\Servicing", r"(?i)\\Windows\\WinSxS",
                    r"(?i)\\Windows\\System32\\DriverStore",
                    r"(?i)\\ProgramData\\Microsoft", 
                    r"(?i)\\$Extend", r"(?i)\\Microsoft\.NET", r"(?i)\\assembly",
                    r"(?i)\\SoftwareDistribution", r"(?i)GAC_MSIL"
                ]
                
                noise_mask = pl.lit(False)
                for pattern in NOISE_PATTERNS:
                    noise_mask = noise_mask | pl.col("ParentPath").str.contains(pattern)
                
                # Root Garbage (autoexec etc.)
                root_garbage_files = ["autoexec.bat", "config.sys", "msdos.sys", "io.sys", "boot.ini", "ntldr"]
                root_garbage_mask = (
                    pl.col("FileName").str.to_lowercase().str.contains(r"install\.res\..+\.dll") |
                    pl.col("FileName").str.to_lowercase().is_in(root_garbage_files)
                )

                lf = lf.filter(sanctuary_mask | (~noise_mask & ~root_garbage_mask))

                # Standard Windows Binaries (FP reduction)
                windows_fp_binaries = ["write.exe", "winhlp32.exe", "regedit.exe", "explorer.exe", "notepad.exe", "calc.exe"]
                lf = lf.filter(~pl.col("FileName").str.to_lowercase().is_in(windows_fp_binaries))

            # ---------------------------------------------------------
            # 2. Wanted Files (Always Capture)
            # ---------------------------------------------------------
            # [MERGED] Added GrrCON Artifacts
            WANTED_FILES = [
                "Secret_Project.pdf", "Windows_Security_Audit", "win_optimizer.lnk", 
                "SunShadow", "Trigger", "UpdateService.exe", "Project_Chaos", 
                "Conf.7z", "c99.php", "mxdwdui.BUD", "tmpudvfh.php"
            ]
            wanted_mask = pl.col("FileName").str.contains(r"(?i)(" + "|".join([re.escape(f) for f in WANTED_FILES]) + ")")
            
            # ---------------------------------------------------------
            # 3. Time Logic & Calculation
            # ---------------------------------------------------------
            cols = lf.collect_schema().names()
            
            si_cr = "si_dt" if "si_dt" in cols else ("Created0x10" if "Created0x10" in cols else "StandardInfoCreationTime")
            fn_cr = "fn_dt" if "fn_dt" in cols else ("Created0x30" if "Created0x30" in cols else "FileNameCreationTime")
            
            possible_mod_cols = ["si_mod_dt", "LastModified0x10", "StandardInfoLastModified"]
            si_mod = next((c for c in possible_mod_cols if c in cols), None)
            if not si_mod: si_mod = si_cr 

            for col_name in [si_cr, fn_cr, si_mod]:
                if col_name in cols:
                     lf = lf.with_columns(pl.col(col_name).str.replace("T", " "))
            
            lf = lf.with_columns([
                pl.col(si_cr).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("si_dt"),
                pl.col(fn_cr).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("fn_dt"),
                pl.col(si_mod).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("si_mod_dt")
            ]).drop_nulls(["si_dt", "fn_dt"])

            lf = lf.with_columns((pl.col("fn_dt") - pl.col("si_dt")).dt.total_seconds().alias("diff_sec"))

            # ---------------------------------------------------------
            # 4. Scoring & Tagging
            # ---------------------------------------------------------
            crit_exts = [".exe", ".dll", ".ps1", ".bat", ".sys", ".php", ".asp", ".jsp"]
            crit_pattern = f"(?i)({'|'.join([re.escape(e) for e in crit_exts])})$"
            
            lf = lf.with_columns([
                pl.when(pl.col("FileName").str.contains(r"(?i)(" + "|".join(WANTED_FILES) + ")"))
                  .then(pl.lit("CRITICAL_ARTIFACT"))
                  
                .when(pl.col("diff_sec") < -60)
                  .then(pl.lit("TIMESTOMP_BACKDATE"))
                  
                # Legacyモードの場合は FALSIFIED_FUTURE (未来) の判定を少し緩める
                .when((pl.col("diff_sec") > (3600 if args.legacy else self.tolerance)) & 
                      (pl.col("FileName").str.contains(crit_pattern) if args.legacy else pl.lit(True)))
                  .then(pl.lit("FALSIFIED_FUTURE"))
                  
                .otherwise(pl.lit("")).alias("Anomaly_Time"),
                
                pl.when(pl.col("si_mod_dt").dt.microsecond() == 0)
                  .then(pl.lit("ZERO_PRECISION"))
                  .otherwise(pl.lit("")).alias("Anomaly_Zero")
            ])
            
            lf = lf.with_columns(
                pl.struct(["Anomaly_Time", "Anomaly_Zero"]).map_elements(lambda x: (
                    200 if x["Anomaly_Time"] == "CRITICAL_ARTIFACT" else
                    100 if x["Anomaly_Time"] == "TIMESTOMP_BACKDATE" else
                    80 if x["Anomaly_Time"] == "FALSIFIED_FUTURE" else
                    50 if x["Anomaly_Zero"] == "ZERO_PRECISION" else 0
                ), return_dtype=pl.Int64).alias("Chronos_Score")
            )

            # Final Filter
            df = lf.filter(pl.col("Chronos_Score") > 0).collect()
            
            if df.height > 0:
                df = df.sort("Chronos_Score", descending=True)
                df.write_csv(args.out)
                print(f"[+] Anomalies detected: {df.height}")
                print(df.select(["Chronos_Score", "Anomaly_Time", "FileName", "ParentPath"]).head(10))
            else:
                print("\n[*] Clean: No significant anomalies found.")
                # 空のCSVを生成して後続のエラー防止
                pl.DataFrame(schema={"Chronos_Score": pl.Int64, "Anomaly_Time": pl.Utf8, "FileName": pl.Utf8, "ParentPath": pl.Utf8}).write_csv(args.out)

        except Exception as e:
            print(f"[!] Critical Error: {e}")
            import traceback
            traceback.print_exc()

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-o", "--out", default="Chronos_Results.csv")
    parser.add_argument("-t", "--tolerance", type=float, default=10.0)
    
    # [MERGED] Added --legacy flag
    parser.add_argument("--legacy", action="store_true", help="Enable Legacy Mode (Ignore System/Program Files)")
    
    parser.add_argument("--targets-only", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--start", help="Ignored")
    parser.add_argument("--end", help="Ignored")
    args = parser.parse_args(argv)
    
    engine = ChronosEngine(args.tolerance)
    engine.analyze(args)

if __name__ == "__main__":
    main()
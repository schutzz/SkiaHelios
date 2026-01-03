import polars as pl
import argparse
import sys
import os
import re
from pathlib import Path
from tools.SH_ThemisLoader import ThemisLoader

# ============================================================
#  SH_ChronosSift v19.3 [Path Logic Fix]
#  Mission: Detect Time Anomalies with strict noise filtering.
# ============================================================

def print_logo():
    print(r"""
       (   )
      (  :  )   < CHRONOS SIFT >
       (   )     v19.3 - Path Logic Fix
        " "      "Time bows to the Law."
    """)

class ChronosEngine:
    def __init__(self, tolerance=10.0):
        self.tolerance = tolerance

    def _calc_score(self, x):
        if x["Threat_Tag"] == "NOISE_ARTIFACT": return 0
        if x["Anomaly_Time"] == "CRITICAL_ARTIFACT": return 200
        if x["Anomaly_Time"] == "TIMESTOMP_BACKDATE": return 100
        if x["Anomaly_Time"] == "FALSIFIED_FUTURE": return 80
        if x["Anomaly_Zero"] == "ZERO_PRECISION": return 50
        return 0

    # [FIX] ロジック修正: FullPathを作成して判定 + ノイズリスト追加
    def _apply_safety_filters(self, df):
        print("    -> [Chronos] Applying Safety Filters (v19.3)...")
        
        # 1. パスとファイル名を結合した「Full_Path_Check」列を一時的に作成
        # (区切り文字バリエーションに対応するため結合する)
        df = df.with_columns(
            pl.concat_str([pl.col("ParentPath"), pl.lit("\\"), pl.col("FileName")]).alias("Full_Path_Check")
        )

        noise_keywords = [
            # System / Update related
            r"Windows\\WinSxS", r"\\InFlight\\",
            r"Windows\\Installer",
            r"Windows\\assembly",
            r"Windows\\Microsoft.NET",
            r"\$Recycle\.Bin",
            r"System Volume Information",
            
            # Python related (Catch root Python27 too)
            r"Python.*\\Lib\\", r"Programs\\Python", r"\\Python27\\", r"\\Python27\\tcl",
            r"\.py$", r"python.*\.dll$", r"include\\.*\.h$",
            r"Windows\\py\.exe", r"Windows\\pyw\.exe", # これでマッチするはず
            r"Python.*\\Doc", r"\.chm$", # Help files
            
            # BCWipe / Jetico Drivers (Noise in this context)
            r"drivers\\bcswap\.sys", r"drivers\\fsh\.sys",
            
            # Apps / Cache
            r"Adobe\\Acrobat Reader DC",
            r"AppData\\Local\\Temp", 
            r"AppData\\Local\\Google\\Chrome\\User Data",
            r"AppData\\Local\\Microsoft\\Windows\\INetCache",
            r"AppData\\Local\\Microsoft\\Windows\\History",
            r"AppData\\Local\\Microsoft\\InputPersonalization",
            r"AppData\\Roaming\\Microsoft\\Windows\\Recent",
            r"Safe Browsing",
            r"Program Files.*\\Common Files",
            
            # Extensions
            r"\.log$", r"\.dat$", r"\.etl$", r"\.xml$", r"\.ini$", r"\.inf$"
        ]
        
        clean_expr = pl.col("Threat_Tag")
        threat_score_expr = pl.col("Threat_Score")
        
        # Full_Path_Check に対して判定を行う
        for kw in noise_keywords:
            is_noise = pl.col("Full_Path_Check").str.contains(kw)
            clean_expr = pl.when(is_noise).then(pl.lit("NOISE_ARTIFACT")).otherwise(clean_expr)
            threat_score_expr = pl.when(is_noise).then(0).otherwise(threat_score_expr)

        # 一時カラムを削除して返す
        return df.with_columns([
            clean_expr.alias("Threat_Tag"),
            threat_score_expr.alias("Threat_Score")
        ]).drop("Full_Path_Check")

    def analyze(self, args):
        mode_str = "LEGACY" if args.legacy else "STANDARD"
        print(f"[*] Chronos v19.3 awakening... Mode: {mode_str}")
        
        try:
            loader = ThemisLoader(["rules/triage_rules.yaml", "rules/sigma_file_event.yaml"])
            lf = pl.scan_csv(args.file, ignore_errors=True, infer_schema_length=0)
            
            print("    -> Applying Scope Filters...")
            # (Scope filter logic here if needed)
            
            print("    -> Applying Themis Threat Scoring...")
            lf = loader.apply_threat_scoring(lf)
            
            # [Step] Apply Safety Filters (with Path fix)
            lf = self._apply_safety_filters(lf)

            # Date Calculation
            cols = lf.collect_schema().names()
            si_cr = "si_dt" if "si_dt" in cols else "Created0x10"
            fn_cr = "fn_dt" if "fn_dt" in cols else "Created0x30"
            
            for col_name in [si_cr, fn_cr]:
                if col_name in cols:
                     lf = lf.with_columns(pl.col(col_name).str.replace("T", " "))
            
            lf = lf.with_columns([
                pl.col(si_cr).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("si_dt"),
                pl.col(fn_cr).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("fn_dt"),
            ]).drop_nulls(["si_dt", "fn_dt"])

            lf = lf.with_columns((pl.col("fn_dt") - pl.col("si_dt")).dt.total_seconds().alias("diff_sec"))

            # Anomaly Tagging
            lf = lf.with_columns([
                pl.when((pl.col("Threat_Score") >= 80) & (pl.col("Threat_Tag") != "NOISE_ARTIFACT"))
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
            
            # Final Scoring
            lf = lf.with_columns(
                pl.struct(["Anomaly_Time", "Anomaly_Zero", "Threat_Tag"]).map_elements(
                    self._calc_score, 
                    return_dtype=pl.Int64
                ).alias("Chronos_Score")
            )

            df = lf.filter(pl.col("Chronos_Score") > 0).collect()
            
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
    # (Main function same as before)
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
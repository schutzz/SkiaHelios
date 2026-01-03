import polars as pl
import argparse
import sys
import os
import re
from pathlib import Path
from tools.SH_ThemisLoader import ThemisLoader

# ============================================================
#  SH_ChronosSift v22.7 [Normalized Override]
#  Mission: Detect Time Anomalies with surgical precision.
#  Update: Reverted to Normalization + Trash Override Logic.
# ============================================================

def print_logo():
    print(r"""
       (   )
      (  :  )   < CHRONOS SIFT >
       (   )     v22.7 - Normalized Override
        " "      "Time bows to the Law."
    """)

class ChronosEngine:
    def __init__(self, tolerance=10.0):
        self.tolerance = tolerance

    def _calc_score(self, x):
        if x["Threat_Tag"] == "NOISE_ARTIFACT": return 0
        if x["Anomaly_Time"] == "LEGACY_BUILD": return 10
        if x["Anomaly_Time"] == "CRITICAL_ARTIFACT": return 200
        if x["Anomaly_Time"] == "TIMESTOMP_BACKDATE": return 100
        if x["Anomaly_Time"] == "FALSIFIED_FUTURE": return 80
        if x["Anomaly_Zero"] == "ZERO_PRECISION": return 50
        return 0

    def _apply_safety_filters(self, df):
        print("    -> [Chronos] Applying Safety Filters (Normalized)...")
        
        # 1. Normalize Path (Lower + Forward Slash)
        # This is the most reliable way to handle path variations.
        df = df.with_columns(
            pl.concat_str([pl.col("ParentPath"), pl.lit("/"), pl.col("FileName")])
            .str.to_lowercase()
            .str.replace_all(r"\\", "/")
            .str.replace(r"^\./", "")
            .alias("Normalized_Path")
        )

        # 2. Allowlist (Standard System Paths)
        absolute_allowlist = [
            r"mofygdvh\.mcp$", r"shatbbms\.dif$", r"vkorppvhkxuvqcvj$",
            r"windows/system32/fm20.*\.dll$", r"windows/system32/ven2232\.olb$",
            r"jetico/.*/(uninstall\.log|langfile2\.dll)$",
            r"programdata/microsoft/office/uicaptions",
            r"windows/shellnew",
            r"programdata/regid\.1991-06\.com\.microsoft",
            r"windows/py(w)?\.exe$", r"windows/bcuninstall\.exe",
            r"program files.*/microsoft office", r"program files.*/common files/microsoft shared",
            r"windows/system32/catroot", r"windows/inf", r"windows/immersivecontrolpanel",
            r"windows/diagnostics", r"windows/policydefinitions", 
            r"program files.*/nmap", r"program files.*/wireshark",
            r"windows/system32/migwiz", r"windows/system32/windowspowershell",
            r"python.*/", r"/tcl/", r"/tk/", 
            r"windows/servicing/packages", r"windows/winsxs", r"windows/servicing",
            r"microsoft\.system\.package\.metadata", r"programdata/microsoft/windows/apprepository",
            r"windows/system32/(drivers|wbem|en-us|zh-cn|ja-jp|driverstore|cursors)",
            r"windows/syswow64", r"windows/assembly", r"windows/microsoft\.net", r"windows/fonts",
            r"windows/system32/.*\.dll$", r"windows/system32/catroot",
            r"program files/windowsapps", r"windows/systemapps",
            r"/crashpad/", r"/mptelemetrysubmit/",
            r"windows/vpnplugins/juniper", r"appdata/locallow/sun/java"
        ]

        # 3. High Risk Zones
        high_risk_zones = [
            r"users/.*/appdata/local/temp",
            r"windows/temp",
            r"users/public",
            r"downloads", 
            r"inetcache", r"inetcookies", # Added here but overridden by trash logic
            r"notifications", 
            r"users/.*/appdata/local/microsoft/windows/notifications" 
        ]
        
        allow_pattern = "|".join(absolute_allowlist)
        risk_pattern = "|".join(high_risk_zones)
        
        # 4. Logic Execution
        is_allow = pl.col("Normalized_Path").str.contains(allow_pattern)
        is_risk = pl.col("Normalized_Path").str.contains(risk_pattern)
        
        # [NEW] TRASH LOGIC (The Overrides)
        # These are noise even if they are in Risk Zones.
        
        # A. Hash Suite Noise: Path contains hash_suite_free AND NOT .exe
        is_hash_suite_noise = (
            pl.col("Normalized_Path").str.contains("hash_suite_free") & 
            (~pl.col("Normalized_Path").str.ends_with(".exe"))
        )
        
        # B. Web Cache Nuke
        is_web_trash = pl.col("Normalized_Path").str.contains(r"/inetcache/|/inetcookies/|/history/")

        # [FINAL DECISION]
        # Safe if: (Allowed AND Not Risk) OR (Is Trash)
        is_safe = (is_allow & (~is_risk)) | is_hash_suite_noise | is_web_trash
        
        clean_expr = pl.col("Threat_Tag")
        threat_score_expr = pl.col("Threat_Score")
        
        clean_expr = pl.when(is_safe).then(pl.lit("NOISE_ARTIFACT")).otherwise(clean_expr)
        threat_score_expr = pl.when(is_safe).then(0).otherwise(threat_score_expr)

        return df.with_columns([
            clean_expr.alias("Threat_Tag"),
            threat_score_expr.alias("Threat_Score")
        ]).drop("Normalized_Path")

    def analyze(self, args):
        mode_str = "LEGACY" if args.legacy else "STANDARD"
        print(f"[*] Chronos v22.7 awakening... Mode: {mode_str}")
        try:
            loader = ThemisLoader(["rules/triage_rules.yaml", "rules/sigma_file_event.yaml"])
            lf = pl.scan_csv(args.file, ignore_errors=True, infer_schema_length=0)
            
            print("    -> Applying Scope Filters...")
            print("    -> Applying Themis Threat Scoring...")
            lf = loader.apply_threat_scoring(lf)
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
            
            # Legacy & Fixed Pattern Filtering
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
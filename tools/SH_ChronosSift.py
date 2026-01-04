import polars as pl
import argparse
import sys
import os
from tools.SH_ThemisLoader import ThemisLoader
from tools.SH_HestiaCensorship import Hestia

# ============================================================
#  SH_ChronosSift v23.15 [Final Polish Mk.III]
#  Mission: Detect Time Anomalies.
#  Update: Crushed remaining Win8.1/Intel/IME noise.
# ============================================================

def print_logo():
    print(r"""
       (   )
      (  :  )   < CHRONOS SIFT >
       (   )     v23.15 - Final Polish Mk.III
        " "      "Time bows to the Law."
    """)

class ChronosEngine:
    def __init__(self, tolerance=10.0):
        self.tolerance = tolerance
        self.hestia = Hestia()

    def _apply_safety_filters(self, df):
        print("    -> [Chronos] Applying Safety Filters (Inverted Shield Mk.III)...")
        
        df = df.with_columns([
            pl.col("ParentPath").fill_null("").str.to_lowercase().alias("_pp"),
            pl.col("FileName").fill_null("").str.to_lowercase().alias("_fn")
        ])
        
        # Normalize Path
        df = df.with_columns(
            pl.concat_str([pl.col("_pp"), pl.lit("/"), pl.col("_fn")])
            .str.replace_all(r"\\", "/")
            .alias("_full_path")
        )

        # ---------------------------------------------------------
        # 1. 🔨 GLOBAL HAMMER (Safe to kill)
        # ---------------------------------------------------------
        kill_keywords = [
            "jetico", "bcwipe", "ccleaner", "dropbox", 
            "skype", "onedrive",
            "adobe/acrobat", "adobe/reader", 
            "google/chrome", "google/update",
            "mozilla", "firefox",
            "vbox", "virtualbox",
            "notepad++",
            # [NEW] Intel / McAfee Noise
            "intel/bca", "intel security", "true key",
            # [NEW] SQL / Analysis Services
            "microsoft analysis services", "as oledb"
        ]
        
        # ---------------------------------------------------------
        # 2. ⚡ DUAL-USE TRAP (Inverted Logic)
        # ---------------------------------------------------------
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

        # ---------------------------------------------------------
        # 3. 🛡️ SYSTEM SHIELD (Expanded)
        # ---------------------------------------------------------
        system_keywords = [
            "users/default", 
            "windows/servicing", "windows/winsxs",
            "windows/assembly", "windows/microsoft.net",
            "program files/windowsapps", "windows/systemapps",
            "windows/system32", "windows/syswow64",
            "windows/inf", "windows/fonts",
            "windows/immersivecontrolpanel",
            "windows/diagnostics", "windows/policydefinitions",
            "program files/microsoft office", 
            "program files (x86)/microsoft office",
            "program files/common files",
            "program files (x86)/common files",
            "programdata/microsoft/windows/apprepository",
            "programdata/microsoft/windows/caches",
            "appdata/local/microsoft/windows/history",
            "appdata/local/microsoft/windows/inetcache",
            "appdata/local/microsoft/windows/webcache",
            "appdata/local/temp",
            # [Previous]
            "windows/winstore", "windows/media",
            "program files/internet explorer",
            "program files (x86)/internet explorer",
            "windows/installer", "windows/camera",
            "windows/bitlockerdiscoveryvolumecontents",
            "windows/boot", "windows/adfs",
            "windows/rescache", "windows/filemanager",
            "windows/systemresources", "windows/globalization",
            "windows/vpnplugins",
            "program files/windows defender", "program files (x86)/windows defender",
            "program files/windows media player", "program files (x86)/windows media player",
            "windows/speech", "windows/schemas", "windows/pla",
            "windows/desktoptileresources", "windows/apppatch",
            "programdata/microsoft/windows/start menu/programs/administrative tools",
            # [NEW] Targeted from Final Top 20 Analysis
            "windows/toastdata", "windows/inputmethod",
            "windows/performance/winsat", "windows/l2schemas",
            "windows/serviceprofiles", # WinX menus hidden here
            "program files/windows journal", # Deprecated feature
            "programdata/microsoft/windows/start menu/programs", # Shortcuts
            "programdata/microsoft/windows/start menu/programs/accessories"
        ]

        file_kill_list = [
            "fm20.dll", "ven2232.olb", "mofygdvh.mcp", 
            "shatbbms.dif", "vkorppvhkxuvqcvj",
            "desktop.ini", "thumbs.db", "iconcache.db",
            "ntuser.dat", "usrclass.dat", 
            "edb.log", "edb.chk", "edb0",
            "gdipfontcache"
        ]

        # Logic
        is_noise = pl.lit(False)
        
        # A. Global Hammer & System Shield
        for kw in kill_keywords + system_keywords:
            is_noise = is_noise | pl.col("_full_path").str.contains(kw, literal=True)

        # B. File Kill List
        for kw in file_kill_list:
            is_noise = is_noise | pl.col("_fn").str.contains(kw, literal=True)

        # C. Dual-Use Inverted Trap
        is_tool_folder = pl.lit(False)
        for tool in dual_use_folders:
            is_tool_folder = is_tool_folder | pl.col("_full_path").str.contains(tool, literal=True)
            
        is_protected_binary = pl.col("_fn").is_in(protected_binaries)
        is_noise = is_noise | (is_tool_folder & (~is_protected_binary))

        # D. Adobe/Google Precision
        is_adobe_google = pl.col("_full_path").str.contains("adobe", literal=True) | pl.col("_full_path").str.contains("google", literal=True)
        is_safe_ext = pl.col("_fn").str.ends_with(".dll") | pl.col("_fn").str.ends_with(".pak") | pl.col("_fn").str.ends_with(".png")
        is_noise = is_noise | (is_adobe_google & is_safe_ext)

        # Apply
        df = df.with_columns([
            pl.when(is_noise).then(pl.lit("NOISE_ARTIFACT")).otherwise(pl.col("Threat_Tag")).alias("Threat_Tag"),
            pl.when(is_noise).then(0).otherwise(pl.col("Threat_Score")).alias("Threat_Score")
        ])

        return df.drop(["_pp", "_fn", "_full_path"])

    def analyze(self, args):
        mode_str = "LEGACY" if args.legacy else "STANDARD"
        print(f"[*] Chronos v23.15 awakening... Mode: {mode_str}")
        try:
            loader = ThemisLoader(["rules/triage_rules.yaml", "rules/sigma_file_event.yaml"])
            lf = pl.scan_csv(args.file, ignore_errors=True, infer_schema_length=0)
            
            print("    -> Applying Themis Threat Scoring...")
            lf = loader.apply_threat_scoring(lf)
            
            if "Threat_Score" in lf.collect_schema().names():
                lf = lf.with_columns(pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0))

            lf = self._apply_safety_filters(lf)
            
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
                pl.when(pl.col("Threat_Tag") == "NOISE_ARTIFACT").then(0)
                .when(pl.col("Anomaly_Time") == "LEGACY_BUILD").then(10)
                .when(pl.col("Anomaly_Time") == "CRITICAL_ARTIFACT").then(200)
                .when(pl.col("Anomaly_Time") == "TIMESTOMP_BACKDATE").then(100)
                .when(pl.col("Anomaly_Time") == "FALSIFIED_FUTURE").then(80)
                .when(pl.col("Anomaly_Zero") == "ZERO_PRECISION").then(50)
                .otherwise(0)
            )

            lf = lf.with_columns(score_expr.alias("Chronos_Score"))
            
            df = lf.filter(pl.col("Chronos_Score") > 0).collect()

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
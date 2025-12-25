import polars as pl
import argparse
import sys
import os
import glob
import re

# ==========================================
#  SH_PlutosGate v1.10 [Final Gatekeeper]
#  Fix: Explorer logic moved to global scope.
# ==========================================

def print_logo():
    print(r"""
       ______   __       __  __   ______  ______   ______    
      /\  == \ /\ \     /\ \/\ \ /\__  _\/\  __ \ /\  ___\   
      \ \  _-/ \ \ \____\ \ \_\ \\/_/\ \/\ \ \/\ \\ \___  \  
       \ \_\    \ \_____\\ \_____\  \ \_\ \ \_____\\/\_____\ 
        \/_/     \/_____/ \/_____/   \/_/  \/_____/ \/_____/ 
      
          [ SH_PlutosGate v1.10 ]
       "Exposing the escape routes of data."
    """)

class PlutosEngine:
    def __init__(self, kape_dir, pandora_csv=None):
        self.kape_dir = kape_dir
        self.pandora_df = self._load_pandora(pandora_csv) if pandora_csv else None
        print(f"[*] Initializing Plutos Gate on: {kape_dir}")

    def _load_pandora(self, path):
        try:
            print(f"    -> Linking with Pandora Ghost List: {path}")
            try:
                df = pl.read_csv(path, ignore_errors=True)
            except:
                df = pl.read_csv(path, encoding='utf-8-sig', ignore_errors=True)

            if "Ghost_FileName" in df.columns:
                return df.select(
                    pl.col("Ghost_FileName").str.to_lowercase().alias("Target_FileName"), 
                    "Risk_Tag", 
                    pl.col("ParentPath").alias("Ghost_Path")
                ).unique()
            elif "Target_FileName" in df.columns:
                return df.select(["Target_FileName", "Risk_Tag", "Ghost_Path"]).unique()
            return None
        except Exception as e:
            print(f"[!] Pandora Link Error: {e}")
            return None

    def _find_csv(self, keyword):
        candidates = glob.glob(os.path.join(self.kape_dir, "**", f"*{keyword}*.csv"), recursive=True)
        if candidates:
            print(f"    -> Found {keyword} log: {os.path.basename(candidates[0])}")
            return candidates[0]
        return None

    def analyze_usb_exfiltration(self):
        print("[*] Phase 1: Analyzing USB Exfiltration...")
        lnk_file = self._find_csv("LECmd") or self._find_csv("Lnk")

        if not lnk_file:
            print("[!] Skipping USB Analysis: Missing LNK CSVs.")
            return None

        try:
            df_lnk = pl.read_csv(lnk_file, infer_schema_length=0, ignore_errors=True)
            cols = df_lnk.columns 
            path_col = next((c for c in cols if c in ['LocalPath', 'Path', 'Target']), 'LocalPath')
            dtype_col = next((c for c in cols if 'DriveType' in c), None)
            
            if dtype_col:
                df_usb_access = df_lnk.filter(
                    pl.col(dtype_col).cast(pl.Utf8).str.contains(r"(?i)Removable|Fixed|^2$") 
                )
            else:
                df_usb_access = df_lnk.filter(
                    ~pl.col(path_col).str.to_uppercase().str.starts_with("C:") & 
                    pl.col(path_col).str.contains(r"^[A-Z]:")
                )

            df_usb_access = df_usb_access.with_columns(
                pl.col(path_col).str.extract(r"\\([^\\]+)$", 1).str.to_lowercase().alias("Target_FileName")
            )

            SYSTEM_NOISE_RE = r"(?i)\\Windows\\|\\Program Files|\\AppData\\Local\\Microsoft\\(OneDrive|Edge)"

            df_usb = df_usb_access
            
            if self.pandora_df is not None:
                df_usb = df_usb.join(self.pandora_df, on="Target_FileName", how="left")
                
                df_usb = df_usb.with_columns(
                    pl.when(pl.col("Risk_Tag").is_not_null())
                    .then(
                        pl.when(
                            (pl.col("Target_FileName").str.ends_with(".exe") | 
                             pl.col("Target_FileName").str.ends_with(".dll")) &
                            pl.col(path_col).str.contains(SYSTEM_NOISE_RE)
                        )
                        .then(pl.lit("SYSTEM_INTERNAL_ACTIVITY"))
                        .otherwise(pl.lit("CONFIRMED_EXFILTRATION"))
                    )
                    .otherwise(
                        pl.when(pl.col(path_col).str.contains(SYSTEM_NOISE_RE))
                        .then(pl.lit("NORMAL_APP_ACCESS"))
                        .otherwise(pl.lit("POTENTIAL_EXFILTRATION"))
                    )
                    .alias("Plutos_Verdict")
                )
            else:
                df_usb = df_usb.with_columns(pl.lit("USB_ACCESS").alias("Plutos_Verdict"))
                df_usb = df_usb.with_columns(pl.lit(None).alias("Risk_Tag"))

            out_cols = ["SourceCreated", "SourceModified", path_col, "Target_FileName", "Plutos_Verdict", "Risk_Tag"]
            available = [c for c in out_cols if c in df_usb.columns]
            
            return df_usb.select(available).sort("SourceModified", descending=True)

        except Exception as e:
            print(f"[!] USB Analysis Failed: {e}")
            return None

    def _correlate_actor_volume(self, row):
        app_path = str(row.get("AppId", "") or "").lower()
        vol_mb = row.get("Total_Sent_MB", 0.0)

        SYSTEM_WHITELIST = {
            "wlidsvc": "system32",
            "dosvc": "system32",
            "svchost.exe": "system32",
            "bits": "system32",
            "dnscache": "system32",
            "wuauserv": "system32",
            "licensemanager": "system32",
            "diagtrack": "system32",
            "cryptsvc": "system32",
            "appxsvc": "system32",
            "spooler": "system32",
            "wpnservice": "system32",
            "waasmedicsvc": "system32",
            "wmansvc": "system32",
            "wisvc": "system32",
            "dhcp": "system32",
            "netprofm": "system32",
            "epmapper": "system32",
            "cdpsvc": "system32",
            "system": "", 
            "msedge.exe": "program files",
            "onedrive.exe": "program files"
        }

        if app_path == "null" or not app_path:
            return "NORMAL_SYSTEM_ACTIVITY"

        for proc, expected_dir in SYSTEM_WHITELIST.items():
            if proc in app_path and expected_dir in app_path:
                return "NORMAL_SYSTEM_ACTIVITY"
            if app_path == proc.lower():
                return "NORMAL_SYSTEM_ACTIVITY"
            if "cloudexperiencehost" in app_path or "webexperience" in app_path:
                return "NORMAL_SYSTEM_ACTIVITY"

        if "windows\\uus" in app_path:
            return "NORMAL_SYSTEM_ACTIVITY"

        # [Fix] Global check for Explorer (before system check)
        # This handles paths like \device\harddiskvolume3\windows\explorer.exe
        if "explorer.exe" in app_path:
            if vol_mb < 5: return "NORMAL_SYSTEM_ACTIVITY"
            else: return "SUSPICIOUS_EXPLORER_TRAFFIC"

        is_system = any(sys_p in app_path for sys_p in ["windows\\system32", "winsxs", "program files"])
        is_script = any(scr_p in app_path for scr_p in ["powershell.exe", "cmd.exe", "wscript.exe", "sqlservr.exe"])
        
        if is_script:
            return "CRITICAL_SCRIPT_COMM"
        
        if is_system:
            if vol_mb > 10240:
                return "ANOMALOUS_SYSTEM_VOL"
            else:
                return "NORMAL_SYSTEM_ACTIVITY"
        else:
            if vol_mb < 5:
                return "C2_BEACON_DETECTED"
            else:
                return "UNKNOWN_ACTOR_EXFIL"

    def analyze_network_traffic(self):
        print("[*] Phase 2: Profiling Network Traffic (SRUM)...")
        srum_file = self._find_csv("NetworkUsage") or self._find_csv("SrumECmd") or self._find_csv("Srum")
        
        if not srum_file:
            print("[!] Skipping SRUM Analysis: Missing SrumECmd CSV.")
            return None

        try:
            lf_srum = pl.scan_csv(srum_file, infer_schema_length=0, ignore_errors=True)
            schema = lf_srum.collect_schema().names()
            
            app_col = next((c for c in schema if c in ['ExeInfo', 'AppId', 'Description']), 'AppId')
            sent_col = next((c for c in schema if "BytesSent" in c or "Bytes Sent" in c), None)
            
            if not sent_col:
                print("[!] Error: BytesSent column not found in SRUM data.")
                return None

            lf_traffic = lf_srum.group_by(app_col).agg([
                (pl.col(sent_col).cast(pl.Float64).sum() / (1024*1024)).alias("Total_Sent_MB"),
                pl.col(app_col).count().alias("Connection_Count")
            ])
            
            df_traffic = lf_traffic.collect()
            
            if app_col != "AppId":
                df_traffic = df_traffic.rename({app_col: "AppId"})

            df_traffic = df_traffic.with_columns(
                pl.struct(["AppId", "Total_Sent_MB"]).map_elements(
                    lambda x: self._correlate_actor_volume(x), 
                    return_dtype=pl.Utf8
                ).alias("Plutos_Verdict")
            )

            df_heavy = df_traffic.filter(pl.col("Plutos_Verdict") != "NORMAL_SYSTEM_ACTIVITY").sort("Total_Sent_MB", descending=True)
            return df_heavy

        except Exception as e:
            print(f"[!] SRUM Analysis Failed: {e}")
            import traceback
            traceback.print_exc()
            return None

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, help="KAPE Output Directory")
    parser.add_argument("--pandora", help="Path to Pandora Ghost List CSV")
    parser.add_argument("-o", "--out", default="plutos_report.csv")
    parser.add_argument("--net-out", default="plutos_network.csv", help="Output path for network report")
    args = parser.parse_args(argv)

    engine = PlutosEngine(args.dir, args.pandora)

    df_usb = engine.analyze_usb_exfiltration()
    if df_usb is not None and df_usb.height > 0:
        print(f"\n[!] USB EXFILTRATION ARTIFACTS FOUND: {df_usb.height}")
        df_usb.write_csv(args.out)
    else:
        print("[-] No specific USB exfiltration artifacts correlated.")

    df_net = engine.analyze_network_traffic()
    if df_net is not None and df_net.height > 0:
        print(f"\n[!] SUSPICIOUS TRAFFIC DETECTED (Top 5):")
        try: print(df_net.head(5))
        except: pass
        net_out_path = args.net_out
        df_net.write_csv(net_out_path)
        print(f"[*] Network Report saved to: {net_out_path}")

    print("\n[*] Analysis Complete. 'Ex Umbra in Solem'.")

if __name__ == "__main__":
    main()
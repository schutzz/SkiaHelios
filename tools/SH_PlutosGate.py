import polars as pl
import argparse
import sys
import os
import glob
import re

# ============================================================
#  SH_PlutosGate v2.1 [Cerberus Phase 2]
#  Mission: Network Hunting, C2 Beacon & RDP/Cloud Exfil Detection
#  Updated: Added RDP Drive Redirection (tsclient) & Cloud Storage tagging.
# ============================================================

def print_logo():
    print(r"""
       ______   __       __  __   ______  ______   ______    
      /\  == \ /\ \     /\ \/\ \ /\__  _\/\  __ \ /\  ___\   
      \ \  _-/ \ \ \____\ \ \_\ \\/_/\ \/\ \ \/\ \\ \___  \  
       \ \_\    \ \_____\\ \_____\  \ \_\ \ \_____\\/\_____\ 
      
      [ SH_PlutosGate v2.1 (Cerberus Phase 2) ]
       "No path is hidden. Not USB, not RDP, not the Cloud."
    """)

class PlutosEngine:
    def __init__(self, kape_dir, pandora_csv=None, start_time=None, end_time=None):
        self.kape_dir = kape_dir
        self.pandora_df = self._load_pandora(pandora_csv) if pandora_csv else None
        self.start_time = start_time
        self.end_time = end_time
        
        # Cloud Storage Known Binaries
        self.cloud_bins = [
            "onedrive.exe", "dropbox.exe", "googledrivesync.exe", 
            "box.exe", "megasync.exe", "icloud.exe", "pcloud.exe"
        ]
        
        print(f"[*] Initializing Plutos Gate v2.1 on: {kape_dir}")

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
            # Prefer files that look like main outputs
            candidates.sort(key=lambda x: len(x)) 
            print(f"    -> Found {keyword} log: {os.path.basename(candidates[0])}")
            return candidates[0]
        return None

    def analyze_device_exfiltration(self):
        """
        Detects exfiltration via Physical USB AND RDP Drive Redirection (\\tsclient)
        """
        print("[*] Phase 1: Analyzing Device Exfiltration (USB & RDP)...")
        lnk_file = self._find_csv("LECmd") or self._find_csv("Lnk")

        if not lnk_file:
            print("[!] Skipping Device Analysis: Missing LNK CSVs.")
            return None

        try:
            df_lnk = pl.read_csv(lnk_file, infer_schema_length=0, ignore_errors=True)
            cols = df_lnk.columns 
            path_col = next((c for c in cols if c in ['LocalPath', 'Path', 'Target']), 'LocalPath')
            dtype_col = next((c for c in cols if 'DriveType' in c), None)
            
            # 1. USB Detection
            if dtype_col:
                df_usb = df_lnk.filter(
                    (pl.col(dtype_col).cast(pl.Utf8).str.contains(r"(?i)Removable|^2$")) | 
                    ((pl.col(dtype_col).cast(pl.Utf8).str.contains(r"(?i)Fixed")) & (~pl.col(path_col).str.to_uppercase().str.starts_with("C:")))
                )
            else:
                df_usb = df_lnk.filter(
                    ~pl.col(path_col).str.to_uppercase().str.starts_with("C:") & 
                    pl.col(path_col).str.contains(r"^[A-Z]:")
                )

            # 2. RDP Drive Redirection Detection (\\tsclient)
            # This is critical for detecting copy-paste from RDP sessions
            df_rdp = df_lnk.filter(
                pl.col(path_col).str.to_lowercase().str.contains(r"\\tsclient|\\device\\rdpdr")
            )

            # Combine
            df_access = pl.concat([df_usb, df_rdp]).unique()

            # Time Filter (SourceModified)
            if self.start_time:
                df_access = df_access.filter(pl.col("SourceModified") >= self.start_time)
            if self.end_time:
                df_access = df_access.filter(pl.col("SourceModified") <= self.end_time)

            df_access = df_access.with_columns(
                pl.col(path_col).str.extract(r"\\([^\\]+)$", 1).str.to_lowercase().alias("Target_FileName")
            )

            SYSTEM_NOISE_RE = r"(?i)\\Windows\\|\\Program Files|\\AppData\\Local\\Microsoft\\(OneDrive|Edge)"

            # Enrichment
            if self.pandora_df is not None:
                df_access = df_access.join(self.pandora_df, on="Target_FileName", how="left")
                
                df_access = df_access.with_columns(
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
                        pl.when(pl.col(path_col).str.to_lowercase().str.contains("tsclient"))
                        .then(pl.lit("RDP_DRIVE_REDIRECTION")) # High Priority
                        .when(pl.col(path_col).str.contains(SYSTEM_NOISE_RE))
                        .then(pl.lit("NORMAL_APP_ACCESS"))
                        .otherwise(pl.lit("POTENTIAL_USB_EXFIL"))
                    )
                    .alias("Plutos_Verdict")
                )
            else:
                df_access = df_access.with_columns(
                    pl.when(pl.col(path_col).str.to_lowercase().str.contains("tsclient"))
                    .then(pl.lit("RDP_DRIVE_REDIRECTION"))
                    .otherwise(pl.lit("USB_ACCESS"))
                    .alias("Plutos_Verdict")
                )
                df_access = df_access.with_columns(pl.lit(None).alias("Risk_Tag"))

            out_cols = ["SourceCreated", "SourceModified", path_col, "Target_FileName", "Plutos_Verdict", "Risk_Tag"]
            available = [c for c in out_cols if c in df_access.columns]
            
            return df_access.select(available).sort("SourceModified", descending=True)

        except Exception as e:
            print(f"[!] Device Analysis Failed: {e}")
            return None

    def analyze_network_traffic(self):
        """
        Detects C2 Beacons (Variance Analysis) & Cloud Storage Uploads
        """
        print("[*] Phase 2: Profiling Network Traffic (SRUM) - Cerberus Mode...")
        srum_file = self._find_csv("NetworkUsage") or self._find_csv("SrumECmd") or self._find_csv("Srum")
        
        if not srum_file:
            print("[!] Skipping SRUM Analysis: Missing SrumECmd CSV.")
            return None

        try:
            # 1. Load & Pre-filter
            lf_srum = pl.scan_csv(srum_file, infer_schema_length=0, ignore_errors=True)
            schema = lf_srum.collect_schema().names()
            time_col = next((c for c in schema if c in ['Timestamp', 'TimeCreated']), 'Timestamp')
            app_col = next((c for c in schema if c in ['ExeInfo', 'AppId', 'Description']), 'AppId')
            sent_col = next((c for c in schema if "BytesSent" in c or "Bytes Sent" in c), None)

            if not sent_col:
                print("[!] Error: BytesSent column not found.")
                return None

            # Time Filter
            if self.start_time:
                lf_srum = lf_srum.filter(pl.col(time_col) >= self.start_time)
            if self.end_time:
                lf_srum = lf_srum.filter(pl.col(time_col) <= self.end_time)

            # 2. Beacon Analysis (Calculating Variance)
            lf_beacon = lf_srum.sort([app_col, time_col]).with_columns([
                pl.col(time_col).str.to_datetime(strict=False).alias("ts_dt")
            ]).filter(pl.col("ts_dt").is_not_null())

            # Calculate time delta between connections
            lf_beacon = lf_beacon.with_columns(
                pl.col("ts_dt").diff().dt.total_seconds().over(app_col).alias("Time_Delta")
            )

            # Aggregation
            lf_stats = lf_beacon.group_by(app_col).agg([
                (pl.col(sent_col).cast(pl.Float64).sum() / (1024*1024)).alias("Total_Sent_MB"),
                pl.col(app_col).count().alias("Connection_Count"),
                pl.col("Time_Delta").mean().alias("Avg_Interval_Sec"),
                pl.col("Time_Delta").std().fill_null(9999).alias("Interval_StdDev")
            ])

            df_stats = lf_stats.collect()

            # 3. Verdict Logic (C2 + Cloud + RDP)
            def judge_traffic(row):
                app = str(row.get(app_col, "")).lower()
                std_dev = row.get("Interval_StdDev", 9999.0)
                count = row.get("Connection_Count", 0)
                vol = row.get("Total_Sent_MB", 0.0)

                # A. RDP Check
                if "mstsc.exe" in app:
                    if vol > 50: return "RDP_HEAVY_TRANSFER" # Screen sharing is usually download, upload means input/file copy
                    return "RDP_SESSION"

                # B. Cloud Storage Check
                if any(c in app for c in self.cloud_bins):
                    if vol > 100: return "CLOUD_MASS_UPLOAD" # >100MB upload
                    return "CLOUD_SYNC_ACTIVITY"

                # C. System Noise
                if "windows\\system32" in app or "winsxs" in app:
                    if vol > 1000: return "HEAVY_SYSTEM_TRAFFIC"
                    return "NORMAL"

                # D. C2 Beacon Check
                # Low jitter (StdDev < 30s) & Frequent (>10 times)
                if std_dev < 30.0 and count > 10:
                    return f"POTENTIAL_BEACON (Int:{int(row['Avg_Interval_Sec'])}s)"
                
                # E. Generic Exfiltration
                if vol > 50:
                    return "DATA_EXFILTRATION_SUSPECT"
                
                return "LOW_RISK"

            df_final = df_stats.with_columns(
                pl.struct(["Interval_StdDev", "Connection_Count", "Total_Sent_MB", app_col]).map_elements(
                    lambda x: judge_traffic(x), return_dtype=pl.Utf8
                ).alias("Plutos_Verdict")
            )

            # Filter out NORMAL and LOW_RISK for report
            df_alert = df_final.filter(~pl.col("Plutos_Verdict").is_in(["NORMAL", "LOW_RISK"])).sort("Total_Sent_MB", descending=True)
            return df_alert

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
    parser.add_argument("--start", help="Filter Start Date")
    parser.add_argument("--end", help="Filter End Date")
    args = parser.parse_args(argv)

    engine = PlutosEngine(args.dir, args.pandora, args.start, args.end)

    # 1. Device Exfiltration (USB + RDP Drive)
    df_dev = engine.analyze_device_exfiltration()
    if df_dev is not None and df_dev.height > 0:
        print(f"\n[!] DEVICE EXFILTRATION ARTIFACTS FOUND: {df_dev.height}")
        # Show RDP hits specifically
        rdp_hits = df_dev.filter(pl.col("Plutos_Verdict") == "RDP_DRIVE_REDIRECTION")
        if rdp_hits.height > 0:
            print(f"    [!!!] ALERT: {rdp_hits.height} RDP Drive Redirection events detected!")
        df_dev.write_csv(args.out)
    else:
        print("[-] No device exfiltration artifacts correlated.")

    # 2. Network Traffic (Beacon + Cloud + RDP)
    df_net = engine.analyze_network_traffic()
    if df_net is not None and df_net.height > 0:
        print(f"\n[!] SUSPICIOUS TRAFFIC DETECTED (Top 5):")
        try: print(df_net.head(5))
        except: pass
        df_net.write_csv(args.net_out)
        print(f"[*] Network Report saved to: {args.net_out}")

    print("\n[*] Analysis Complete. 'Cerberus is watching'.")

if __name__ == "__main__":
    main()
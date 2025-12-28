import polars as pl
import argparse
import sys
import os
import glob
import re

# ============================================================
#  SH_PlutosGate v2.3 [Safety First]
#  Mission: Network Hunting.
#  Fix: Handle missing SRUM columns gracefully to prevent crash.
# ============================================================

def print_logo():
    print(r"""
       ______   __       __  __   ______  ______   ______    
      /\  == \ /\ \     /\ \/\ \ /\__  _\/\  __ \ /\  ___\   
      \ \  _-/ \ \ \____\ \ \_\ \\/_/\ \/\ \ \/\ \\ \___  \  
       \ \_\    \ \_____\ \_____\  \ \_\ \ \_____\\/\_____\ 
      
      [ SH_PlutosGate v2.3 ]
    """)

class PlutosEngine:
    def __init__(self, kape_dir, pandora_csv=None, start_time=None, end_time=None):
        self.kape_dir = kape_dir
        self.pandora_df = self._load_pandora(pandora_csv) if pandora_csv else None
        self.start_time = start_time
        self.end_time = end_time
        self.evtx_df = self._load_evtx()

    def _load_csv(self, pattern):
        search_path = os.path.join(self.kape_dir, "**", pattern)
        files = glob.glob(search_path, recursive=True)
        if not files: return None
        try:
            return pl.read_csv(files[0], ignore_errors=True, infer_schema_length=0)
        except: return None

    def _load_pandora(self, path):
        if path and os.path.exists(path):
            return pl.read_csv(path, ignore_errors=True)
        return None

    def _load_evtx(self):
        print("[*] Hunting for Network Events (Evtx)...")
        df = self._load_csv("*EvtxECmd*.csv")
        if df is None: return None
        if "EventId" not in df.columns: return None
        target_eids = ["3", "5156", "5154", "5157"]
        return df.filter(pl.col("EventId").cast(pl.Utf8).is_in(target_eids))

    def analyze_device_exfiltration(self):
        print("[*] Phase 1: Analyzing Device Exfiltration (USB/RDP)...")
        hits = []
        if self.pandora_df is not None:
            usb_ghosts = self.pandora_df.filter(pl.col("ParentPath").str.contains(r"(?i)^[D-Z]:\\")).select(["Ghost_FileName", "ParentPath", "Risk_Tag"])
            if usb_ghosts.height > 0: hits.append(usb_ghosts.with_columns(pl.lit("USB_ARTIFACT_DETECTED").alias("Plutos_Verdict")))
            
            rdp_ghosts = self.pandora_df.filter(pl.col("ParentPath").str.to_lowercase().str.contains("tsclient")).select(["Ghost_FileName", "ParentPath", "Risk_Tag"])
            if rdp_ghosts.height > 0: hits.append(rdp_ghosts.with_columns(pl.lit("RDP_DRIVE_REDIRECTION").alias("Plutos_Verdict")))

        if hits: return pl.concat(hits)
        return None

    def analyze_network_traffic(self):
        print("[*] Phase 2: Analyzing Network Telemetry (SRUM & IPs)...")
        
        # --- Part A: SRUM (Safety Checked) ---
        df_srum = self._load_csv("*SRUM*Network*.csv")
        srum_hits = None
        
        if df_srum is not None:
            # Check for required columns
            required = ["ExeInfo", "BytesSent"]
            if all(c in df_srum.columns for c in required):
                try:
                    stats = df_srum.group_by("ExeInfo").agg([
                        pl.col("BytesSent").cast(pl.Float64, strict=False).sum().alias("Total_Sent"),
                        pl.len().alias("Connection_Count")
                    ])
                    stats = stats.with_columns((pl.col("Total_Sent") / 1024 / 1024).alias("Total_Sent_MB"))
                    cloud_pattern = "onedrive|dropbox|google drive|box|mega"
                    stats = stats.with_columns(
                        pl.when(pl.col("ExeInfo").str.to_lowercase().str.contains(cloud_pattern))
                        .then(pl.lit("CLOUD_SYNC_ACTIVITY"))
                        .otherwise(pl.lit("NORMAL_TRAFFIC"))
                        .alias("Plutos_Verdict")
                    )
                    srum_hits = stats.filter(pl.col("Plutos_Verdict") != "NORMAL_TRAFFIC")
                except Exception as e:
                    print(f"[!] SRUM Analysis skipped due to data error: {e}")
            else:
                print(f"[!] SRUM Analysis skipped: Missing columns (Found: {df_srum.columns})")

        # --- Part B: Event Logs (IP Tracing) ---
        evtx_hits = None
        if self.evtx_df is not None:
            cols = self.evtx_df.columns
            dst_ip_col = next((c for c in ["DestinationIp", "DestAddress", "DestinationAddress"] if c in cols), None)
            dst_port_col = next((c for c in ["DestinationPort", "DestPort"] if c in cols), None)
            img_col = next((c for c in ["Image", "Application", "ProcessName"] if c in cols), "Unknown_App")
            time_col = next((c for c in ["TimeCreated", "Timestamp_UTC"] if c in cols), "Time")

            if dst_ip_col:
                noise_ips = ["127.0.0.1", "0.0.0.0", "::1", "255.255.255.255"]
                multicast = r"^(224\.|239\.|ff02::)"
                net_evts = self.evtx_df.filter(
                    ~pl.col(dst_ip_col).is_in(noise_ips) &
                    ~pl.col(dst_ip_col).str.contains(multicast)
                )
                if self.start_time: net_evts = net_evts.filter(pl.col(time_col) >= self.start_time)
                if self.end_time:   net_evts = net_evts.filter(pl.col(time_col) <= self.end_time)

                if net_evts.height > 0:
                    evtx_hits = net_evts.select([
                        pl.col(time_col).alias("Timestamp"),
                        pl.col(img_col).alias("Process"),
                        pl.col(dst_ip_col).alias("Remote_IP"),
                        pl.col(dst_port_col).alias("Remote_Port"),
                        pl.lit("NETWORK_CONNECTION").alias("Event_Type")
                    ]).sort("Timestamp", descending=True)

        return srum_hits, evtx_hits

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", required=True, help="KAPE Output Directory")
    parser.add_argument("--pandora", help="Optional: Pandora Ghost List CSV")
    parser.add_argument("-o", "--out", default="plutos_report.csv")
    parser.add_argument("--net-out", default="plutos_network_details.csv", help="Detailed IP Log Output")
    parser.add_argument("--start", help="Filter Start Date")
    parser.add_argument("--end", help="Filter End Date")
    args = parser.parse_args(argv)

    engine = PlutosEngine(args.dir, args.pandora, args.start, args.end)

    # 1. Device Exfiltration
    df_dev = engine.analyze_device_exfiltration()
    if df_dev is not None and df_dev.height > 0:
        df_dev.write_csv(args.out)

    # 2. Network Traffic
    df_srum, df_evtx = engine.analyze_network_traffic()
    
    if df_srum is not None and df_srum.height > 0:
        df_srum.write_csv(args.out.replace(".csv", "_srum.csv"))

    if df_evtx is not None and df_evtx.height > 0:
        print(f"[!] NETWORK CONNECTIONS TRACED: {df_evtx.height} events.")
        df_evtx.write_csv(args.net_out)
    else:
        print("[-] No detailed network events (IPs) found in Event Logs.")

if __name__ == "__main__":
    main()
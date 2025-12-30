import polars as pl
import argparse
import sys
import os
import glob
import re
import ipaddress

# ============================================================
#  SH_PlutosGate v2.4 [Internal Scout + Safety]
#  Mission: Detect Internal Exfiltration & Lateral Movement
#  Base: v2.3 (Robust Input Handling) + v1.9 (Lateral Logic)
# ============================================================

def print_logo():
    print(r"""
       ______   __       __  __   ______  ______   ______    
      /\  == \ /\ \     /\ \/\ \ /\__  _\/\  __ \ /\  ___\   
      \ \  _-/ \ \ \____\ \ \_\ \\/_/\ \/\ \ \/\ \\ \___  \  
       \ \_\    \ \_____\ \_____\  \ \_\ \ \_____\\/\_____\ 
      
      [ SH_PlutosGate v2.4 ]
      "Internal Borders are no match for the Gatekeeper."
    """)

class PlutosEngine:
    def __init__(self, kape_dir, pandora_csv=None, start_time=None, end_time=None):
        self.kape_dir = kape_dir
        self.pandora_df = self._load_pandora(pandora_csv) if pandora_csv else None
        self.start_time = start_time
        self.end_time = end_time
        self.evtx_df = self._load_evtx()
        
        # [v2.4] Lateral Movement Tools (Living off the Land)
        self.lateral_processes = [
            "psexec.exe", "psexesvc.exe", "wsmprovhost.exe", "wmiprvse.exe", 
            "powershell.exe", "pwsh.exe", "wmic.exe", "bitsadmin.exe", 
            "certutil.exe", "schtasks.exe", "sc.exe", "net.exe", "reg.exe",
            "rundll32.exe", "regsvr32.exe"
        ]

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
        # EID 3: Sysmon Net, 5156: WFP Allow, 5157: Block, 5154: Listen
        target_eids = ["3", "5156", "5154", "5157"]
        return df.filter(pl.col("EventId").cast(pl.Utf8).is_in(target_eids))

    def _is_internal_ip(self, ip_str):
        """ [v2.4] RFC1918 & Localhost Check """
        if not ip_str or ip_str in ["-", "", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"]: return True
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except:
            return False

    def analyze_lateral_movement(self):
        """ 
        [v2.4] Combined Logic:
        1. USB/RDP (Legacy v2.3)
        2. Admin Share Drops (New v1.9)
        """
        print("[*] Phase 1: Analyzing Lateral Movement (Admin Shares, RDP, USB)...")
        hits = []

        if self.pandora_df is not None:
            # 1. USB Artifacts (Legacy)
            usb_ghosts = self.pandora_df.filter(pl.col("ParentPath").str.contains(r"(?i)^[D-Z]:\\")).select(["Ghost_FileName", "ParentPath", "Risk_Tag"])
            if usb_ghosts.height > 0: 
                hits.append(usb_ghosts.with_columns([
                    pl.lit("USB_ARTIFACT_DETECTED").alias("Plutos_Verdict"),
                    pl.lit("MEDIUM").alias("Severity")
                ]))
            
            # 2. RDP Drive Redirection (Legacy + New)
            rdp_ghosts = self.pandora_df.filter(
                pl.col("ParentPath").str.to_lowercase().str.contains("tsclient")
            ).select(["Ghost_FileName", "ParentPath", "Risk_Tag"])
            
            if rdp_ghosts.height > 0:
                hits.append(rdp_ghosts.with_columns([
                    pl.lit("RDP_DRIVE_REDIRECTION").alias("Plutos_Verdict"),
                    pl.lit("HIGH").alias("Severity")
                ]))

            # 3. Admin Share Drops (New v2.4)
            # Regex: \\.*\\[A-Za-z]\$ or \\.*\\ADMIN\$ or \\.*\\IPC\$
            admin_share_pattern = r"(?i)\\\\[^\\]+\\([a-z]\$|admin\$|ipc\$)"
            lateral_drops = self.pandora_df.filter(
                pl.col("ParentPath").str.contains(admin_share_pattern) &
                pl.col("Ghost_FileName").str.contains(r"(?i)\.(exe|bat|ps1|7z|zip|dll)$")
            ).select(["Ghost_FileName", "ParentPath", "Risk_Tag"])
            
            if lateral_drops.height > 0:
                hits.append(lateral_drops.with_columns([
                    pl.lit("LATERAL_TOOL_DROP").alias("Plutos_Verdict"),
                    pl.lit("HIGH").alias("Severity")
                ]))

        if hits: return pl.concat(hits)
        return None

    def analyze_network_traffic(self):
        print("[*] Phase 2: Analyzing Network Telemetry (SRUM & IPs)...")
        
        # --- Part A: SRUM (Internal Burst Scout) ---
        df_srum = self._load_csv("*SRUM*Network*.csv")
        srum_hits = None
        
        if df_srum is not None:
            # Safety Check from v2.3
            required = ["ExeInfo", "BytesSent"]
            if all(c in df_srum.columns for c in required):
                try:
                    # 50MB Threshold for Internal Burst
                    stats = df_srum.group_by("ExeInfo").agg([
                        pl.col("BytesSent").cast(pl.Float64, strict=False).sum().alias("Total_Sent"),
                        pl.len().alias("Connection_Count")
                    ])
                    stats = stats.with_columns((pl.col("Total_Sent") / 1024 / 1024).alias("Total_Sent_MB"))
                    
                    cloud_pattern = "onedrive|dropbox|google drive|box|mega"
                    lateral_pattern = "|".join([re.escape(p) for p in self.lateral_processes])
                    
                    # Logic: 
                    # 1. Cloud Exfil (External)
                    # 2. Internal Burst (Lateral Exfil via SMB/WMI etc)
                    stats = stats.with_columns(
                        pl.when(pl.col("ExeInfo").str.to_lowercase().str.contains(cloud_pattern))
                        .then(pl.lit("CLOUD_SYNC_EXFIL"))
                        .when((pl.col("Total_Sent_MB") > 50) & 
                              (pl.col("ExeInfo").str.to_lowercase().str.contains(lateral_pattern)))
                        .then(pl.lit("INTERNAL_BURST_TRANSFER"))
                        .otherwise(pl.lit("NORMAL_TRAFFIC"))
                        .alias("Plutos_Verdict")
                    )
                    srum_hits = stats.filter(pl.col("Plutos_Verdict") != "NORMAL_TRAFFIC")
                except Exception as e:
                    print(f"[!] SRUM Analysis skipped due to data error: {e}")
            else:
                print(f"[!] SRUM Analysis skipped: Missing columns (Found: {df_srum.columns})")

        # --- Part B: Event Logs (Scoring Logic) ---
        evtx_hits = []
        if self.evtx_df is not None:
            cols = self.evtx_df.columns
            dst_ip_col = next((c for c in ["DestinationIp", "DestAddress", "DestinationAddress"] if c in cols), None)
            dst_port_col = next((c for c in ["DestinationPort", "DestPort"] if c in cols), None)
            img_col = next((c for c in ["Image", "Application", "ProcessName"] if c in cols), "Unknown_App")
            time_col = next((c for c in ["TimeCreated", "Timestamp_UTC"] if c in cols), "Time")

            if dst_ip_col:
                noise_ips = ["0.0.0.0", "255.255.255.255"] # Keep 127.0.0.1 for local check if needed
                multicast = r"^(224\.|239\.|ff02::)"
                
                # Filter noise
                net_evts = self.evtx_df.filter(
                    ~pl.col(dst_ip_col).is_in(noise_ips) &
                    ~pl.col(dst_ip_col).str.contains(multicast)
                )
                if self.start_time: net_evts = net_evts.filter(pl.col(time_col) >= self.start_time)
                if self.end_time:   net_evts = net_evts.filter(pl.col(time_col) <= self.end_time)

                # Scoring Logic (Iterative for accuracy)
                if net_evts.height > 0:
                    for row in net_evts.iter_rows(named=True):
                        ip = str(row.get(dst_ip_col, ""))
                        proc = str(row.get(img_col, "")).lower()
                        proc_name = proc.split("\\")[-1]
                        
                        score = 0
                        tags = []
                        
                        is_internal = self._is_internal_ip(ip)
                        
                        # 1. Lateral Tool Execution
                        if proc_name in self.lateral_processes:
                            score += 40
                            tags.append("LATERAL_TOOL")
                        
                        # 2. Internal Connection Context
                        if is_internal:
                            # High ports often used for RPC/WinRM
                            port = str(row.get(dst_port_col, ""))
                            if port in ["445", "135", "5985", "5986"]:
                                score += 30
                                tags.append("SMB_WMI_WINRM")
                            
                            if proc_name in self.lateral_processes:
                                score += 20 # Boost if lateral tool talks internal
                        
                        # 3. External C2 Context
                        if not is_internal and proc_name in ["powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe"]:
                            score += 60
                            tags.append("POTENTIAL_C2")
                            
                        # Verdict
                        if score >= 60:
                            verdict = "LATERAL_MOVEMENT" if is_internal else "C2_COMMUNICATION"
                            evtx_hits.append({
                                "Timestamp": row.get(time_col),
                                "Process": proc,
                                "Remote_IP": ip,
                                "Remote_Port": row.get(dst_port_col),
                                "Plutos_Verdict": verdict,
                                "Tags": ", ".join(tags),
                                "Severity": "HIGH"
                            })
                        elif score >= 40:
                             evtx_hits.append({
                                "Timestamp": row.get(time_col),
                                "Process": proc,
                                "Remote_IP": ip,
                                "Remote_Port": row.get(dst_port_col),
                                "Plutos_Verdict": "SUSPICIOUS_CONNECTION",
                                "Tags": ", ".join(tags),
                                "Severity": "MEDIUM"
                            })

        df_evtx_res = pl.DataFrame(evtx_hits) if evtx_hits else None
        return srum_hits, df_evtx_res

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

    # 1. Lateral Movement & Exfil (Pandora based)
    # Renamed from analyze_device_exfiltration
    df_lat = engine.analyze_lateral_movement()
    if df_lat is not None and df_lat.height > 0:
        print(f"[!] LATERAL MOVEMENT / EXFIL DETECTED: {df_lat.height} artifacts.")
        df_lat.write_csv(args.out)
    else:
        print("[-] No file-based lateral movement traces found.")

    # 2. Network Traffic (SRUM & EVTX)
    df_srum, df_evtx = engine.analyze_network_traffic()
    
    if df_srum is not None and df_srum.height > 0:
        print(f"[!] SRUM ANOMALIES: {df_srum.height} records.")
        df_srum.write_csv(args.out.replace(".csv", "_srum.csv"))

    if df_evtx is not None and df_evtx.height > 0:
        print(f"[!] NETWORK CONNECTIONS TRACED: {df_evtx.height} events.")
        df_evtx.write_csv(args.net_out)
    else:
        print("[-] No significant network anomalies found.")

if __name__ == "__main__":
    main()
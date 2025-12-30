import polars as pl
import argparse
import sys
import os
import glob
import re
import ipaddress

# ============================================================
#  SH_PlutosGate v2.5 [Thermodynamics Update]
#  Mission: Detect Internal Exfiltration & Lateral Movement
#  Base: v2.4 (Input Handling) + v2.5 (Heat Logic)
# ============================================================

def print_logo():
    print(r"""
       ______   __       __  __   ______   ______   ______    
      /\  == \ /\ \     /\ \/\ \ /\__  _\/\  __ \ /\  ___\   
      \ \  _-/ \ \ \____\ \ \_\ \\/_/\ \/\ \ \/\ \\ \___  \  
       \ \_\    \ \_____\ \_____\  \ \_\ \ \_____\\/\_____\ 
      
      [ SH_PlutosGate v2.5 ]
      "The Heat of the Evidence burns away the Lies."
    """)

class PlutosGate:
    """
    [Plutos: The Wealth Giver (of Evidence)]
    v2.5: ネットワークログ、SRUM、ファイアウォールログを解析し、
    外部通信(C2)と内部横展開(Lateral)を熱量(Heat Score)で判定する。
    """
    def __init__(self, kape_dir, pandora_csv=None, start_time=None, end_time=None):
        self.kape_dir = kape_dir
        self.pandora_df = self._load_pandora(pandora_csv) if pandora_csv else None
        self.start_time = start_time
        self.end_time = end_time
        self.evtx_df = self._load_evtx()
        
        # Lateral Movement Tools (Living off the Land)
        self.lateral_processes = [
            "psexec.exe", "psexesvc.exe", "wsmprovhost.exe", "wmiprvse.exe", 
            "powershell.exe", "pwsh.exe", "wmic.exe", "bitsadmin.exe", 
            "certutil.exe", "schtasks.exe", "sc.exe", "net.exe", "reg.exe",
            "rundll32.exe", "regsvr32.exe", "curl.exe", "wget.exe", "7z.exe", "rar.exe"
        ]

    def _load_csv(self, pattern):
        """KAPE出力ディレクトリからパターンに一致するCSVを検索して読み込む"""
        search_path = os.path.join(self.kape_dir, "**", pattern)
        files = glob.glob(search_path, recursive=True)
        if not files: return None
        try:
            # 型推論エラーを防ぐため、まずは全カラム文字列として読み込む
            return pl.read_csv(files[0], ignore_errors=True, infer_schema_length=0)
        except Exception as e:
            print(f"[!] Error loading {pattern}: {e}")
            return None

    def _load_pandora(self, path):
        if path and os.path.exists(path):
            try:
                return pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
            except: pass
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
        """ RFC1918 & Localhost Check """
        if not ip_str or ip_str in ["-", "", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"]: return True
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except:
            return False

    def analyze_lateral_movement(self):
        """ 
        [Lateral Movement Detection]
        1. USB Artifacts
        2. RDP Drive Redirection
        3. Admin Share Drops (v2.4 Logic)
        """
        print("[*] Phase 1: Analyzing Lateral Movement (Admin Shares, RDP, USB)...")
        hits = []

        if self.pandora_df is not None:
            # 1. USB Artifacts
            usb_ghosts = self.pandora_df.filter(pl.col("ParentPath").str.contains(r"(?i)^[D-Z]:\\")).select(["Ghost_FileName", "ParentPath", "Risk_Tag"])
            if usb_ghosts.height > 0: 
                hits.append(usb_ghosts.with_columns([
                    pl.lit("USB_ARTIFACT_DETECTED").alias("Plutos_Verdict"),
                    pl.lit("MEDIUM").alias("Severity"),
                    pl.lit(0).alias("Heat_Score")
                ]))
            
            # 2. RDP Drive Redirection
            rdp_ghosts = self.pandora_df.filter(
                pl.col("ParentPath").str.to_lowercase().str.contains("tsclient")
            ).select(["Ghost_FileName", "ParentPath", "Risk_Tag"])
            
            if rdp_ghosts.height > 0:
                hits.append(rdp_ghosts.with_columns([
                    pl.lit("RDP_DRIVE_REDIRECTION").alias("Plutos_Verdict"),
                    pl.lit("HIGH").alias("Severity"),
                    pl.lit(80).alias("Heat_Score")
                ]))

            # 3. Admin Share Drops
            admin_share_pattern = r"(?i)\\\\[^\\]+\\([a-z]\$|admin\$|ipc\$)"
            lateral_drops = self.pandora_df.filter(
                pl.col("ParentPath").str.contains(admin_share_pattern) &
                pl.col("Ghost_FileName").str.contains(r"(?i)\.(exe|bat|ps1|7z|zip|dll)$")
            ).select(["Ghost_FileName", "ParentPath", "Risk_Tag"])
            
            if lateral_drops.height > 0:
                hits.append(lateral_drops.with_columns([
                    pl.lit("LATERAL_TOOL_DROP").alias("Plutos_Verdict"),
                    pl.lit("HIGH").alias("Severity"),
                    pl.lit(90).alias("Heat_Score")
                ]))

        if hits: return pl.concat(hits)
        return None

    def analyze_network_traffic(self):
        """
        SRUM (Heat Analysis) & EVTX (Connection Scoring)
        """
        print("[*] Phase 2: Analyzing Network Thermodynamics (SRUM & EVTX)...")
        
        # --- Part A: SRUM Thermodynamics (v2.5 Updated) ---
        df_srum = self._load_csv("*SRUM*Network*.csv")
        srum_hits = []
        
        if df_srum is not None:
            # カラム名の揺らぎ吸収
            app_col = next((c for c in ["ExeInfo", "AppId", "AppName", "Process"] if c in df_srum.columns), None)
            sent_col = next((c for c in ["BytesSent", "Bytes_Sent"] if c in df_srum.columns), None)
            recv_col = next((c for c in ["BytesReceived", "Bytes_Received"] if c in df_srum.columns), None)
            time_col = next((c for c in ["Timestamp", "Time", "Date"] if c in df_srum.columns), "Timestamp") # Default name if missing

            if app_col and sent_col and recv_col:
                print("   -> Calculating SRUM Heat Scores...")
                
                BURST_THRESHOLD = 50 * 1024 * 1024 # 50MB
                HIGH_HEAT_PROCESSES = {
                    "mstsc.exe": 50, "svchost.exe": 20, "7z.exe": 80, "rar.exe": 80, 
                    "curl.exe": 60, "wget.exe": 60, "powershell.exe": 40, "psexesvc.exe": 90,
                    "chrome.exe": 10, "msedge.exe": 10
                }
                
                # SRUMは集計が必要な場合が多いが、ここでは簡易的に高熱量なレコードを抽出
                # (本来はTimestampごとのAggregationが望ましいが、KAPEのCSVは既にレコード化されている前提)
                
                # Polarsでの処理（高速化のため式で処理）
                # 文字列カラムを数値に変換
                df_srum = df_srum.with_columns([
                    pl.col(sent_col).cast(pl.Float64, strict=False).fill_null(0).alias("_sent"),
                    pl.col(recv_col).cast(pl.Float64, strict=False).fill_null(0).alias("_recv"),
                    pl.col(app_col).str.to_lowercase().alias("_app_lower")
                ])
                
                # フィルタリング: バースト または 危険なプロセス
                # 1. Burst Traffic
                burst_mask = (pl.col("_sent") > BURST_THRESHOLD) | (pl.col("_recv") > BURST_THRESHOLD)
                
                # 2. Dangerous Process
                proc_pattern = "|".join([re.escape(p) for p in HIGH_HEAT_PROCESSES.keys()])
                proc_mask = pl.col("_app_lower").str.contains(proc_pattern)
                
                candidates = df_srum.filter(burst_mask | proc_mask)
                
                for row in candidates.iter_rows(named=True):
                    sent = int(row["_sent"])
                    recv = int(row["_recv"])
                    app_full = str(row.get(app_col, ""))
                    app_name = app_full.lower().split('\\')[-1]
                    
                    heat_score = 0
                    tags = []
                    
                    # Volume Heat
                    if sent > BURST_THRESHOLD:
                        heat_score += 60
                        tags.append(f"DATA_EXFIL_BURST({sent//1024//1024}MB)")
                    elif recv > BURST_THRESHOLD:
                        heat_score += 40
                        tags.append(f"DOWNLOAD_BURST({recv//1024//1024}MB)")
                        
                    # Process Heat
                    base_score = 0
                    for p_name, score in HIGH_HEAT_PROCESSES.items():
                        if p_name in app_name:
                            base_score = score
                            break
                    
                    if base_score > 0:
                        heat_score += base_score
                        # バーストしていればボーナス
                        if (sent + recv) > (10 * 1024 * 1024):
                            heat_score += 20
                            
                    if heat_score >= 80:
                        verdict = "HIGH_HEAT_ACTIVITY"
                        if "mstsc" in app_name: verdict = "RDP_TUNNEL_SUSPICION"
                        
                        srum_hits.append({
                            "Timestamp": row.get(time_col),
                            "Plutos_Verdict": verdict,
                            "Remote_IP": "Unknown (SRUM)",
                            "Process": app_full,
                            "Detail": f"Sent: {sent:,} / Recv: {recv:,} | Score: {heat_score}",
                            "Tags": ", ".join(tags),
                            "Heat_Score": heat_score
                        })
            else:
                print(f"[!] SRUM Analysis skipped: Missing columns in {df_srum.columns}")

        # --- Part B: Event Logs (EVTX) ---
        evtx_hits = []
        if self.evtx_df is not None:
            cols = self.evtx_df.columns
            dst_ip_col = next((c for c in ["DestinationIp", "DestAddress", "DestinationAddress"] if c in cols), None)
            dst_port_col = next((c for c in ["DestinationPort", "DestPort"] if c in cols), None)
            img_col = next((c for c in ["Image", "Application", "ProcessName"] if c in cols), "Unknown_App")
            time_col = next((c for c in ["TimeCreated", "Timestamp_UTC"] if c in cols), "Time")

            if dst_ip_col:
                noise_ips = ["0.0.0.0", "255.255.255.255"]
                multicast = r"^(224\.|239\.|ff02::)"
                
                net_evts = self.evtx_df.filter(
                    ~pl.col(dst_ip_col).is_in(noise_ips) &
                    ~pl.col(dst_ip_col).str.contains(multicast)
                )
                if self.start_time: net_evts = net_evts.filter(pl.col(time_col) >= self.start_time)
                if self.end_time:   net_evts = net_evts.filter(pl.col(time_col) <= self.end_time)

                if net_evts.height > 0:
                    for row in net_evts.iter_rows(named=True):
                        ip = str(row.get(dst_ip_col, ""))
                        proc = str(row.get(img_col, "")).lower()
                        proc_name = proc.split("\\")[-1]
                        
                        heat_score = 0 # EVTXの場合はHeat Scoreを簡易計算
                        tags = []
                        
                        is_internal = self._is_internal_ip(ip)
                        
                        # 1. Lateral Tool
                        if proc_name in self.lateral_processes:
                            heat_score += 40
                            tags.append("LATERAL_TOOL")
                        
                        # 2. Connection Context
                        if is_internal:
                            port = str(row.get(dst_port_col, ""))
                            if port in ["445", "135", "5985", "5986"]:
                                heat_score += 30
                                tags.append("SMB_WMI_WINRM")
                                if proc_name in self.lateral_processes:
                                    heat_score += 20
                        
                        # 3. External C2
                        if not is_internal and proc_name in ["powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe"]:
                            heat_score += 60
                            tags.append("POTENTIAL_C2")
                            
                        # Verdict
                        if heat_score >= 60:
                            verdict = "LATERAL_MOVEMENT" if is_internal else "C2_COMMUNICATION"
                            evtx_hits.append({
                                "Timestamp": row.get(time_col),
                                "Process": proc,
                                "Remote_IP": ip,
                                "Plutos_Verdict": verdict,
                                "Tags": ", ".join(tags),
                                "Heat_Score": heat_score,
                                "Detail": f"Port: {row.get(dst_port_col)} | Tags: {tags}"
                            })

        df_srum_res = pl.DataFrame(srum_hits) if srum_hits else None
        df_evtx_res = pl.DataFrame(evtx_hits) if evtx_hits else None
        
        return df_srum_res, df_evtx_res

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

    gate = PlutosGate(args.dir, args.pandora, args.start, args.end)

    # 1. Lateral Movement (Pandora based)
    df_lat = gate.analyze_lateral_movement()
    if df_lat is not None and df_lat.height > 0:
        print(f"[!] LATERAL MOVEMENT / EXFIL DETECTED: {df_lat.height} artifacts.")
        df_lat.write_csv(args.out)
    else:
        print("[-] No file-based lateral movement traces found.")

    # 2. Network Traffic (SRUM & EVTX)
    df_srum, df_evtx = gate.analyze_network_traffic()
    
    if df_srum is not None and df_srum.height > 0:
        print(f"[!] SRUM HIGH HEAT EVENTS: {df_srum.height} records.")
        # Append or Write separate? SRUM usually differs in schema, keep separate or merge smart.
        # Here we write to dedicated SRUM log for Atropos
        df_srum.write_csv(args.out.replace(".csv", "_srum.csv"))

    if df_evtx is not None and df_evtx.height > 0:
        print(f"[!] NETWORK CONNECTIONS TRACED: {df_evtx.height} events.")
        df_evtx.write_csv(args.net_out)
    else:
        print("[-] No significant network anomalies found.")

if __name__ == "__main__":
    main()
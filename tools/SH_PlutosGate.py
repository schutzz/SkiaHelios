import polars as pl
import argparse
import sys
import os
import glob
import re
import ipaddress
from datetime import datetime

# ============================================================
#  SH_PlutosGate v3.4 [MFT Fix]
#  Mission: Detect Internal Exfiltration & Lateral Movement
#  Update: Fixed MFT/History file targeting (Pattern Strictness)
# ============================================================

def print_logo():
    print(r"""
       ______   __       __  __   ______   ______   ______    
      /\  == \ /\ \     /\ \/\ \ /\__  _\/\  __ \ /\  ___\   
      \ \  _-/ \ \ \____\ \ \_\ \\/_/\ \/\ \ \/\ \\ \___  \  
       \ \_\    \ \_____\  \ \_\ \ \_____\\/\_____\ 
      
      [ SH_PlutosGate v3.4 ]
      "The Heat of the Evidence burns away the Lies."
    """)

class PlutosGate:
    def __init__(self, kape_dir, pandora_csv=None, start_time=None, end_time=None):
        self.kape_dir = kape_dir
        self.pandora_df = self._load_pandora(pandora_csv) if pandora_csv else None
        self.start_time = start_time
        self.end_time = end_time
        
        # Load External Intelligence
        self.config = self._load_config()
        self.plutos_conf = self.config.get("plutos_config", {})

        # 設定: ヒートスコア計算用プロセス
        self.high_heat_processes = self.plutos_conf.get("high_heat_processes", [])
        self.burst_threshold = self.plutos_conf.get("burst_threshold_bytes", 50 * 1024 * 1024)

        # 監視対象ドメイン定義 (Dragnet)
        self.exfil_domains = self.plutos_conf.get("exfil_domains", [])
        
        # URL不審キーワード
        self.suspicious_url_keywords = self.plutos_conf.get("suspicious_url_keywords", [])

        # メール送出を示唆するキーワード (URL/Title)
        self.mail_action_keywords = self.plutos_conf.get("mail_action_keywords", [])

        # [v5.5] IIS Log Analysis Patterns
        self.iis_attack_signatures = self.plutos_conf.get("iis_attack_signatures", [])

    def _load_config(self):
        try:
            from pathlib import Path
            import yaml
            # Assuming rules directory is peer to tools or similar logic
            # This logic mimics HerculesReferee
            base_dir = Path(__file__).parent.parent
            config_path = base_dir / "rules" / "intel_signatures.yaml"
            if not config_path.exists():
                print(f"[!] Config not found: {config_path}")
                return {}
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"[!] Error loading config: {e}")
            return {}

    def _load_csv(self, pattern, columns=None):
        """高速読み込み用ラッパー (LazyFrame)"""
        search_path = os.path.join(self.kape_dir, "**", pattern)
        files = glob.glob(search_path, recursive=True)
        if not files: return None
        
        target_file = files[0]
        
        try:
            lf = pl.scan_csv(target_file, ignore_errors=True, infer_schema_length=10000)
            if columns:
                # 実際に存在するカラムだけを選択 (Missing Columns Error回避)
                available_cols = [c for c in columns if c in lf.collect_schema().names()]
                if not available_cols:
                    print(f"[!] Warning: None of the requested columns {columns} found in {os.path.basename(target_file)}")
                    return None
                lf = lf.select(available_cols)
            return lf 
        except Exception as e:
            print(f"[!] Error loading {pattern}: {e}")
            return None

    def _load_pandora(self, path):
        if path and os.path.exists(path):
            try: return pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
            except: pass
        return None

    def _is_internal_ip(self, ip_str):
        if not ip_str or ip_str in ["-", "", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"]: return True
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except: return False

    # ---------------------------------------------------------
    # Feature 1: Lateral Movement
    # ---------------------------------------------------------
    def analyze_lateral_movement(self):
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
            rdp_ghosts = self.pandora_df.filter(pl.col("ParentPath").str.to_lowercase().str.contains("tsclient")).select(["Ghost_FileName", "ParentPath", "Risk_Tag"])
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

    # ---------------------------------------------------------
    # Feature 2: Network Thermodynamics (Vectorized)
    # ---------------------------------------------------------
    def analyze_network_traffic_fast(self):
        print("[*] Phase 2: Analyzing Network Thermodynamics (Vectorized)...")
        
        # --- SRUM Analysis ---
        # Usageログをピンポイント指定
        lf_srum = self._load_csv("*SRUM*NetworkUsage*.csv") 
        srum_res = None
        evtx_res = None

        if lf_srum is not None:
            schema = lf_srum.collect_schema().names()
            app_col = next((c for c in ["ExeInfo", "AppId", "AppName", "Process"] if c in schema), "AppId")
            sent_col = next((c for c in ["BytesSent", "Bytes_Sent"] if c in schema), "BytesSent")
            recv_col = next((c for c in ["BytesReceived", "Bytes_Received"] if c in schema), "BytesReceived")
            time_col = next((c for c in ["Timestamp", "Time", "Date"] if c in schema), "Timestamp")

            if sent_col not in schema:
                print(f"[!] SRUM Skip: 'BytesSent' column not found in {schema}")
            else:
                score_expr = pl.lit(0)
                for proc in self.high_heat_processes:
                    score_add = 50 if proc in ["mstsc.exe", "psexesvc.exe"] else 20
                    score_expr = score_expr + pl.when(pl.col(app_col).str.to_lowercase().str.contains(proc)).then(score_add).otherwise(0)

                score_expr = score_expr + \
                             pl.when(pl.col(sent_col).cast(pl.Float64, strict=False).fill_null(0) > self.burst_threshold).then(60).otherwise(0) + \
                             pl.when(pl.col(recv_col).cast(pl.Float64, strict=False).fill_null(0) > self.burst_threshold).then(40).otherwise(0)

                q_srum = (
                    lf_srum
                    .with_columns([
                        score_expr.alias("Heat_Score"),
                        (pl.col(sent_col).cast(pl.Float64, strict=False).fill_null(0) + pl.col(recv_col).cast(pl.Float64, strict=False).fill_null(0)).alias("Total_Bytes")
                    ])
                    .filter(pl.col("Heat_Score") >= 60)
                    .select([
                        pl.col(time_col).alias("Timestamp"),
                        pl.col(app_col).alias("Process"),
                        pl.col(sent_col).cast(pl.Int64),
                        pl.col(recv_col).cast(pl.Int64),
                        pl.col("Heat_Score"),
                        pl.lit("SRUM_HIGH_HEAT").alias("Plutos_Verdict"),
                        pl.lit("Unknown (SRUM)").alias("Remote_IP"),
                        pl.lit("").alias("Remote_Port"),
                        pl.lit("Potential Exfiltration/Tunneling").alias("Tags")
                    ])
                )
                try: srum_res = q_srum.collect()
                except Exception as e: print(f"[!] SRUM Analysis Error: {e}")

        # --- EVTX Analysis ---
        lf_evtx = self._load_csv("*EvtxECmd*.csv")
        if lf_evtx is not None:
            schema = lf_evtx.collect_schema().names()
            if "EventId" in schema:
                dst_ip_col = next((c for c in ["DestinationIp", "DestAddress", "DestinationAddress"] if c in schema), None)
                dst_port_col = next((c for c in ["DestinationPort", "DestPort"] if c in schema), None)
                img_col = next((c for c in ["Image", "Application", "ProcessName"] if c in schema), "Unknown_App")
                time_col = next((c for c in ["TimeCreated", "Timestamp_UTC"] if c in schema), "Time")

                if dst_ip_col and dst_port_col:
                    noise_ips = self.plutos_conf.get("network_noise_ips", ["0.0.0.0", "255.255.255.255", "127.0.0.1", "::1"])
                    target_eids = self.plutos_conf.get("target_event_ids", [3, 5156, 5154, 5157])
                    
                    q_evtx = (
                        lf_evtx
                        .filter(pl.col("EventId").cast(pl.Int64, strict=False).is_in(target_eids))
                        .filter(~pl.col(dst_ip_col).is_in(noise_ips))
                        .filter(~pl.col(dst_ip_col).str.starts_with("224."))
                        .filter(~pl.col(dst_ip_col).str.starts_with("ff02"))
                        .with_columns([
                            pl.col(time_col).alias("Timestamp"),
                            pl.col(img_col).alias("Process"),
                            pl.col(dst_ip_col).alias("Remote_IP"),
                            pl.col(dst_port_col).cast(pl.Utf8).alias("Remote_Port"),
                            pl.lit(0).alias("Heat_Score")
                        ])
                    )

                    # [Phase 7] Orphan Rescue & Port Analysis
                    # Load Network Spec from Config
                    net_conf = self.config.get("network_config", {})
                    susp_ports = net_conf.get("suspicious_ports", [445, 3389, 5985, 5986, 8080, 4444])
                    private_ranges = net_conf.get("private_ip_ranges", ["192.168.", "10.", "172."])

                    try: 
                        evtx_raw = q_evtx.collect()
                        
                        if evtx_raw.height > 0:
                            # Apply Rescue Logic in Memory (Polars)
                            # 1. Flag Suspicious Ports (Lateral/C2)
                            evtx_res = evtx_raw.with_columns(
                                pl.when(pl.col("Remote_Port").cast(pl.Int64, strict=False).is_in(susp_ports))
                                .then(pl.lit("CRITICAL_NETWORK_TRACE"))
                                .otherwise(pl.lit("NETWORK_CONNECTION"))
                                .alias("Plutos_Verdict"),
                                
                                pl.when(pl.col("Remote_Port").cast(pl.Int64, strict=False).is_in(susp_ports))
                                .then(pl.lit("ORPHAN_RESCUE"))
                                .otherwise(pl.lit("EVTX_TRACE"))
                                .alias("Tags"),

                                pl.when(pl.col("Remote_Port").cast(pl.Int64, strict=False).is_in(susp_ports))
                                .then(200) # High Score for Suspicious Ports
                                .otherwise(0)
                                .alias("Heat_Score")
                            )

                            # 2. Filter: Only keep Rescued/Suspicious items if "Orphan" mode is strict
                            # But for now, user wants ANY suspicious orphan.
                            # We filter out low-score noise if needed, but keep High Score.
                            evtx_res = evtx_res.filter(pl.col("Heat_Score") > 0)

                            if evtx_res.height > 0:
                                print(f"    [+] ORPHAN RESCUE: Recovered {evtx_res.height} suspicious network events.")
                    except Exception as e: print(f"[!] EVTX Analysis Error: {e}")

        return srum_res, evtx_res

    # ---------------------------------------------------------
    # Feature 3: Exfiltration Correlation
    # ---------------------------------------------------------
    def analyze_exfiltration_correlation(self):
        print("[*] Phase 3: Correlating Exfiltration (SRUM x Browser x MFT)...")
        
        lf_srum = self._load_csv("*SRUM*NetworkUsage*.csv")
        # [FIX] History読み込みを厳格化（ClioGet出力に限定）
        lf_hist = self._load_csv("Browser_History*.csv") 
        # [FIX] MFT読み込みを厳格化（Bootセクタ誤爆回避）
        lf_mft  = self._load_csv("*$MFT_Output.csv")     

        if lf_srum is None or lf_hist is None or lf_mft is None:
            print("[-] Missing artifacts for correlation.")
            return None

        # Preprocessing
        def parse_date(col_name):
            return pl.coalesce([
                pl.col(col_name).str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                pl.col(col_name).str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                pl.col(col_name).str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False)
            ])

        # SRUM setup
        srum_cols = lf_srum.collect_schema().names()
        srum_time = next((c for c in ["Timestamp", "Time", "Date"] if c in srum_cols), "Timestamp")
        srum_sent = next((c for c in ["BytesSent", "Bytes_Sent"] if c in srum_cols), "BytesSent")
        srum_app  = next((c for c in ["ExeInfo", "AppId", "AppName", "Process"] if c in srum_cols), "AppId")

        if srum_sent not in srum_cols:
            print(f"[!] Correlation Skip: 'BytesSent' missing in SRUM.")
            return None

        q_srum = (
            lf_srum
            .filter(pl.col(srum_sent).cast(pl.Float64, strict=False) > 10_000_000) # 10MB
            .with_columns(parse_date(srum_time).alias("Timestamp_DT"))
            .drop_nulls("Timestamp_DT")
            .select([pl.col("Timestamp_DT").alias("Timestamp"), pl.col(srum_app).alias("AppId"), pl.col(srum_sent).alias("BytesSent")])
            .sort("Timestamp")
        )

        # Browser
        hist_cols = lf_hist.collect_schema().names()
        hist_url = next((c for c in ["URL", "ValueData", "Url"] if c in hist_cols), "URL")
        hist_time = next((c for c in ["VisitTime", "LastWriteTimestamp"] if c in hist_cols), "VisitTime")
        hist_title = next((c for c in ["Title", "ValueName"] if c in hist_cols), "Title")

        domain_pattern = "|".join(self.exfil_domains)
        keyword_pattern = "|".join(self.suspicious_url_keywords)
        combined_pattern = f"(?i)({domain_pattern}|{keyword_pattern})"

        q_hist = (
            lf_hist
            .filter(pl.col(hist_url).str.contains(combined_pattern))
            .with_columns(parse_date(hist_time).alias("VisitTime_DT"))
            .drop_nulls("VisitTime_DT")
            .select([pl.col("VisitTime_DT").alias("VisitTime"), pl.col(hist_url).alias("URL"), pl.col(hist_title).alias("Title")])
            .sort("VisitTime")
        )

        # MFT
        mft_cols = lf_mft.collect_schema().names()
        mft_name = next((c for c in ["FileName", "Name"] if c in mft_cols), "FileName")
        mft_time = next((c for c in ["StandardInformation_Created", "Created0x10", "SI_Created"] if c in mft_cols), "Created0x10")
        mft_size = next((c for c in ["FileSize", "Size"] if c in mft_cols), "FileSize")

        q_mft = (
            lf_mft
            .filter(pl.col(mft_name).str.contains(r"(?i)\.(zip|rar|7z|xlsx|docx|pdf|csv)$"))
            .with_columns(parse_date(mft_time).alias("Created_DT"))
            .drop_nulls("Created_DT")
            .select([pl.col("Created_DT").alias("FileCreated"), pl.col(mft_name).alias("FileName"), pl.col(mft_size).alias("FileSize")])
            .sort("FileCreated")
        )

        try:
            joined = q_srum.join_asof(q_hist, left_on="Timestamp", right_on="VisitTime", strategy="backward", tolerance="1h")
            final_q = joined.join_asof(q_mft, left_on="Timestamp", right_on="FileCreated", strategy="backward", tolerance="2h")

            result = final_q.filter(
                pl.col("URL").is_not_null() | pl.col("FileName").is_not_null()
            ).collect()
            return result
        except Exception as e:
            print(f"[!] Correlation Error: {e}")
            return None

    # ---------------------------------------------------------
    # Feature 4: Email Hunter
    # ---------------------------------------------------------
    def analyze_email_artifacts(self):
        print("[*] Phase 4: Hunting Email Artifacts (PST/OST & Webmail Actions)...")
        hits = []

        # A. Local Email Archives
        lf_mft = self._load_csv("*$MFT_Output.csv") # ここも修正
        if lf_mft is not None:
            cols = lf_mft.collect_schema().names()
            mft_path = next((c for c in ["ParentPath", "ParentFolder"] if c in cols), "ParentPath")
            mft_name = next((c for c in ["FileName", "Name"] if c in cols), "FileName")
            mft_time = next((c for c in ["StandardInformation_Created", "Created0x10"] if c in cols), "Created0x10")

            q_mail_files = (
                lf_mft
                .filter(pl.col(mft_name).str.contains(r"(?i)\.(pst|ost|eml|msg)$"))
                .filter(~pl.col(mft_path).str.to_lowercase().str.contains(r"appdata|microsoft\\outlook"))
                .select([
                    pl.col(mft_time).alias("Timestamp"),
                    pl.col(mft_name).alias("Artifact"),
                    pl.col(mft_path).alias("Path"),
                    pl.lit("SUSPICIOUS_EMAIL_ARCHIVE").alias("Verdict")
                ])
            )
            try:
                res_files = q_mail_files.collect()
                if res_files.height > 0:
                    hits.append(res_files)
            except: pass

        # B. Webmail Actions
        lf_hist = self._load_csv("Browser_History*.csv") # 修正
        if lf_hist is not None:
            cols = lf_hist.collect_schema().names()
            h_url = next((c for c in ["URL", "ValueData"] if c in cols), "URL")
            h_title = next((c for c in ["Title", "ValueName"] if c in cols), "Title")
            h_time = next((c for c in ["VisitTime", "LastWriteTimestamp"] if c in cols), "VisitTime")

            mail_domains = r"mail\.google|outlook\.live|yahoo|proton"
            action_keywords = "|".join(self.mail_action_keywords)
            
            q_webmail = (
                lf_hist
                .filter(pl.col(h_url).str.contains(mail_domains))
                .filter(
                    pl.col(h_url).str.contains(f"(?i)({action_keywords})") | 
                    pl.col(h_title).str.contains(f"(?i)({action_keywords})")
                )
                .select([
                    pl.col(h_time).alias("Timestamp"),
                    pl.col(h_title).alias("Artifact"),
                    pl.col(h_url).alias("Path"),
                    pl.lit("WEBMAIL_SEND_ACTIVITY").alias("Verdict")
                ])
            )
            try:
                res_web = q_webmail.collect()
                if res_web.height > 0:
                    hits.append(res_web)
            except: pass

        if hits:
            return pl.concat(hits)
        return None

    # ============================================================
    # [v5.5] IIS Log Analyzer
    # ============================================================
    def analyze_iis_logs(self):
        """
        Analyze IIS/W3SVC logs for web attack signatures.
        Detects: SQLi, WebShell, Path Traversal, 500-burst, 404 reconnaissance
        """
        print("[*] Phase 5: Analyzing IIS/Web Server Logs...")
        
        # Try multiple IIS log patterns
        lf_iis = None
        for pattern in ["*IIS*.csv", "*W3SVC*.csv", "*u_ex*.csv", "*iis*.csv"]:
            lf_iis = self._load_csv(pattern)
            if lf_iis is not None:
                break
        
        if lf_iis is None:
            print("    [*] No IIS logs found. Skipping web analysis.")
            return None
        
        try:
            # Identify columns
            schema = lf_iis.collect_schema().names()
            
            # Common IIS log column variations
            uri_col = next((c for c in ["cs-uri-stem", "UriStem", "URI", "Request", "cs_uri_stem"] if c in schema), None)
            query_col = next((c for c in ["cs-uri-query", "UriQuery", "Query", "QueryString", "cs_uri_query"] if c in schema), None)
            status_col = next((c for c in ["sc-status", "Status", "StatusCode", "sc_status"] if c in schema), None)
            time_col = next((c for c in ["date", "DateTime", "Timestamp", "time"] if c in schema), None)
            client_col = next((c for c in ["c-ip", "ClientIP", "ClientIp", "c_ip", "SourceIp"] if c in schema), None)
            
            if not uri_col:
                print("    [!] Cannot identify URI column in IIS logs.")
                return None
            
            print(f"    [+] IIS columns detected: URI={uri_col}, Status={status_col}")
            
            hits = []
            
            # --- 1. Attack Signature Detection ---
            combined_pattern = "|".join(self.iis_attack_signatures)
            
            # Build filter expression
            filter_expr = pl.col(uri_col).str.contains(combined_pattern)
            if query_col and query_col in schema:
                filter_expr = filter_expr | pl.col(query_col).cast(pl.Utf8).fill_null("").str.contains(combined_pattern)
            
            attack_hits = lf_iis.filter(filter_expr)
            attack_df = attack_hits.collect()
            
            if attack_df.height > 0:
                print(f"    [!] WEB ATTACK SIGNATURES DETECTED: {attack_df.height} requests")
                attack_df = attack_df.with_columns([
                    pl.lit("WEB_ATTACK_SIGNATURE").alias("Plutos_Verdict"),
                    pl.lit("CRITICAL").alias("Severity"),
                    pl.lit(300).alias("Heat_Score")
                ])
                hits.append(attack_df)
            
            # --- 2. 500-Error Burst Detection ---
            if status_col and status_col in schema:
                error_500 = lf_iis.filter(
                    pl.col(status_col).cast(pl.Utf8).str.starts_with("5")
                ).collect()
                
                if error_500.height >= 5:
                    print(f"    [!] SERVER ERROR BURST: {error_500.height} 5xx errors")
                    error_500 = error_500.with_columns([
                        pl.lit("IIS_SERVER_ERROR_BURST").alias("Plutos_Verdict"),
                        pl.lit("HIGH").alias("Severity"),
                        pl.lit(80).alias("Heat_Score")
                    ])
                    hits.append(error_500.head(50))  # Limit output
            
            # --- 3. 404 Reconnaissance Detection ---
            if status_col and status_col in schema and uri_col:
                recon_404 = (
                    lf_iis
                    .filter(pl.col(status_col).cast(pl.Utf8) == "404")
                    .group_by(uri_col)
                    .agg(pl.len().alias("hit_count"))
                    .filter(pl.col("hit_count") >= 3)  # 3+ hits on same 404 = recon
                    .collect()
                )
                
                if recon_404.height > 0:
                    print(f"    [!] RECONNAISSANCE SCAN: {recon_404.height} URIs with repeated 404s")
                    recon_404 = recon_404.with_columns([
                        pl.lit("RECONNAISSANCE_404_SCAN").alias("Plutos_Verdict"),
                        pl.lit("MEDIUM").alias("Severity"),
                        pl.lit(50).alias("Heat_Score")
                    ])
                    hits.append(recon_404)
            
            if hits:
                return pl.concat(hits, how="diagonal")
            
        except Exception as e:
            print(f"    [!] IIS Analysis Error: {e}")
        
        return None

    # ============================================================
    # [v6.0] Browser Reconnaissance Hunter (Updated for Feature 2)
    # ============================================================
    def analyze_browser_recon(self):
        """
        Analyze browser history for reconnaissance activities.
        Detects: Hacking tools research, exfiltration methods, security conference downloads,
        AND [Feature 2] Internal Recon (phpMyAdmin, etc.)
        """
        print("[*] Phase 6: Hunting Browser Reconnaissance (Internal & External)...")
        
        lf_hist = self._load_csv("Browser_History*.csv")
        if lf_hist is None:
            return None

        # Load Recon Indicators from Config
        recon_conf = self.config.get("recon_indicators", {})
        susp_domains = recon_conf.get("suspicious_domains", [])
        susp_terms = recon_conf.get("suspicious_search_terms", [])
        susp_downloads = recon_conf.get("suspicious_downloads", {}).get("patterns", [])
        
        # [Feature 2] Internal Recon Keywords
        internal_recon_kws = ["phpmyadmin", "phpinfo", "adminer", "webmin", "kibana", "/admin/", "/dashboard/"]
        
        # Fallback if config unavailable (Safety Net)
        if not susp_domains:
             susp_domains = ["kali.org", "metasploit.com", "exploit-db.com", "packetstorm"]
        
        try:
            schema = lf_hist.collect_schema().names()
            url_col = next((c for c in ["URL", "ValueData", "Url"] if c in schema), "URL")
            title_col = next((c for c in ["Title", "ValueName"] if c in schema), "Title")
            time_col = next((c for c in ["VisitTime", "LastWriteTimestamp"] if c in schema), "VisitTime")
            tag_col = next((c for c in ["Tag"] if c in schema), None)  # Check if ClioGet added Tags
            
            # 1. Regex Construction
            domain_pattern = "|".join([re.escape(d) for d in susp_domains])
            term_pattern = "|".join(susp_terms) if susp_terms else r"(?!)" 
            download_pattern = "|".join(susp_downloads) if susp_downloads else r"(?!)"
            internal_pattern = "|".join([re.escape(k) for k in internal_recon_kws])

            # Build Filter Expression - Match URL/Title patterns OR ClioGet Tag
            filter_expr = (
                pl.col(url_col).str.contains(f"(?i)({domain_pattern}|{term_pattern}|{download_pattern}|{internal_pattern})") |
                pl.col(title_col).str.contains(f"(?i)({term_pattern}|{internal_pattern})")
            )
            
            if tag_col:
                filter_expr = filter_expr | pl.col(tag_col).str.contains("INTERNAL_RECON_WEB")

            # Combine all recon patterns for filtering
            recon_hits = (
                lf_hist
                .filter(filter_expr)
                .with_columns([
                    # Timestamp normalization
                    pl.col(time_col).alias("Timestamp"),
                    pl.col(url_col).alias("URL"),
                    pl.col(title_col).alias("Title"),
                    
                    # Verdict Determination - Internal Recon takes priority
                    pl.when(
                        pl.col(url_col).str.contains(f"(?i)({internal_pattern})") | 
                        (pl.col(tag_col).str.contains("INTERNAL_RECON_WEB") if tag_col else pl.lit(False))
                    )
                    .then(pl.lit("INTERNAL_RECON_WEB"))
                    .when(pl.col(url_col).str.contains(f"(?i)({domain_pattern})"))
                    .then(pl.lit("RECON_ACTIVITY"))
                    .when(pl.col(url_col).str.contains(f"(?i)({download_pattern})"))
                    .then(pl.lit("RECON_SECTOOLS"))
                    .otherwise(pl.lit("RECON_EXFILTRATION"))
                    .alias("Plutos_Verdict"),
                    
                    # Score Assignment - [Feature 2] Internal Recon = 600 (High Priority)
                    pl.when(
                        pl.col(url_col).str.contains(f"(?i)({internal_pattern})") | 
                        (pl.col(tag_col).str.contains("INTERNAL_RECON_WEB") if tag_col else pl.lit(False))
                    )
                    .then(600)  # [Feature 2] Internal Recon is High Priority
                    .when(pl.col(url_col).str.contains(f"(?i)({download_pattern})"))
                    .then(150) 
                    .when(pl.col(url_col).str.contains("(?i)exfiltrat"))
                    .then(120) 
                    .otherwise(100) 
                    .alias("Heat_Score"),
                    
                    pl.lit("RECONNAISSANCE").alias("Tags")
                ])
                .select(["Timestamp", "URL", "Title", "Plutos_Verdict", "Heat_Score", "Tags"])
                .collect()
            )
            
            if recon_hits.height > 0:
                internal_count = recon_hits.filter(pl.col("Plutos_Verdict") == "INTERNAL_RECON_WEB").height
                print(f"[!] BROWSER RECONNAISSANCE DETECTED: {recon_hits.height} events")
                if internal_count > 0:
                    print(f"    [!] INTERNAL RECON (phpMyAdmin/phpinfo/admin): {internal_count} events - HIGH PRIORITY")
                return recon_hits
                
        except Exception as e:
            print(f"[!] Browser Recon Analysis Error: {e}")
            import traceback
            traceback.print_exc()
            
        return None

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

    # 1. Lateral Movement
    df_lat = gate.analyze_lateral_movement()
    if df_lat is not None and df_lat.height > 0:
        print(f"[!] LATERAL MOVEMENT / EXFIL DETECTED: {df_lat.height} artifacts.")
        df_lat.write_csv(args.out)

    # 2. Network Traffic (Fast SRUM & EVTX)
    df_srum, df_evtx = gate.analyze_network_traffic_fast()
    if df_srum is not None and df_srum.height > 0:
        print(f"[!] SRUM HIGH HEAT EVENTS: {df_srum.height} records.")
        df_srum.write_csv(args.out.replace(".csv", "_srum.csv"))
    if df_evtx is not None and df_evtx.height > 0:
        print(f"[!] NETWORK CONNECTIONS TRACED: {df_evtx.height} events.")
        df_evtx.write_csv(args.net_out)

    # 3. Exfiltration Correlation
    df_exfil = gate.analyze_exfiltration_correlation()
    if df_exfil is not None and df_exfil.height > 0:
        print(f"[!] EXFILTRATION CORRELATION FOUND: {df_exfil.height} events")
        df_exfil.write_csv(args.out.replace(".csv", "_exfil_correlation.csv"))

    # 4. Email Hunter
    df_mail = gate.analyze_email_artifacts()
    if df_mail is not None and df_mail.height > 0:
        print(f"[!] SUSPICIOUS EMAIL ACTIVITY DETECTED: {df_mail.height} events")
        df_mail.write_csv(args.out.replace(".csv", "_email_hunt.csv"))

    # 5. IIS/Web Server Log Analysis [v5.5]
    df_iis = gate.analyze_iis_logs()
    if df_iis is not None and df_iis.height > 0:
        print(f"[!] WEB SERVER ANOMALIES DETECTED: {df_iis.height} events")
        df_iis.write_csv(args.out.replace(".csv", "_iis_analysis.csv"))

    # 6. Browser Reconnaissance [v6.0]
    df_recon = gate.analyze_browser_recon()
    if df_recon is not None and df_recon.height > 0:
        print(f"[!] BROWSER RECONNAISSANCE IDENTIFIED: {df_recon.height} events")
        df_recon.write_csv(args.out.replace(".csv", "_recon.csv"))

if __name__ == "__main__":
    main()
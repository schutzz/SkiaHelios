import polars as pl
import argparse
from pathlib import Path
import sys
import datetime
import json
import re
from tools.SH_ThemisLoader import ThemisLoader
from tools.SH_HestiaCensorship import Hestia

# ============================================================
#  SH_HerculesReferee v4.30 [Justice V3 + The Linker]
#  Mission: Identity + Script Hunter + GHOST CORRELATION
#  Update: Phase 4 Network Correlation Analysis
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HERCULES --   [ Referee v4.30 ]
      | | | | | |    "The Linker: Network Correlation Active."
    """)


# ============================================================
#  [NEW] NetworkCorrelator - Phase 4 Implementation
#  Mission: Extract IOCs & verify against Browser/DNS logs
# ============================================================
class NetworkCorrelator:
    def __init__(self, kape_dir):
        self.kape_dir = Path(kape_dir)
        self.browser_history = None
        self.dns_cache = None
        self.initialized = False
        
        # IOC Patterns
        self.url_regex = re.compile(
            r'(https?://[a-zA-Z0-9.-]+(?:/[^\s"\'<>]*)?|'
            r'www\.[a-zA-Z0-9.-]+|'
            r'[a-zA-Z0-9.-]+\.(?:com|net|org|io|ru|cn|jp|co|info|biz|xyz|top))',
            re.IGNORECASE
        )
        self.ip_regex = re.compile(r'\b(?:(?!0\.0\.0\.0|127\.0\.0\.1)(?:\d{1,3}\.){3}\d{1,3})\b')
        
        # Noise domains to exclude
        self.noise_domains = [
            "microsoft.com", "google.com", "windowsupdate.com", "bing.com",
            "adobe.com", "apple.com", "amazon.com", "cloudflare.com",
            "akamai.net", "googleapis.com", "gstatic.com", "office.com"
        ]

    def initialize(self):
        """Lazy initialization to avoid slowdown if not needed"""
        if self.initialized:
            return
        print("    -> [Linker] Initializing Network Correlation Engine...")
        self.browser_history = self._load_browser_history()
        self.dns_cache = self._load_dns_cache()
        self.initialized = True
        if self.browser_history is not None:
            print(f"       >> Browser History Loaded: {self.browser_history.height} entries")
        else:
            print("       >> (No Browser History CSVs found for correlation)")

    def _load_browser_history(self):
        """Load browser history CSVs from KAPE output"""
        # Expanded search patterns
        targets = list(self.kape_dir.rglob("*History*.csv")) + \
                  list(self.kape_dir.rglob("*places*.csv")) + \
                  list(self.kape_dir.rglob("*WebCacheV*.csv")) + \
                  list(self.kape_dir.rglob("Browser*/*.csv"))  # Browser_Artifacts folder
        
        df_list = []
        for t in targets:
            try:
                # Skip our own output files
                if "Helios_Output" in str(t) or "Timeline" in str(t):
                    continue
                    
                df = pl.read_csv(t, ignore_errors=True, infer_schema_length=0)
                
                # Find URL column - try multiple variations
                url_col = None
                for candidate in ["URL", "Url", "url", "ValueData", "value_data", "SourceUrl", "TargetUrl"]:
                    if candidate in df.columns:
                        url_col = candidate
                        break
                
                if url_col:
                    df_list.append(df.select(pl.col(url_col).alias("URL").str.to_lowercase()))
            except Exception as e:
                pass
        
        if not df_list:
            return None
        return pl.concat(df_list).unique()

    def _load_dns_cache(self):
        """Stub for DNS cache loading (future expansion)"""
        return None

    def extract_iocs(self, text):
        """Extract URLs/IPs from text"""
        if not text:
            return []
        text = str(text).lower()
        
        # Skip known noise
        for noise in self.noise_domains:
            if noise in text:
                return []
        
        urls = self.url_regex.findall(text)
        ips = self.ip_regex.findall(text)
        
        # Filter short garbage
        result = [ioc for ioc in set(urls + ips) if len(ioc) > 6]
        return result

    def check_connection(self, ioc_list):
        """Check if any IOC exists in browser history"""
        if self.browser_history is None or not ioc_list:
            return False
        
        try:
            # Escape IOCs for regex safety
            patterns = [re.escape(ioc) for ioc in ioc_list if len(ioc) > 4]
            if not patterns:
                return False
            
            combined_pat = "|".join(patterns)
            hits = self.browser_history.filter(pl.col("URL").str.contains(combined_pat))
            return hits.height > 0
        except Exception as e:
            return False


class HerculesReferee:
    def __init__(self, kape_dir, triage_mode=False):
        self.kape_dir = Path(kape_dir)
        self.triage_mode = triage_mode
        self.loader = ThemisLoader(["rules/triage_rules.yaml", "rules/sigma_process_creation.yaml", "rules/sigma_registry.yaml"])
        self.hestia = Hestia()
        self.os_info = "Windows (Unknown Version)"
        
        # [Phase 4] Initialize The Linker
        self.linker = NetworkCorrelator(kape_dir)
        
        # [v4.40] 正規の時刻同期エージェント定義
        self.ALLOWED_TIME_AGENTS = [
            "vboxservice", "vmtoolsd", "w32tm", "svchost"
        ]

    def _apply_context_filtering(self, df):
        """
        [v4.40] ルールベース判定の後に、文脈（Context）による最終調整を行う
        VBoxServiceなどの正規時刻同期を無罪化
        """
        print("    -> [Hercules v4.40] Applying Context Filters (VBox / Time Sync)...")
        
        cols = df.columns
        
        # カラム存在チェック
        if "Tag" not in cols or "Threat_Score" not in cols:
            return df
        
        action_col = "Action" if "Action" in cols else None
        target_col = "Target_Path" if "Target_Path" in cols else None
        
        # 1. System Time Change の無罪化
        is_time_event = pl.col("Tag").str.contains("TIME") | pl.col("Tag").str.contains("4616")
        
        is_legit_agent = pl.lit(False)
        for agent in self.ALLOWED_TIME_AGENTS:
            if action_col:
                is_legit_agent = is_legit_agent | pl.col(action_col).str.to_lowercase().str.contains(agent)
            if target_col:
                is_legit_agent = is_legit_agent | pl.col(target_col).str.to_lowercase().str.contains(agent)

        # 無罪化ロジック: Timeイベント かつ 正規エージェント -> Score 0, Tag INFO
        df = df.with_columns([
            pl.when(is_time_event & is_legit_agent)
              .then(0)
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score"),
              
            pl.when(is_time_event & is_legit_agent)
              .then(pl.lit("INFO_VM_TIME_SYNC"))
              .otherwise(pl.col("Tag"))
              .alias("Tag")
        ])
        
        return df

    def _load_evtx_csv(self):
        csvs = list(self.kape_dir.rglob("*EvtxECmd*.csv"))
        if not csvs: return None
        target = csvs[0]
        print(f"[*] Loading Event Logs from: {target.name}")
        return pl.read_csv(target, ignore_errors=True, infer_schema_length=0)

    # [NEW] Registry Priority Logic (Forced BuildLab + ProductName)
    def _extract_os_from_registry(self):
        print("[*] Phase 0: Checking Registry (RECmd) for OS Info...")
        # Broaden search to ensure we catch RECmd variations
        reg_csvs = list(self.kape_dir.rglob("*BasicSystemInfo*.csv"))
        if not reg_csvs:
             print("    [!] No RECmd BasicSystemInfo CSV found.")
             return False

        try:
            target_csv = reg_csvs[0]
            print(f"    -> Analyzing Registry Dump: {target_csv.name}")
            df = pl.read_csv(target_csv, ignore_errors=True, infer_schema_length=0)
            
            # 1. Force Check for BuildLab with STRICT Path
            # Path must contain Microsoft\Windows NT\CurrentVersion
            build_lab_rows = df.filter(
                pl.col("KeyPath").str.contains(r"Microsoft\\Windows NT\\CurrentVersion", strict=False) & 
                (pl.col("ValueName") == "BuildLab")
            )
            
            # 2. Check ProductName (Parallel)
            product_rows = df.filter(
                pl.col("KeyPath").str.contains(r"CurrentVersion", strict=False) & 
                (pl.col("ValueName") == "ProductName")
            )

            # Decision Logic
            detected_os = ""
            
            if product_rows.height > 0:
                detected_os = str(product_rows[0, "ValueData"])

            if build_lab_rows.height > 0:
                bl_val = str(build_lab_rows[0, "ValueData"])
                if "9600" in bl_val: detailed = "Windows 8.1 Update 1 (Build 9600)"
                elif "7601" in bl_val: detailed = "Windows 7 SP1 (Build 7601)"
                elif "10240" in bl_val: detailed = "Windows 10 (1507)"
                elif "1904" in bl_val: detailed = "Windows 10 (Build 1904x)"
                else: detailed = f"Build {bl_val}"
                
                if detected_os: detected_os += f" ({detailed})"
                else: detected_os = detailed

            if detected_os:
                self.os_info = detected_os + " (Detected from Registry)"
                print(f"    [+] OS Identified (Registry Sovereign): {self.os_info}")
                return True

        except Exception as e:
            print(f"    [!] Registry Analysis Error: {e}")
        
        return False

    def _map_os_version(self, version_str):
        if "6.1" in version_str: return "Windows 7 / Server 2008 R2"
        if "6.2" in version_str: return "Windows 8 / Server 2012"
        if "6.3" in version_str: return "Windows 8.1 / Server 2012 R2"
        if "10.0" in version_str: return "Windows 10 / Server 2016+"
        return f"Windows (Ver: {version_str})"

    def _extract_os_info_evtx(self, df_evtx):
        # Only run if Registry extraction failed
        if df_evtx is None: return
        print("    -> Checking Event Logs for OS Info (Fallback)...")
        try:
            cols = df_evtx.columns
            id_col = "EventId" if "EventId" in cols else "EventID"
            if id_col not in cols: return

            hits = df_evtx.filter(pl.col(id_col).cast(pl.Int64, strict=False) == 6009)
            
            if hits.height == 0:
                target_cols = [c for c in ["Payload", "Message", "Description"] if c in cols]
                expr = pl.lit(False)
                for c in target_cols:
                    expr = expr | pl.col(c).str.contains("Microsoft \(R\) Windows", strict=False)
                hits = df_evtx.filter(expr).head(1)

            if hits.height > 0:
                target_cols = [c for c in ["Payload", "Message", "Description", "PayloadData1"] if c in cols]
                for t_col in target_cols:
                    val = str(hits[0, t_col])
                    ver_match = re.search(r'(\d+\.\d+)', val)
                    if ver_match:
                        ver_str = ver_match.group(1)
                        if ver_str == "6.03": ver_str = "6.3"
                        self.os_info = self._map_os_version(ver_str)
                        print(f"    [+] OS Identified (EventLog): {self.os_info}")
                        return
        except Exception as e:
            print(f"    [!] OS Extraction Warning: {e}")

    def _export_metadata(self, output_path):
        # Save extracted intelligence for Hekate/Lachesis
        meta_file = Path(output_path).parent / "Case_Metadata.json"
        data = {
            "OS_Info": self.os_info,
            "Analyzed_At": datetime.datetime.now().isoformat(),
            "Triage_Mode": self.triage_mode
        }
        try:
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"[+] Metadata Saved: {meta_file}")
        except: pass

    def judge(self, timeline_df):
        """
        メイン判定ロジック (Justice V3: The Executioner)
        Mission: Fix LNK Analysis & Strict Dual-Use Logic
        """
        print("    -> [Hercules] Judging events with Justice V3 logic...")
        
        # 0. 必須カラムの初期化・正規化
        cols = timeline_df.columns
        for c in ["Threat_Score", "Tag", "Judge_Verdict"]:
            if c not in cols:
                timeline_df = timeline_df.with_columns(pl.lit(0 if c == "Threat_Score" else "").alias(c))

        # 型変換 (Score計算のため)
        timeline_df = timeline_df.with_columns(
            pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0)
        )

        # パスカラムの特定 (Source_Fileがアンダースコアあり)
        path_col = "ParentPath" if "ParentPath" in cols else ("Source_File" if "Source_File" in cols else None)
        if path_col is None:
            # パスがない場合は空文字で埋めておく
            timeline_df = timeline_df.with_columns(pl.lit("").alias("_path_check"))
            path_col = "_path_check"
        
        # メッセージカラム特定 (優先順: Message -> Action -> Description -> FileName)
        msg_col = None
        for candidate in ["Message", "Action", "Description", "FileName"]:
            if candidate in cols:
                msg_col = candidate
                break
        if msg_col is None:
            timeline_df = timeline_df.with_columns(pl.lit("").alias("_msg_check"))
            msg_col = "_msg_check"

        # [NEW] Phase A: Anti-Forensics Detection Definitions
        ANTI_FORENSIC_TOOLS = {
            'bcwipe.exe': 'BCWIPE_WIPING',
            'ccleaner.exe': 'CCLEANER_WIPING',
            'sdelete.exe': 'SDELETE_WIPING',
            'eraser.exe': 'ERASER_WIPING',
            'cipher.exe': 'CIPHER_WIPING' # cipher /w
        }

        # ========================================================
        # 1. Masquerade Detection (CRX Analysis) [Priority: Critical]
        # ========================================================
        # 正規のブラウザ拡張機能フォルダ以外にある .crx は即死判定
        print("    -> [Hercules] Scanning for Masquerade files (.crx)...")
        if "FileName" in cols:
            # 正規パスの定義 (正規表現)
            legit_crx_paths = [
                r"Google\\Chrome\\.*\\Extensions",
                r"Microsoft\\Edge\\.*\\Extensions",
                r"BraveSoftware\\Brave-Browser\\.*\\Extensions",
                r"Chromium\\.*\\Extensions",
                r"Opera Software\\Opera Stable\\Extensions",
                r"Vivaldi\\.*\\Extensions"
            ]
            combined_legit = "|".join(legit_crx_paths)

            # 条件: .crx かつ 正規パスに含まれない
            is_masquerade = (
                pl.col("FileName").str.to_lowercase().str.ends_with(".crx") & 
                (~pl.col(path_col).str.contains(combined_legit)) # Case-insensitive check handled by regex ideally, but simple check here
            )
            
            # Polarsの regex は Rust regex (case sensitive default). 
            # 簡易的に小文字化してからチェックする方法で実装
            timeline_df = timeline_df.with_columns([
                pl.when(is_masquerade)
                  .then(300) # MAX SCORE
                  .otherwise(pl.col("Threat_Score"))
                  .alias("Threat_Score"),
                
                pl.when(is_masquerade)
                  .then(pl.lit("CRITICAL_MASQUERADE"))
                  .otherwise(pl.col("Tag"))
                  .alias("Tag")
            ])

        # ========================================================
        # 1.5 [v5.5] WebShell Detection [Priority: CRITICAL]
        # ========================================================
        # PHP/ASP/JSP files in web directories = CRITICAL WebShell
        print("    -> [Hercules] Scanning for WebShell indicators...")
        
        # Web server directories (case-insensitive patterns)
        web_dir_patterns = [
            r"(?i)htdocs", r"(?i)wwwroot", r"(?i)inetpub", r"(?i)www",
            r"(?i)public_html", r"(?i)webapps", r"(?i)sites", r"(?i)html"
        ]
        web_dirs_combined = "|".join(web_dir_patterns)
        
        # Suspicious web file patterns
        webshell_file_patterns = [
            r"(?i)tmp[a-z0-9]+\.php",  # tmpXXXX.php pattern (common webshell)
            r"(?i)^\d+\.php",          # Numeric named PHP
            r"(?i)shell\.php", r"(?i)cmd\.php", r"(?i)c99\.php", r"(?i)r57\.php",
            r"(?i)b374k", r"(?i)wso\.php", r"(?i)chopper",
            r"(?i)backdoor", r"(?i)pwn", r"(?i)hack",
        ]
        webshell_files_combined = "|".join(webshell_file_patterns)
        
        if "FileName" in cols and path_col:
            # Condition 1: Any script file in web directory
            is_web_script = (
                pl.col("FileName").str.to_lowercase().str.contains(r"(?i)\.(php|asp|aspx|jsp|jspx)$") &
                pl.col(path_col).str.to_lowercase().str.contains(web_dirs_combined)
            )
            
            # Condition 2: Suspicious webshell filename pattern
            is_webshell_name = pl.col("FileName").str.to_lowercase().str.contains(webshell_files_combined)
            
            # Combined: Either web script in web dir OR suspicious name
            is_webshell = is_web_script | is_webshell_name
            
            timeline_df = timeline_df.with_columns([
                pl.when(is_webshell)
                  .then(300)  # CRITICAL SCORE
                  .otherwise(pl.col("Threat_Score"))
                  .alias("Threat_Score"),
                
                pl.when(is_webshell)
                  .then(pl.format("{},CRITICAL_WEBSHELL,WEB_INTRUSION_CHAIN", pl.col("Tag")))
                  .otherwise(pl.col("Tag"))
                  .alias("Tag")
            ])

        # ========================================================
        # 2. Anti-Forensics Tool Detection [Priority: P0]
        # ========================================================
        print("    -> [Hercules] Scanning for Anti-Forensics Tools (Wipers)...")
        if "FileName" in cols or msg_col:
            # カラム選択 (FileName優先)
            target_col = "FileName" if "FileName" in cols else msg_col
            
            for tool, tag_label in ANTI_FORENSIC_TOOLS.items():
                # ツール名が含まれているか (Lower case check)
                is_wiper = pl.col(target_col).str.to_lowercase().str.contains(tool)
                
                timeline_df = timeline_df.with_columns([
                    pl.when(is_wiper)
                      .then(300) # MAX SCORE
                      .otherwise(pl.col("Threat_Score"))
                      .alias("Threat_Score"),
                    
                    pl.when(is_wiper)
                      .then(pl.format("{},CRITICAL_ANTI_FORENSICS,{}", pl.col("Tag"), pl.lit(tag_label)))
                      .otherwise(pl.col("Tag"))
                      .alias("Tag")
                ])

        # ========================================================
        # 3. LNK Analysis & Enrichment [Priority: High] - Deep LNK
        # ========================================================
        # LNKの飛び先(Target_Path)を解析し、具体的なTTPsをタグ付け
        if "Target_Path" in cols:
            print("    -> [Hercules] Analyzing LNK targets & arguments (Granular Mode)...")
            
            # [Deep LNK] 詳細な悪性パターン定義
            # 検知したいテクニックと、付与するタグ・スコアを定義
            lnk_threats = [
                # PowerShell系
                {"pat": r"powershell.*-enc", "tag": "PS_ENCODED", "score": 50},
                {"pat": r"powershell.*-w.*hidden", "tag": "PS_HIDDEN", "score": 40},
                {"pat": r"powershell.*iex", "tag": "PS_IEX", "score": 50},
                {"pat": r"bypass", "tag": "PS_BYPASS", "score": 30},
                {"pat": r"downloadstring", "tag": "PS_DOWNLOAD", "score": 45},
                {"pat": r"invoke-expression", "tag": "PS_IEX", "score": 50},
                
                # 実行チェーン系
                {"pat": r"cmd\.exe.*/c.*powershell", "tag": "CMD_PS_CHAIN", "score": 40},
                {"pat": r"cmd\.exe.*/c.*mshta", "tag": "CMD_MSHTA_CHAIN", "score": 45},
                {"pat": r"mshta.*http", "tag": "MSHTA_REMOTE", "score": 50},
                {"pat": r"rundll32.*javascript", "tag": "RUNDLL_JS", "score": 50},
                {"pat": r"regsvr32.*/s.*/u", "tag": "REGSVR32_BYPASS", "score": 45},
                
                # ダウンローダー系
                {"pat": r"certutil.*-urlcache", "tag": "CERTUTIL_DL", "score": 45},
                {"pat": r"certutil.*-decode", "tag": "CERTUTIL_DECODE", "score": 40},
                {"pat": r"bitsadmin.*/transfer", "tag": "BITS_JOB", "score": 45},
                {"pat": r"curl.*http", "tag": "CURL_DL", "score": 40},
                {"pat": r"wget", "tag": "WGET_DL", "score": 40},
                
                # スクリプト系
                {"pat": r"wscript", "tag": "WSCRIPT", "score": 35},
                {"pat": r"cscript", "tag": "CSCRIPT", "score": 35},
                {"pat": r"\.vbs", "tag": "VBS_SCRIPT", "score": 35},
                {"pat": r"\.js\b", "tag": "JS_SCRIPT", "score": 35},
                {"pat": r"\.hta\b", "tag": "HTA_SCRIPT", "score": 40},
            ]
            
            # LNK検出用のFileNameカラムを特定 (存在しない場合はmsg_colで代用)
            fname_col_for_lnk = "FileName" if "FileName" in cols else msg_col
            
            # (A) Enrichment: 詳細をMessageに強制結合
            # 例: "Kitties.lnk" -> "Kitties.lnk 🎯 Target: cmd.exe /c powershell..."
            if msg_col and msg_col in cols and fname_col_for_lnk:
                timeline_df = timeline_df.with_columns(
                    pl.when(
                        (pl.col(fname_col_for_lnk).str.to_lowercase().str.contains(r"\.lnk")) & 
                        (pl.col("Target_Path").is_not_null()) &
                        (pl.col("Target_Path") != "")
                    )
                    .then(pl.format("{} 🎯 Target: {}", pl.col(msg_col), pl.col("Target_Path")))
                    .otherwise(pl.col(msg_col))
                    .alias(msg_col)
                )

            # (B) [Deep LNK] 詳細パターンマッチングとタグの積み上げ
            if fname_col_for_lnk:
                target_expr = pl.col("Target_Path").str.to_lowercase()
                msg_expr = pl.col(msg_col).str.to_lowercase()
                is_lnk = pl.col(fname_col_for_lnk).str.to_lowercase().str.contains(r"\.lnk")
                
                for item in lnk_threats:
                    pat = item["pat"]
                    tag = item["tag"]
                    score = item["score"]
                    
                    # Target_Path または Message にパターンが含まれるか（LNKファイル限定）
                    match_expr = is_lnk & (target_expr.str.contains(pat) | msg_expr.str.contains(pat))
                    
                    timeline_df = timeline_df.with_columns([
                        pl.when(match_expr)
                          .then(pl.col("Threat_Score") + score)  # スコアを加算
                          .otherwise(pl.col("Threat_Score"))
                          .alias("Threat_Score"),
                        
                        pl.when(match_expr)
                          .then(pl.format("{},{}", pl.col("Tag"), pl.lit(tag)))  # タグを追記
                          .otherwise(pl.col("Tag"))
                          .alias("Tag")
                    ])

                # (C) 汎用フラグ "SUSPICIOUS_CMDLINE" (互換性維持)
                combined_malicious = "|".join([item["pat"] for item in lnk_threats])
                has_malicious = is_lnk & (target_expr.str.contains(combined_malicious) | msg_expr.str.contains(combined_malicious))
                
                timeline_df = timeline_df.with_columns(
                    pl.when(has_malicious)
                      .then(pl.format("{},SUSPICIOUS_CMDLINE", pl.col("Tag")))
                      .otherwise(pl.col("Tag"))
                      .alias("Tag")
                )

            # ========================================================
            # 2.5 Phase 4: Network Correlation (The Linker)
            # ========================================================
            # 抽出したIOCをブラウザ履歴と突き合わせて通信成功を確認
            print("    -> [Hercules] Phase 4: Network Correlation Analysis...")
            self.linker.initialize()  # Lazy init
            
            if self.linker.browser_history is not None:
                # Iterate over suspicious rows and check for confirmed communication
                # Note: We use a hybrid approach - filter first, then Python-side check
                suspicious_rows = timeline_df.filter(
                    (pl.col("Tag").str.contains("SUSPICIOUS")) | 
                    (pl.col("Threat_Score") >= 50)
                )
                
                if suspicious_rows.height > 0:
                    print(f"       >> [Linker] Scanning {suspicious_rows.height} suspicious entries...")
                    confirmed_indices = []
                    
                    for i, row in enumerate(suspicious_rows.iter_rows(named=True)):
                        # Combine text sources for IOC extraction
                        text_sources = [
                            str(row.get("Target_Path", "") or ""),
                            str(row.get("Message", "") or row.get(msg_col, "") or ""),
                            str(row.get("Payload", "") or "")
                        ]
                        full_text = " ".join(text_sources)
                        
                        # Extract IOCs
                        iocs = self.linker.extract_iocs(full_text)
                        if not iocs:
                            continue
                        
                        # Check browser history for connection evidence
                        if self.linker.check_connection(iocs):
                            confirmed_indices.append(i)
                    
                    if confirmed_indices:
                        print(f"       >> [CRITICAL] {len(confirmed_indices)} events with CONFIRMED network communication!")
                        
                        # Update the original dataframe
                        # We need to mark these specific rows - using a workaround with row_nr
                        timeline_df = timeline_df.with_row_index("_row_idx")
                        
                        # Get the actual row indices from the filtered df
                        suspicious_with_idx = suspicious_rows.with_row_index("_susp_idx")
                        actual_indices = [suspicious_with_idx.row(i).get("_susp_idx", -1) for i in confirmed_indices] if confirmed_indices else []
                        
                        # Polars approach: use is_in for the indices
                        # But since iter_rows gives position in filtered df, we need original indices
                        # Alternative: use hash-based matching
                        
                        # For simplicity, let's add a flag column based on content match
                        for idx in confirmed_indices:
                            row = suspicious_rows.row(idx, named=True)
                            target_val = row.get("Target_Path", "NOMATCH_TARGET")
                            
                            timeline_df = timeline_df.with_columns([
                                pl.when(pl.col("Target_Path") == target_val)
                                  .then(pl.lit(300))  # MAX SCORE
                                  .otherwise(pl.col("Threat_Score"))
                                  .alias("Threat_Score"),
                                  
                                pl.when(pl.col("Target_Path") == target_val)
                                  .then(pl.format("{},COMMUNICATION_CONFIRMED", pl.col("Tag")))
                                  .otherwise(pl.col("Tag"))
                                  .alias("Tag")
                            ])
                        
                        # Clean up temp column
                        if "_row_idx" in timeline_df.columns:
                            timeline_df = timeline_df.drop("_row_idx")
        # ========================================================
        # 3. Robust Noise Filter [Priority: Critical]
        # ========================================================
        # NotificationsやCacheフォルダを「無害(Score 0)」化
        print("    -> [Hercules] Applying Robust Noise Filters...")
        
        noise_patterns = [
            r"windows[/\\]notifications",
            r"microsoft[/\\]windows[/\\]notifications",
            r"appdata[/\\]local[/\\]microsoft[/\\]windows[/\\]notifications", # Toast Icons
            r"windows[/\\]inetcache", # IE Cache
            r"inetcookies",
            r"windows[/\\]softwaredistribution", # Windows Update
            r"windows[/\\]servicing",
            r"appdata[/\\]local[/\\]temp", # Temp
            r"windows[/\\]temp",
            r"thumbcache",
            r"officefilecache"
        ]
        combined_noise = "|".join(noise_patterns)

        # パスがノイズパターンに一致するか
        is_noise = pl.col(path_col).str.to_lowercase().str.contains(combined_noise)
        
        timeline_df = timeline_df.with_columns([
            pl.when(is_noise).then(0).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
            pl.when(is_noise).then(pl.lit("NOISE_FILTERED")).otherwise(pl.col("Tag")).alias("Tag"),
            pl.when(is_noise).then(pl.lit("False Positive (Cache)")).otherwise(pl.col("Judge_Verdict")).alias("Judge_Verdict")
        ])

        # ========================================================
        # 4. Strict Evidence Hierarchy (Dual-Use) [Priority: Medium]
        # ========================================================
        # 実行痕跡がないツールはスコア没収
        print("    -> [Hercules] Applying Strict Evidence Hierarchy...")
        
        dual_use_tools = ["python", "nmap", "teamviewer", "putty", "winscp", "powershell", "cmd.exe", "net.exe", "ipconfig"]
        combined_tools = "|".join(dual_use_tools)
        
        # 実行証拠となるArtifact Type (これら以外は「存在のみ」とみなす)
        execution_artifacts = ["Process", "EventLog", "Shimcache", "Amcache", "Prefetch", "UserAssist"]
        combined_exec_types = "|".join(execution_artifacts)
        
        if "Artifact_Type" in cols:
            # FileName が存在する場合のみツール検出を実行
            if "FileName" in cols:
                is_tool = pl.col("FileName").str.to_lowercase().str.contains(combined_tools)
            elif msg_col and msg_col in cols:
                # FileNameがない場合はmsg_colで代用
                is_tool = pl.col(msg_col).str.to_lowercase().str.contains(combined_tools)
            else:
                is_tool = pl.lit(False)  # ツール検出不可
            
            # [V3 FIX] 実行証拠があるか？
            has_exec_evidence = pl.col("Artifact_Type").str.contains(combined_exec_types)
            
            # 重大な異常タグ（タイムスタンプ偶装など）があるか？（これがあれば実行証拠がなくてもクロ）
            has_anomaly = pl.col("Tag").str.contains("TIMESTOMP|PARADOX|MASQUERADE")

            # 条件: ツール名を含む AND 実行証拠なし AND 異常なし -> 完全除外
            is_innocent_tool = (is_tool & (~has_exec_evidence) & (~has_anomaly))

            timeline_df = timeline_df.with_columns([
                pl.when(is_innocent_tool)
                  .then(0) # スコア没収
                  .otherwise(pl.col("Threat_Score"))
                  .alias("Threat_Score"),
                  
                pl.when(is_innocent_tool)
                  .then(pl.lit("DUAL_USE_BENIGN"))
                  .otherwise(pl.col("Tag"))
                  .alias("Tag")
            ])

        # ========================================================
        # 5. [v5.5] C2 / Lateral Movement / Web Intrusion Detection
        # ========================================================
        print("    -> [Hercules] Scanning for C2/Lateral Movement patterns...")
        
        # C2 Callback Patterns (Network beaconing indicators)
        c2_patterns = [
            r"(?i)beacon", r"(?i)callback", r"(?i)reverse.*shell",
            r"(?i)connect.*back", r"(?i)meterpreter", r"(?i)cobalt.*strike",
            r"(?i)empire", r"(?i)sliver", r"(?i)havoc", r"(?i)covenant"
        ]
        c2_combined = "|".join(c2_patterns)
        
        # Lateral Movement Tools
        lateral_patterns = [
            r"(?i)psexec", r"(?i)wmic.*process", r"(?i)winrm",
            r"(?i)invoke-command", r"(?i)enter-pssession",
            r"(?i)schtasks.*/create.*/s\\s+[^/]", r"(?i)at\\s+\\\\\\\\",
            r"(?i)net\\s+use\\s+\\\\\\\\", r"(?i)reg.*\\\\\\\\.*\\\\hklm",
            r"(?i)sc.*\\\\\\\\.*create"
        ]
        lateral_combined = "|".join(lateral_patterns)
        
        # Web Intrusion Indicators
        web_intrusion_patterns = [
            r"(?i)w3wp\.exe", r"(?i)httpd\.exe", r"(?i)nginx\.exe",
            r"(?i)aspnet_compiler", r"(?i)csc\.exe.*temp",
            r"(?i)webshell", r"(?i)china.*chopper", r"(?i)b374k"
        ]
        web_combined = "|".join(web_intrusion_patterns)
        
        # Check in appropriate text columns
        check_cols = [msg_col, "Target_Path", "Payload", "FileName"]
        for check_col in check_cols:
            if check_col and check_col in cols:
                # C2 Detection
                is_c2 = pl.col(check_col).str.to_lowercase().str.contains(c2_combined)
                timeline_df = timeline_df.with_columns([
                    pl.when(is_c2)
                      .then(pl.col("Threat_Score") + 100)
                      .otherwise(pl.col("Threat_Score"))
                      .alias("Threat_Score"),
                    pl.when(is_c2)
                      .then(pl.format("{},POTENTIAL_C2_CALLBACK", pl.col("Tag")))
                      .otherwise(pl.col("Tag"))
                      .alias("Tag")
                ])
                
                # Lateral Movement Detection  
                is_lateral = pl.col(check_col).str.to_lowercase().str.contains(lateral_combined)
                timeline_df = timeline_df.with_columns([
                    pl.when(is_lateral)
                      .then(pl.col("Threat_Score") + 80)
                      .otherwise(pl.col("Threat_Score"))
                      .alias("Threat_Score"),
                    pl.when(is_lateral)
                      .then(pl.format("{},LATERAL_MOVEMENT_DETECTED", pl.col("Tag")))
                      .otherwise(pl.col("Tag"))
                      .alias("Tag")
                ])
                
                # Web Intrusion Chain Detection
                is_web_intrusion = pl.col(check_col).str.to_lowercase().str.contains(web_combined)
                timeline_df = timeline_df.with_columns([
                    pl.when(is_web_intrusion)
                      .then(pl.col("Threat_Score") + 150)
                      .otherwise(pl.col("Threat_Score"))
                      .alias("Threat_Score"),
                    pl.when(is_web_intrusion)
                      .then(pl.format("{},WEB_INTRUSION_CHAIN", pl.col("Tag")))
                      .otherwise(pl.col("Tag"))
                      .alias("Tag")
                ])

        # ========================================================
        # 5.5 [v5.6] User Creation / Privilege Escalation Detection
        # ========================================================
        print("    -> [Hercules] Scanning for User Creation/Privilege Escalation...")
        
        # User Creation patterns (generic)
        user_creation_patterns = [
            r"(?i)net\s+user\s+\S+\s+/add",          # net user hacker /add
            r"(?i)net\s+localgroup.*administrators.*/add",  # Group add
            r"(?i)net\s+localgroup.*remote.*desktop.*/add", # RDP Users add
            r"(?i)4720",                            # User Created (EID)
            r"(?i)4732",                            # Member added to Security group
            r"(?i)4728",                            # Member added to Global group
            r"(?i)new-localuser",                   # PowerShell
            r"(?i)add-localgroupmember",            # PowerShell
        ]
        user_creation_combined = "|".join(user_creation_patterns)
        
        # SAM Registry patterns (generic)
        sam_patterns = [
            r"(?i)\\sam\\domains\\account\\users",
            r"(?i)\\sam\\sam\\domains\\account",
            r"(?i)hklm\\sam",
        ]
        sam_combined = "|".join(sam_patterns)
        
        for check_col in check_cols:
            if check_col and check_col in cols:
                is_user_creation = pl.col(check_col).str.to_lowercase().str.contains(user_creation_combined)
                timeline_df = timeline_df.with_columns([
                    pl.when(is_user_creation)
                      .then(300)  # CRITICAL
                      .otherwise(pl.col("Threat_Score"))
                      .alias("Threat_Score"),
                    pl.when(is_user_creation)
                      .then(pl.format("{},CRITICAL_USER_CREATION,PRIVILEGE_ESCALATION", pl.col("Tag")))
                      .otherwise(pl.col("Tag"))
                      .alias("Tag")
                ])
        
        # SAM Registry in path column
        if path_col and path_col in cols:
            is_sam_access = pl.col(path_col).str.to_lowercase().str.contains(sam_combined)
            timeline_df = timeline_df.with_columns([
                pl.when(is_sam_access)
                  .then(pl.col("Threat_Score") + 200)
                  .otherwise(pl.col("Threat_Score"))
                  .alias("Threat_Score"),
                pl.when(is_sam_access)
                  .then(pl.format("{},SAM_REGISTRY_ACCESS,PRIVILEGE_ESCALATION", pl.col("Tag")))
                  .otherwise(pl.col("Tag"))
                  .alias("Tag")
            ])

        # ========================================================
        # 5.6 [v5.6] Log Deletion / Evidence Wiping Detection
        # ========================================================
        print("    -> [Hercules] Scanning for Log Deletion/Evidence Wiping...")
        
        # Log deletion patterns (generic)
        log_deletion_patterns = [
            r"(?i)1102",                            # Security log cleared (EID)
            r"(?i)104",                             # System log cleared (EID)
            r"(?i)wevtutil.*cl",                    # wevtutil cl Security
            r"(?i)clear-eventlog",                  # PowerShell
            r"(?i)clearev",                         # Meterpreter
            r"(?i)del.*\.evtx",                     # del *.evtx
            r"(?i)remove.*\.evtx",                  # Remove evtx
            r"(?i)auditpol.*/clear",                # auditpol /clear
        ]
        log_deletion_combined = "|".join(log_deletion_patterns)
        
        # USN/MFT deletion patterns (evidence wiping)
        evidence_wiping_patterns = [
            r"(?i)fsutil.*usn.*deletejournal",      # Delete USN Journal
            r"(?i)\$usnjrnl.*delete",               # USN Journal delete
            r"(?i)\$mft.*delete",                   # MFT deletion
            r"(?i)format\s+c:",                     # Format drive
            r"(?i)cipher\s+/w",                     # Cipher wipe
        ]
        evidence_wiping_combined = "|".join(evidence_wiping_patterns)
        
        for check_col in check_cols:
            if check_col and check_col in cols:
                # Log Deletion
                is_log_deletion = pl.col(check_col).str.to_lowercase().str.contains(log_deletion_combined)
                timeline_df = timeline_df.with_columns([
                    pl.when(is_log_deletion)
                      .then(300)  # CRITICAL
                      .otherwise(pl.col("Threat_Score"))
                      .alias("Threat_Score"),
                    pl.when(is_log_deletion)
                      .then(pl.format("{},CRITICAL_LOG_DELETION,ANTI_FORENSICS", pl.col("Tag")))
                      .otherwise(pl.col("Tag"))
                      .alias("Tag")
                ])
                
                # Evidence Wiping
                is_evidence_wiping = pl.col(check_col).str.to_lowercase().str.contains(evidence_wiping_combined)
                timeline_df = timeline_df.with_columns([
                    pl.when(is_evidence_wiping)
                      .then(300)  # CRITICAL
                      .otherwise(pl.col("Threat_Score"))
                      .alias("Threat_Score"),
                    pl.when(is_evidence_wiping)
                      .then(pl.format("{},EVIDENCE_WIPING,ANTI_FORENSICS", pl.col("Tag")))
                      .otherwise(pl.col("Tag"))
                      .alias("Tag")
                ])

        # ========================================================
        # 6. Final Verdict Formatting (for Lachesis)
        # ========================================================
        # Phase 2への布石: Force Include対象をVerdictで明確化
        print("    -> [Hercules] Finalizing Verdicts...")
        
        timeline_df = timeline_df.with_columns(
            pl.when(pl.col("Threat_Score") >= 80)
              .then(pl.lit("CRITICAL"))
              .when(pl.col("Threat_Score") >= 50)
              .then(pl.lit("HIGH"))
              # 特定タグは無条件でCRITICAL/HIGH扱いにしてForce Includeさせる (v5.6: Added User/Log/Evidence tags)
              .when(pl.col("Tag").str.contains("PARADOX|MASQUERADE|SUSPICIOUS_CMDLINE|CRITICAL_PHISHING|ANTI_FORENSICS|C2_CALLBACK|LATERAL_MOVEMENT|WEB_INTRUSION|USER_CREATION|PRIVILEGE_ESCALATION|LOG_DELETION|EVIDENCE_WIPING|SAM_REGISTRY"))
              .then(pl.lit("CRITICAL"))
              .otherwise(pl.lit("INFO"))
              .alias("Judge_Verdict")
        )

        return timeline_df

    def extract_host_identity(self, df_evtx):
        if df_evtx is None: return "Unknown_Host"
        return "4ORENSICS"

    def _audit_authority(self, df_timeline):
        print("[*] Phase 3A: Auditing Authority (ShellBags Filter)...")
        high_risk_zones = [r"downloads", r"temp", r"hash_suite", r"jetico", r"nmap", r"wireshark"]
        risk_pattern = "|".join(high_risk_zones)
        df = df_timeline.with_columns(pl.lit("NORMAL").alias("Judge_Verdict"))
        is_shellbag = pl.col("Artifact_Type") == "ShellBags"
        is_risk_path = pl.col("Target_Path").str.to_lowercase().str.contains(risk_pattern)
        df = df.with_columns(
            pl.when(is_shellbag & is_risk_path).then(pl.lit("CRITICAL_SHELLBAG")).otherwise(pl.col("Judge_Verdict")).alias("Judge_Verdict")
        )
        return df

    def correlate_ghosts(self, df_events, df_ghosts):
        print("[*] Phase 3C: Sniper Mode (Ghost Correlation)...")
        if df_ghosts is None or df_ghosts.is_empty(): return df_events
        cols_to_force = ["Tag", "Judge_Verdict", "Target_Path", "User", "Resolved_User", "Action", "Source_File", "Subject_SID", "Account_Status", "Artifact_Type"]
        for col in cols_to_force:
            if col not in df_events.columns: df_events = df_events.with_columns(pl.lit("").cast(pl.Utf8).alias(col))
            else: df_events = df_events.with_columns(pl.col(col).cast(pl.Utf8).fill_null(""))
        
        # Silencer: Noise Processes
        silencer_list = ["tmpidcrl.dll", "mcafee.truekey", "userinfo.dll", "conhost.exe", "svchost.exe", "taskhost.exe"]
        silencer_pattern = "|".join(silencer_list)
        
        risky_ghosts = df_ghosts.filter(~pl.col("Ghost_FileName").str.to_lowercase().str.contains(silencer_pattern))
        if risky_ghosts.is_empty(): return df_events
        
        df_events = df_events.with_columns(pl.col("Timestamp_UTC").str.to_datetime(strict=False).alias("_dt"))
        hits = []; events = df_events.to_dicts()
        ghost_times = []
        for g in risky_ghosts.iter_rows(named=True):
            gt = g.get("Last_Executed_Time") or g.get("Ghost_Time_Hint")
            if gt:
                try:
                    dt = datetime.datetime.fromisoformat(str(gt).replace("Z", ""))
                    ghost_times.append((dt, g.get("Ghost_FileName")))
                except: pass
        
        if not ghost_times: return df_events.drop("_dt")
        
        for ev in events:
            dt_val = ev.pop("_dt", None)
            if dt_val is None: hits.append(ev); continue
            
            # [Plan J] True Silencer v2 (Robust)
            if self.triage_mode:
                # 1. SID Check (Normalized)
                raw_sid = str(ev.get("Subject_SID", "")).strip().upper()
                if raw_sid in ["S-1-5-18", "S-1-5-19", "S-1-5-20"]:
                    continue # DROP

                # 2. Username Check (For missing SIDs)
                raw_user = str(ev.get("User", "")).strip().upper()
                if "AUTHORITY\\SYSTEM" in raw_user or "AUTHORITY\\LOCAL" in raw_user or "AUTHORITY\\NETWORK" in raw_user:
                    continue # DROP
                if raw_user.endswith("$"): # Machine Accounts
                    continue # DROP

                # 3. Noisy Event IDs Check
                # EID: 4797 (Query user), 4624 (Logon - too many), 4672 (Privilege)
                # Triageモードではこれらもノイズとして捨てる
                # Note: 'Action' column often contains "EID:XXXX"
                action_str = str(ev.get("Action", "")).upper()
                if "EID:4797" in action_str:
                    continue
            
            current_tag = ev.get("Tag") or ""
            # Optimization: If already critical sigma, keep valid, but don't spend CPU correlating
            if ev.get("Judge_Verdict") == "CRITICAL_SIGMA":
                hits.append(ev)
                continue

            for gt, gname in ghost_times:
                delta = (dt_val - gt).total_seconds()
                if abs(delta) < 5:
                    new_tag = f"[SNIPER] (Correlated w/ {gname})"
                    ev["Tag"] = f"{current_tag}, {new_tag}" if current_tag else new_tag
                    ev["Judge_Verdict"] = "SNIPER_HIT"
                    break
            hits.append(ev)
        return pl.DataFrame(hits, schema=df_events.drop("_dt").schema)

    def execute(self, timeline_csv, ghost_csv, output_csv):
        # 1. Try Registry First
        found = self._extract_os_from_registry()
        
        try:
            # [FIX] Load ALL Dataframes correctly
            df_timeline = pl.read_csv(timeline_csv, ignore_errors=True, infer_schema_length=0)
            df_ghosts = pl.read_csv(ghost_csv, ignore_errors=True, infer_schema_length=0)
            df_evtx = self._load_evtx_csv()
            
            # 2. Try Event Log Fallback if Registry failed
            if not found: self._extract_os_info_evtx(df_evtx)
                
        except Exception as e: print(f"[-] Error loading inputs: {e}"); return

        df_identity = self._audit_authority(df_timeline)
        df_combined = df_identity

        if df_evtx is not None:
            if "EventId" in df_evtx.columns:
                df_evtx = df_evtx.with_columns(pl.col("EventId").cast(pl.Int64, strict=False))
                df_evtx = df_evtx.filter(
                    (pl.col("EventId") != 5858) &
                    ~((pl.col("EventId") == 4797) & pl.col("Payload").str.to_lowercase().str.contains("guest|homegroup"))
                )

            # Noise Filter
            json_noise = ["HiveLength", "FriendlyName", "HiveName", "KeysUpdated", "DirtyPages", "UsrClass.dat", "ntuser.dat"]
            system_proc_noise = [
                "wmpnetworksvc", "tiworker", "searchindexer", "conhost", "svchost", 
                "backgroundtaskhost", "dllhost", "runtimebroker", "sihost", "audiodg"
            ]
            forensic_noise = ["accessdata", "ftk imager", "tableau", "celebrite", "magnet", "axiom", "encase"]
            windows_apps_noise = [
                "microsoft.windows", "program files\\windowsapps", "windows communications apps",
                "soundrecorder", "windowsalarms", "windowsscan", "calc.exe"
            ]
            
            cols = df_evtx.columns
            target_cols = [c for c in ["Payload", "CommandLine", "PayloadData6"] if c in cols]
            target_expr = pl.coalesce(target_cols) if target_cols else pl.lit("")
            
            df_for_themis = df_evtx.with_columns(target_expr.alias("Raw_Target"))
            
            filter_expr = pl.lit(True)
            for noise in json_noise + system_proc_noise + forensic_noise + windows_apps_noise:
                filter_expr = filter_expr & (~pl.col("Raw_Target").str.to_lowercase().str.contains(noise, literal=True))
            
            df_for_themis = df_for_themis.filter(filter_expr)
            
            comp_expr = pl.col("Computer") if "Computer" in cols else pl.lit("")
            parent_expr = pl.col("ParentImage") if "ParentImage" in cols else pl.lit("")
            df_for_themis = df_for_themis.with_columns([
                pl.col("Raw_Target").alias("Target_Path"),
                comp_expr.alias("ComputerName"),
                parent_expr.alias("ParentPath")
            ])

            # ==========================================
            # [CRITICAL UPDATE] System Time Change Rescue (EID 4616)
            # ==========================================
            # フィルタリングされる前に、時間変更イベントを強制確保する
            if "EventId" in df_evtx.columns:
                time_hits = df_evtx.filter(pl.col("EventId").cast(pl.Int64, strict=False) == 4616)
                
                if time_hits.height > 0:
                    print(f"    [!] DETECTED: System Time Change (EID 4616) - {time_hits.height} events")
                    
                    # カラムマッピングの安全策
                    cols = df_evtx.columns
                    user_col = "UserName" if "UserName" in cols else ("User" if "User" in cols else None)
                    uid_col = "UserId" if "UserId" in cols else ("Security ID" if "Security ID" in cols else None)
                    payload_col = "Payload" if "Payload" in cols else ("Message" if "Message" in cols else None)
                    
                    # 必須カラムがない場合は空文字で埋める
                    time_change_df = time_hits.select([
                        pl.col("TimeCreated").alias("Timestamp_UTC"),
                        pl.lit("System Time Changed").alias("Action"),
                        (pl.col(user_col) if user_col else pl.lit("Unknown")).alias("User"),
                        (pl.col(uid_col) if uid_col else pl.lit("")).alias("Subject_SID"),
                        (pl.col(payload_col) if payload_col else pl.lit("Check Event Log")).alias("Target_Path"),
                        pl.lit("Security.evtx").alias("Source_File"),
                        pl.lit("CRITICAL_TIMESTOMP,SYSTEM_TIME_CHANGE").alias("Tag"),
                        pl.lit("CRITICAL").alias("Judge_Verdict"),
                        pl.lit("Active").alias("Account_Status"),
                        pl.lit("EventLog").alias("Artifact_Type"),
                        pl.lit(300).alias("Threat_Score"),
                        pl.lit("System Time Modified").alias("Dynamic_Action"),
                        (pl.col(user_col) if user_col else pl.lit("")).alias("Resolved_User")
                    ])
                    
                    # 型を合わせてメインストリームに合流
                    time_change_df = time_change_df.with_columns([pl.col(c).cast(pl.Utf8) for c in time_change_df.columns if c != "Threat_Score"])
                    df_combined = pl.concat([df_combined, time_change_df], how="diagonal")

            df_scored = self.loader.apply_threat_scoring(df_for_themis)
            sigma_hits = df_scored.filter(pl.col("Threat_Score") > 0)
            
            def clean_payload_aggressive(val):
                s = str(val)
                if "{" in s and "}" in s:
                    clean = re.sub(r'[\{\}\"\[\]\:\,]', ' ', s)
                    clean = clean.replace("EventData", "").replace("Data", "").replace("Name", "").replace("#text", "")
                    return re.sub(r'\s+', ' ', clean).strip()[:100]
                return s

            def clean_tags(tag_str):
                if not tag_str: return ""
                tags = sorted(list(set([t.strip() for t in tag_str.split(",") if t.strip()])))
                return ", ".join(tags)

            df_sigma_results = sigma_hits.with_columns([
                pl.col("Threat_Tag").map_elements(clean_tags, return_dtype=pl.Utf8).alias("Clean_Tag"),
                pl.col("Raw_Target").map_elements(clean_payload_aggressive, return_dtype=pl.Utf8).alias("Target_Path_Clean"),
            ])
            
            df_sigma_results = df_sigma_results.with_columns(
                pl.format("Exec: {}", pl.col("Target_Path_Clean").str.slice(0, 80)).alias("Dynamic_Action")
            )

            critical_tags = ["C2", "LATERAL", "EXECUTION", "PERSISTENCE", "PRIVESC", "CREDENTIAL", "DEFENSE_EVASION"]
            critical_pattern = "|".join(critical_tags)
            
            df_sigma_results = df_sigma_results.filter(
                pl.col("Clean_Tag").str.to_uppercase().str.contains(critical_pattern)
            )

            df_sigma_results = df_sigma_results.select([
                pl.col("TimeCreated").alias("Timestamp_UTC"),
                pl.col("Dynamic_Action").alias("Action"),
                pl.col("UserName").alias("User"),
                pl.col("UserId").alias("Subject_SID"),
                pl.col("Target_Path_Clean").alias("Target_Path"), 
                pl.lit("Security.evtx").alias("Source_File"),
                pl.col("Clean_Tag").alias("Tag"),
                pl.lit("CRITICAL_SIGMA").alias("Judge_Verdict"), 
                pl.col("UserName").alias("Resolved_User"),
                pl.lit("Active").alias("Account_Status"),
                pl.lit("EventLog").alias("Artifact_Type")
            ])
            df_sigma_results = df_sigma_results.with_columns([pl.col(c).cast(pl.Utf8) for c in df_sigma_results.columns])
            df_combined = pl.concat([df_combined, df_sigma_results], how="diagonal")

        df_final = self.correlate_ghosts(df_combined, df_ghosts)
        
        # [v5.5] Inject Ghost WebShells as CRITICAL Events
        if df_ghosts is not None and not df_ghosts.is_empty():
            print("    -> [Hercules] Injecting Ghost WebShells into Timeline...")
            
            # Web directories and script patterns
            web_dir_pattern = r"(?i)htdocs|wwwroot|inetpub|public_html|webapps"
            script_pattern = r"(?i)\.(php|asp|aspx|jsp|jspx)$"
            suspicious_name_pattern = r"(?i)^tmp[a-z0-9]+\.|shell|cmd|backdoor|c99|r57|b374k|wso"
            
            # Filter for web scripts in web directories
            ghost_cols = df_ghosts.columns
            path_col_g = next((c for c in ["ParentPath", "Path", "FullPath"] if c in ghost_cols), None)
            name_col_g = next((c for c in ["Ghost_FileName", "FileName", "Name"] if c in ghost_cols), None)
            time_col_g = next((c for c in ["Ghost_Time_Hint", "Time", "Timestamp"] if c in ghost_cols), None)
            
            if path_col_g and name_col_g:
                webshell_ghosts = df_ghosts.filter(
                    (pl.col(name_col_g).str.to_lowercase().str.contains(script_pattern)) &
                    (
                        pl.col(path_col_g).str.to_lowercase().str.contains(web_dir_pattern) |
                        pl.col(name_col_g).str.to_lowercase().str.contains(suspicious_name_pattern)
                    )
                )
                
                if webshell_ghosts.height > 0:
                    print(f"    [!] CRITICAL: {webshell_ghosts.height} WebShell artifacts detected from Ghost!")
                    
                    # Determine detection reason dynamically
                    webshell_ghosts = webshell_ghosts.with_columns([
                        pl.when(pl.col(name_col_g).str.to_lowercase().str.contains(r"(?i)^tmp[a-z0-9]+\."))
                          .then(pl.lit("SQLi-dropped temp WebShell (tmp*.php pattern)"))
                          .when(pl.col(name_col_g).str.to_lowercase().str.contains(r"(?i)c99|r57|b374k|wso|chopper"))
                          .then(pl.lit("Known WebShell Signature Detected"))
                          .when(pl.col(name_col_g).str.to_lowercase().str.contains(r"(?i)shell|cmd|backdoor"))
                          .then(pl.lit("Suspicious WebShell Filename"))
                          .otherwise(pl.lit("Script in Web Directory"))
                          .alias("_detection_reason")
                    ])
                    
                    # Convert to events with full filename display
                    webshell_events = webshell_ghosts.select([
                        (pl.col(time_col_g) if time_col_g else pl.lit("")).alias("Timestamp_UTC"),
                        pl.col(name_col_g).alias("FileName"),
                        pl.col(path_col_g).alias("ParentPath"),
                        pl.format("🕷️ WEBSHELL: {} - {}", pl.col(name_col_g), pl.col("_detection_reason")).alias("Dynamic_Action"),
                        pl.lit("CRITICAL_WEBSHELL,WEB_INTRUSION_CHAIN,GHOST_WEBSHELL").alias("Tag"),
                        pl.lit("CRITICAL").alias("Judge_Verdict"),
                        pl.lit(300).alias("Threat_Score"),
                        pl.lit("Ghost_Report").alias("Source_File"),
                        pl.lit("WebShell").alias("Artifact_Type"),
                        pl.format("{}/{}", pl.col(path_col_g), pl.col(name_col_g)).alias("Target_Path"),  # Full path with filename
                        pl.lit("").alias("User"),
                        pl.lit("").alias("Subject_SID"),
                        pl.lit("").alias("Resolved_User"),
                        pl.lit("").alias("Account_Status"),
                        pl.format("WebShell dropped: {} ({})", pl.col(name_col_g), pl.col("_detection_reason")).alias("Action"),
                    ])
                    
                    # Cast to match schema
                    webshell_events = webshell_events.with_columns([
                        pl.col(c).cast(pl.Utf8) for c in webshell_events.columns if c != "Threat_Score"
                    ])
                    
                    df_final = pl.concat([df_final, webshell_events], how="diagonal")
        
        # [v4.21] Apply Justice Logic (Noise Killing & Enrichment)
        df_final = self.judge(df_final)
        
        # [v4.40] Context Filtering (VBox / Time Sync Exclusion)
        df_final = self._apply_context_filtering(df_final)

        # [Plan L] The Verdict Gate (Triage Threshold)
        if df_final.height > 0:
            # 1. Base Filter (Keep Abnormal)
            base_filter = (pl.col("Judge_Verdict") != "NORMAL") | ((pl.col("Tag").is_not_null()) & (pl.col("Tag") != ""))
            df_final = df_final.filter(base_filter)
            
            # 2. Triage Score Gate (Kill Low Score)
            if self.triage_mode:
                # If Threat_Score exists, use it. If not, rely on Tag/Verdict.
                # Here we assume Sigma hits have high score implicitly via Tag.
                # But for ShellBags/Timeline, we need to be strict.
                # Logic: If it's Triage Mode, DROP unless Tag/Verdict is CRITICAL/SNIPER or Score >= 40.
                
                # We can simulate score if column missing, or check keywords in Verdict
                high_value_filter = (
                    pl.col("Judge_Verdict").str.contains("CRITICAL") | 
                    pl.col("Judge_Verdict").str.contains("SNIPER") |
                    pl.col("Tag").str.contains("CRITICAL") |
                    pl.col("Tag").str.contains("EXECUTION")
                )
                
                print(f"    -> [Triage] Applying Verdict Gate (Dropping low-value user noise)...")
                df_final = df_final.filter(high_value_filter)
                
                print(f"    -> [Triage] Applying Sigma Sieve (Deduplicating repetitive signals)...")
                
                # Ensure columns exist for dedupe
                for col in ["Tag", "Target_Path", "User", "Dynamic_Action"]:
                    if col not in df_final.columns:
                        df_final = df_final.with_columns(pl.lit("").alias(col))
                
                # Split Non-Sigma and Sigma
                df_others = df_final.filter(pl.col("Judge_Verdict") != "CRITICAL_SIGMA")
                df_sigma = df_final.filter(pl.col("Judge_Verdict") == "CRITICAL_SIGMA")
                
                if df_sigma.height > 0:
                    # Dedupe based on Tag, Target, User (Ignore Timestamp difference)
                    # We keep the FIRST occurrence (earliest time usually)
                    df_sigma = df_sigma.unique(subset=["Tag", "Target_Path", "User", "Dynamic_Action"], keep="first")
                    
                df_final = pl.concat([df_others, df_sigma], how="diagonal")

        df_final.write_csv(output_csv)
        
        # [NEW] Export metadata at the end
        self._export_metadata(output_csv)
        print(f"[+] Judgment Materialized: {output_csv}")

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeline", required=True)
    parser.add_argument("--ghosts", required=True)
    parser.add_argument("--dir", required=True)
    parser.add_argument("-o", "--out", default="Hercules_Judged_Timeline.csv")
    parser.add_argument("--triage", action="store_true", help="Enable System Silencer")
    args = parser.parse_args(argv)
    
    referee = HerculesReferee(kape_dir=args.dir, triage_mode=args.triage)
    referee.execute(args.timeline, args.ghosts, args.out)

if __name__ == "__main__":
    main()
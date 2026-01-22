import re
import os
import json
import polars as pl
from datetime import datetime, timedelta
from tools.lachesis.intel import TEXT_RES
from tools.lachesis.correlator import CrossCorrelationEngine
from tools.lachesis.scoring_engine import ScoringEngine
from tools.lachesis.insight_generator import InsightGenerator

# ============================================================
# [MIGRATED v2.0] All patterns moved to rules/scoring_rules.yaml
# [REFACTORED v3.0] adjust_score -> scoring_engine.py
# [REFACTORED v3.0] generate_ioc_insight -> insight_generator.py
# ============================================================


class LachesisAnalyzer:
    def __init__(self, intel_module, enricher_module, lang="jp"):
        self.intel = intel_module
        self.enricher = enricher_module
        self.lang = lang
        self.txt = TEXT_RES[self.lang if self.lang in TEXT_RES else "jp"]
        self.visual_iocs = []
        self.visual_iocs_hashes = set()
        self.pivot_seeds = []
        self.infra_ips_found = set()
        self.noise_stats = {}
        self.total_events_analyzed = 0
        self.dynamic_verdict = None
        
        context_scoring = self.intel.get('context_scoring', {})
        self.path_penalties = context_scoring.get('path_penalties', [])
        
        # [v2.1] Initialize CompiledRuleEngine
        self._rule_engine = None
        try:
            from tools.compiled_rule_engine import CompiledRuleEngine
            threat_scores = self.intel.get('threat_scores', [])
            if threat_scores:
                self._rule_engine = CompiledRuleEngine(threat_scores)
        except ImportError:
            pass
        
        # [v2.2] Initialize LedgerManager
        self._ledger_manager = None
        try:
            from tools.score_ledger import LedgerManager
            self._ledger_manager = LedgerManager()
        except ImportError:
            pass
        
        # [v3.0 REFACTORED] Initialize ScoringEngine
        self._scoring_engine = ScoringEngine(
            intel_module=self.intel,
            rule_engine=self._rule_engine,
            ledger_manager=self._ledger_manager
        )
        
        # [v3.0 REFACTORED] Initialize InsightGenerator
        self._insight_generator = InsightGenerator(
            intel_module=self.intel,
            txt_resources=self.txt
        )

    def adjust_score(self, path: str, base_score: int, penalties=None, command_line: str = "", ledger=None) -> tuple:
        """
        [v3.0 REFACTORED] Delegate to ScoringEngine.
        Maintains backward compatibility with existing callers.
        """
        return self._scoring_engine.adjust_score(path, base_score, penalties, command_line, ledger)



    # ═══════════════════════════════════════════════════════════════════════
    # [FIX] Smart Timestamp Extraction Helper
    # ═══════════════════════════════════════════════════════════════════════
    def _get_best_timestamp(self, row):
        candidate_cols = [
            "Timestamp", "Time", "Timestamp_UTC", "Date", 
            "Ghost_Time_Hint", "Last_Executed_Time", 
            "LastWriteTime", "CreationTime", "SourceCreated", 
            "EventTime", "Anomaly_Time", "si_dt", "UpdateTimestamp",
            "TimeCreated", "Created0x10", "LastModified0x10"
        ]
        
        for col in candidate_cols:
            val = str(row.get(col, "")).strip()
            if val and val.lower() not in ["none", "n/a", "null", ""]:
                return val
        return ""

    def _clean_json_garbage(self, text):
        """
        [Fix] JSON形式のログから、人間が読める 'Script' や 'Command' 部分だけを抽出する
        """
        if not text: return text
        
        # 0. 末尾のJSON的なゴミを一括除去 (}}]}} 等)
        # 特にパスの末尾にゴミがついているケースに対応
        if len(text) < 100:
            text = re.sub(r'[\"\'\}\] ]+$', '', text).strip()
            # パスっぽいが先頭にゴミがある場合
            text = re.sub(r'^[\[\{\"\' ]+', '', text).strip()

        # 1. 明らかな非JSONはスルー（高速化）
        if "{" not in text and "}" not in text:
            return text

        # 2. 特有の構造から抽出を試みる
        try:
            # [v6.8] Path を最優先にして、スクリプト全文ではなくファイル名を抽出
            keys = ["Path", "CommandLine", "Command", "Value", "#text"]
            
            # パターンA: 標準的な "Key": "Value"
            # パターンB: "@Name": "Key", "#text": "Value" (XML/JSON変換形式)
            for key in keys:
                # パターンBを優先（より特定的）
                pat_b = rf'"@Name":\s*"{key}",\s*"#text":\s*"([^"]+)"'
                match = re.search(pat_b, text, re.IGNORECASE)
                if not match:
                    # パターンA
                    pat_a = rf'"{key}":\s*"([^"]+)"'
                    match = re.search(pat_a, text, re.IGNORECASE)
                
                if match:
                    clean = match.group(1).replace(r'\"', '"').replace(r'\n', ' ').replace(r'\r', '').strip()
                    if re.match(r'^\d+$', clean): continue # 数字のみはスキップ
                    
                    # 先頭のコメント除去
                    if clean.startswith("#"):
                         clean = re.sub(r'^#.*$', '', clean, flags=re.MULTILINE).strip()
                    
                    # 抽出に成功したがまだJSONの断片（}]}}など）が含まれている場合、それ以降をカット
                    if '"' in clean or "}" in clean or "]" in clean:
                         # 最初に見つかった閉じ記号で切る
                         clean = re.split(r'["}]', clean)[0].strip()

                    return clean[:80] + "..." if len(clean) > 80 else clean

        except:
            pass

        # 3. マッチしなかったがJSONっぽい場合
        if ("{" in text or "}" in text):
             if len(text) > 80:
                 # スクリプト名らしきものを探す (A:\...ps1 など)
                 file_match = re.search(r'([a-zA-Z]:\\[^"\}]+\.ps1)', text)
                 if file_match:
                     return file_match.group(1)
                 return "[Complex Data Object]"
             else:
                 # 短いゴミ付き文字列ならゴミを削って返す
                 return re.sub(r'[\"\'\}\] ]+$', '', text).strip()

        return text

    def _is_noise(self, ioc):
        fname = str(ioc.get("Value", "")).lower()
        v = str(ioc.get('Value', '')).lower()
        p = str(ioc.get('Path', '')).lower()
        t = str(ioc.get('Target_Path', '')).lower()
        c = str(ioc.get('CommandLine', '')).lower()
        check_val = f"{v} | {p} | {t} | {c}"
        
        tags = str(ioc.get("Tag", "")).upper()
        score = int(ioc.get("Score", 0) or 0)
        norm_path = check_val.replace("/", "\\").replace(".\\", "").replace("\\\\", "\\")

        # ═══════════════════════════════════════════════════════════
        # [Case 6] STRICT NOISE FILTER (Killer Rule Integration)
        # ═══════════════════════════════════════════════════════════
        # 1. Regex Definitions
        ps1_noise = r"(?i)^((rs|ts|rc|cl|vf|mf)_.*\.ps1$|.*chocolatey.*\.ps1$|.*\.tests\.ps1$|^(describe|mock|should|context|pester.*)\.ps1$)"
        app_noise = r"(?i)^(googleupdate.*|chrome|chrmstp|notification_helper|onedrive.*|filecoauth|msmpeng|mpcmdrun|nissrv|shimgen|checksum)\.exe$"
        sys_noise = r"(?i)^(pagefile|swapfile|wd(boot|filter|nisdrv))\.sys$"
        cmd_noise = r"(?i)^(collectsynclogs|onedrivepersonal)\.(bat|cmd)$"
        misc_noise = r"(?i).*\.(ignore|manifest)$"
        
        fn_only = fname.split("\\")[-1]
        
        if re.match(ps1_noise, fn_only) or re.match(app_noise, fn_only) or re.match(sys_noise, fn_only) or re.match(cmd_noise, fn_only) or re.match(misc_noise, fn_only):
             # 2. Safety Net: Keep if in suspicious user paths
             suspicious_paths = ["\\downloads\\", "\\temp\\", "appdata\\local\\temp"]
             if any(x in norm_path for x in suspicious_paths):
                 pass # Keep (Risk of Masquerade)
             else:
                 return True # KILL (It's Noise)

        # [Feature 2] Expanded RECON_KEYWORDS for phpMyAdmin/phpinfo detection
        RECON_KEYWORDS = [
            "xampp", "phpmyadmin", "admin", "dashboard", "kibana", 
            "phishing", "c2", "login", "webshell", "backdoor", "exploit",
            "phpinfo", "adminer", "webmin"  # [Feature 2] Added
        ]
        
        image_exts = [".png", ".jpg", ".gif", ".ico", ".bmp"]
        if any(fname.endswith(ext) for ext in image_exts):
            is_recon_evidence = any(kw in norm_path for kw in RECON_KEYWORDS)
            if is_recon_evidence:
                ioc['Score'] = max(score, 600)
                if "INTERNAL_RECON" not in tags:
                    ioc['Tag'] = (tags + ",INTERNAL_RECON").strip(',')
                return False

        # [FIX] Extended noise extensions to reduce false positives
        noise_exts = [
            ".mui", ".nls", ".dll", ".sys", ".jpg", ".png", ".gif", ".ico", ".xml", ".dat",
            ".odl", ".admx", ".adml", ".svg", ".rb", ".provxml", ".cdxml", ".man",
            ".pak"  # [Case 6 Fix] Chrome pak files
        ]
        system_resource_paths = [
            "windows\\system32", 
            "windows\\syswow64",
            "windows\\web\\",
            "windows\\branding\\",
            "program files\\windowsapps",
            "programdata\\microsoft\\windows\\systemdata",
            # [Final Noise Tuning] Update Garbage Paths
            "softwaredistribution",
            "provisioning",
            "onedrive\\setup\\logs"
        ]
        browser_cache_paths = [
            "appdata\\local\\microsoft\\windows\\inetcache",
            "appdata\\local\\google\\chrome\\user data\\default\\cache",
            "temporary internet files",
            "content.ie5",
        ]
        
        # [Final Noise Tuning] Chrome Default Apps Whitelist
        if ".crx" in fname and "default_apps" in norm_path and "chrome" in norm_path:
            return True
            
        # [Final Noise Tuning] OpenSSH Manual Filter
        if "openssh" in norm_path and ("manual" in norm_path or ".htm" in fname):
            return True

        if any(fname.endswith(ext) for ext in noise_exts):
            critical_tags = ["RECON", "EXFIL", "MASQUERADE", "SCREENSHOT", "LATERAL"]
            if any(t in tags for t in critical_tags):
                return False
            if any(sp in norm_path for sp in system_resource_paths):
                return True
            if any(bp in norm_path for bp in browser_cache_paths):
                return True

        if score >= 200: return False
        if "LATERAL" in tags or "REMOTE" in tags or "RANSOM" in tags or "WIPER" in tags:
            return False

        # [FIX] Exclude Puppet/Ruby development paths (major noise source)
        dev_tool_paths = ["puppet", "ruby", "\\gems\\", "\\lib\\ruby", "\\vendor\\"]
        if any(dev_path in norm_path for dev_path in dev_tool_paths):
            return True

        # [v2.0] Load garbage patterns from YAML
        garbage_patterns = self.intel.get('garbage_patterns', [])
        for trash in garbage_patterns:
            if trash in norm_path:
                return True

        other_noise_exts = [".manifest", ".mum", ".cat", ".tlb", ".pri", ".p7x", ".p7s", ".db"]
        for ext in other_noise_exts:
            if fname.endswith(ext) and "RECON" not in tags:
                return True

        return False

    def get_verdict_for_report(self, verdict_flags):
        verdicts = {
            "jp": {
                "ransomware": ("🚨 CRITICAL: ランサムウェア攻撃を検出", "暗号化バースト、破壊コマンド、または身代金要求ノートが検出されました。"),
                "webshell": ("🚨 CRITICAL: WebShell侵害を検出", "Webサーバー上でWebShellの痕跡が確認されました。"),
                "anti_forensics": ("⚠️ HIGH: 証拠隠滅・偽装を伴う侵害を確認", "ワイピングツールやアンチフォレンジック活動が検出されました。"),
                "phishing": ("⚠️ HIGH: フィッシング攻撃の痕跡を確認", "偽装されたLNKファイルやソーシャルエンジニアリングの痕跡が検出されました。"),
                "standard": ("📌 MEDIUM: 不審な活動を検出", "分析対象期間において、複数の不審な活動を確認しました。")
            },
            "en": {
                "ransomware": ("🚨 CRITICAL: RANSOMWARE ACTIVITY DETECTED", "Encryption burst, destructive commands, or ransom notes were detected."),
                "webshell": ("🚨 CRITICAL: WEBSHELL INTRUSION DETECTED", "WebShell artifacts were found on the web server."),
                "anti_forensics": ("⚠️ HIGH: COMPROMISE WITH EVIDENCE DESTRUCTION", "Wiping tools and anti-forensics activities were detected."),
                "phishing": ("⚠️ HIGH: PHISHING ATTACK INDICATORS FOUND", "Masqueraded LNK files or social engineering artifacts were detected."),
                "standard": ("📌 MEDIUM: SUSPICIOUS ACTIVITY DETECTED", "Multiple suspicious activities were identified during the analysis period.")
            }
        }
        
        lang_verdicts = verdicts.get(self.lang, verdicts["jp"])
        flags = verdict_flags or set()
        
        if "RANSOMWARE_ACTIVITY" in flags:
            title, desc = lang_verdicts["ransomware"]
            severity = "CRITICAL"
        elif "WEBSHELL_INTRUSION" in flags:
            title, desc = lang_verdicts["webshell"]
            severity = "CRITICAL"
        elif "ANTI_FORENSICS_HEAVY" in flags:
            title, desc = lang_verdicts["anti_forensics"]
            severity = "HIGH"
        elif "PHISHING_ENTRY" in flags:
            title, desc = lang_verdicts["phishing"]
            severity = "HIGH"
        else:
            title, desc = lang_verdicts["standard"]
            severity = "MEDIUM"
        
        return {
            "title": title,
            "description": desc,
            "severity": severity,
            "ioc_counts": {}
        }

    def export_score_breakdown(self, output_path: str, case_name: str = "") -> str:
        """
        [v2.2] Export score ledgers to markdown file.
        Only includes events with score >= 500.
        
        Args:
            output_path: Directory to write the MD file
            case_name: Case identifier for filename
            
        Returns:
            Path to generated file, or empty string if no high-score events
        """
        if self._ledger_manager:
            return self._ledger_manager.export_to_markdown(output_path, threshold=500, case_name=case_name)
        return ""

    def process_events(self, analysis_result, dfs):
        raw_events = analysis_result.get("events", [])
        self.total_events_analyzed = len(raw_events)
        self.noise_stats = self.intel.noise_stats 
        
        high_crit_times = []
        critical_events = []
        medium_events = []

        for ev in raw_events:
            try:
                # [Fix] support both Score (v6.1+) and Criticality (Legacy/Triad-specific)
                score_val = ev.get('Score') or ev.get('Criticality', 0)
                score = int(float(score_val))
            except: score = 0

            summary = ev.get('Summary', '')
            tag = str(ev.get('Tag', '')).upper()
            is_dual = self.intel.is_dual_use(summary)
            
            is_crit_std = False
            if score >= 200: is_crit_std = True
            elif is_dual and score >= 80: is_crit_std = True
            elif "CRITICAL" in str(ev.get('Category', '')).upper(): is_crit_std = True
            elif "CRITICAL" in tag or "ACTIVE" in tag: is_crit_std = True
            
            force_include_tags = ["TIME_PARADOX", "MASQUERADE", "PHISHING", "SUSPICIOUS_CMDLINE", "ROLLBACK"]
            if any(k in tag for k in force_include_tags):
                is_crit_std = True
            
            if is_crit_std: critical_events.append(ev)
            elif score >= 80: medium_events.append(ev)

            chk_score = score
            for k in ['Threat_Score', 'Chronos_Score', 'AION_Score']:
                try: 
                    s = int(float(ev.get(k, 0)))
                    if s > chk_score: chk_score = s
                except: pass
            
            chk_tag = tag + str(ev.get('Threat_Tag', "")).upper()
            chk_name = str(ev.get('FileName', "") or ev.get('Ghost_FileName', "") or ev.get('Target_FileName', "") or summary).lower()
            
            if chk_score >= 200 or "CRITICAL" in chk_tag or "MASQUERADE" in chk_tag or "TIMESTOMP" in chk_tag or "PHISHING" in chk_tag or "PARADOX" in chk_tag or self.intel.is_dual_use(chk_name):
                # [FIX] Use best effort time extraction from raw event if needed, but enricher handles parsing
                t_val = ev.get('Time') or ev.get('Ghost_Time_Hint') or ev.get('Last_Executed_Time')
                dt = self.enricher.parse_time_safe(t_val)
                if dt and dt.year >= 2000:  
                    high_crit_times.append((dt, chk_score))

        self.visual_iocs = []
        self._extract_visual_iocs_from_pandora(dfs)
        self._extract_visual_iocs_from_timeline(dfs) 
        self._extract_visual_iocs_from_chronos(dfs)
        self._extract_visual_iocs_from_aion(dfs)
        self._extract_visual_iocs_from_plutos_srum(dfs)
        self._extract_visual_iocs_from_plutos_recon(dfs)
        self._extract_visual_iocs_from_events(raw_events)
        
        correlator = CrossCorrelationEngine(self.intel)
        if self.visual_iocs:
            correlator.load_evidence(dfs)
            self.visual_iocs = correlator.apply_rules(self.visual_iocs)
            self.visual_iocs = correlator.apply_temporal_proximity_boost(self.visual_iocs)
            flags, summary = correlator.determine_verdict(self.visual_iocs)
            analysis_result["verdict_flags"] = flags
            analysis_result["lateral_summary"] = summary
        
        # ═══════════════════════════════════════════════════════════
        # [The Reaper] Final Noise Filter (Polars Logic Adaptation)
        # Drop items with Score < 400 AND Tag "SYSTEM_NOISE"
        # ═══════════════════════════════════════════════════════════
        before_reaper = len(self.visual_iocs)
        self.visual_iocs = [
            ioc for ioc in self.visual_iocs
            if not (int(ioc.get('Score', 0) or 0) < 400 and "SYSTEM_NOISE" in str(ioc.get('Tag', '')))
        ]
        print(f"[THE REAPER] Culled {before_reaper - len(self.visual_iocs)} noise artifacts.")
        
        self._generate_pivot_seeds()
        
        force_include_types = [
            "TIME_PARADOX", "CRITICAL_MASQUERADE", "CRITICAL_PHISHING", 
            "TIMESTOMP", "CREDENTIALS", "ANTI_FORENSICS", "PERSISTENCE", "SAM_SCAVENGE"
        ]
        for ioc in self.visual_iocs:
            ioc_type = str(ioc.get("Type", "")).upper()
            if any(k in ioc_type for k in force_include_types):
                ioc_time = ioc.get("Time", "")
                dt = self.enricher.parse_time_safe(ioc_time)
                # Parse score for Recency Check
                try: ioc_score = int(ioc.get("Score", 0) or 0)
                except: ioc_score = 0
                
                if dt and dt.year >= 2000:
                    high_crit_times.append((dt, ioc_score))

        # [Case 6 Fix] Recency Logic for Analysis Range (Score-Aware)
        # Prevent ancient artifacts (2011, etc.) from skewing the report timeline,
        # UNLESS they are High Criticality (Score >= 900).
        valid_times = []
        if high_crit_times:
            # Sort by date
            high_crit_times = sorted([t for t in high_crit_times if t[0] is not None], key=lambda x: x[0])
            
            if high_crit_times:
                max_dt = high_crit_times[-1][0]
                cutoff_dt = max_dt - timedelta(days=730) # 2 years
                
                # Keep if Recent OR Critical
                valid_times = [t[0] for t in high_crit_times if (t[0] >= cutoff_dt) or (t[1] >= 900)]
                
                # If we filtered everything (unlikely), fallback to last 30 days of max
                if not valid_times:
                     valid_times = [max_dt]

        time_range = "Unknown Range (No Critical Events)"
        if valid_times:
            core_start = min(valid_times) - timedelta(hours=3)
            core_end = max(valid_times) + timedelta(hours=3)
            time_range = f"{core_start.strftime('%Y-%m-%d %H:%M')} 〜 {core_end.strftime('%Y-%m-%d %H:%M')} (UTC)"
        
        self._correlate_antiforensics_and_user_creation()

        return {
            "critical_events": critical_events,
            "medium_events": medium_events,
            "time_range": time_range,
            "phases": [critical_events] if critical_events else []
        }

    def _correlate_antiforensics_and_user_creation(self):
        has_log_deletion = False
        has_user_creation = False
        user_names = []
        
        for ioc in self.visual_iocs:
            tag = str(ioc.get('Tag', '')).upper()
            ioc_type = str(ioc.get('Type', '')).upper()
            value = str(ioc.get('Value', ''))
            
            if "LOG_DELETION" in tag or "EVIDENCE_WIPING" in tag or "1102" in value:
                has_log_deletion = True
            
            if "USER_CREATION" in tag or "NEW_USER_CREATED" in tag or "SAM_USER" in tag:
                has_user_creation = True
                if value:
                    user_names.append(value)
        
        if has_log_deletion and has_user_creation:
            if self.lang == "en":
                causality_note = f"⚠️ **CAUSALITY DETECTED**: Log deletion + User creation (Scavenged) detected. Missing EID 4720/4732 confirmed. [LOG_WIPE_INDUCED_MISSING_EVENT] for user(s): {', '.join(user_names)}"
            else:
                causality_note = f"⚠️ **因果関係検知**: ログ削除とユーザー作成(Scavenged)を検知。イベントログ(EID 4720/4732)の欠落を確認しました。[LOG_WIPE_INDUCED_MISSING_EVENT] 対象: {', '.join(user_names)}"
            
            for ioc in self.visual_iocs:
                tag = str(ioc.get('Tag', '')).upper()
                if "LOG_DELETION" in tag or "EVIDENCE_WIPING" in tag:
                    ioc['Causality_Note'] = causality_note
                    ioc['Score'] = max(int(ioc.get('Score', 0)), 500) 
        
        elif has_log_deletion and not has_user_creation:
            if self.lang == "en":
                gap_note = "🚨 **EVIDENCE GAP**: Log deletion detected but no user creation events (EID 4720/4732) found. High probability that events were deleted to hide unauthorized account creation. [LOG_WIPE_INDUCED_MISSING_EVENT]"
            else:
                gap_note = "🚨 **証拠の空白**: ログ削除を検知しましたがユーザー作成イベント(EID 4720/4732)が見つかりません。不正アカウント作成を隠蔽した可能性が高いです。[LOG_WIPE_INDUCED_MISSING_EVENT]"
            
            for ioc in self.visual_iocs:
                tag = str(ioc.get('Tag', '')).upper()
                if "LOG_DELETION" in tag or "EVIDENCE_WIPING" in tag:
                    ioc['Causality_Note'] = gap_note



    def _extract_visual_iocs_from_plutos_srum(self, dfs):
        """[OPTIMIZED] SRUM High Heat Extraction - Vectorized version"""
        srum_df = dfs.get('Plutos_Srum')
        if srum_df is None or srum_df.height == 0: 
            return

        # [OPTIMIZATION] Pre-filter with vectorized operations
        # Only process rows with Bytes_Sent > 1MB (1000000)
        proc_col = "App_Name" if "App_Name" in srum_df.columns else "Process"
        bytes_col = "Bytes_Sent"
        
        if proc_col not in srum_df.columns or bytes_col not in srum_df.columns:
            return
        
        # Vectorized filter: Bytes_Sent > 1MB
        high_traffic = srum_df.filter(
            pl.col(bytes_col).cast(pl.Int64, strict=False).fill_null(0) > 1000000
        )
        
        if high_traffic.height == 0:
            return
        
        print(f"    [SRUM] Found {high_traffic.height} high-traffic entries (>1MB)")
        
        # Convert to list only for filtered rows (much smaller dataset)
        for row in high_traffic.iter_rows(named=True):
            proc = row.get(proc_col, '') or ''
            if not proc: 
                continue
             
            bytes_sent = int(row.get(bytes_col, 0) or 0)
            mb_sent = bytes_sent // 1024 // 1024
            self._add_unique_visual_ioc({
                "Type": "SRUM_HIGH_HEAT",
                "Value": f"Proc: {proc}<br>Sent: {mb_sent} MB",
                "Path": "SRUM Database",
                "Time": self._get_best_timestamp(row),
                "Score": 500,
                "Tag": "DATA_EXFIL,SRUM",
                "Note": f"High Volume Traffic: {mb_sent} MB Sent"
            })


    def _extract_visual_iocs_from_timeline(self, dfs):
        timeline_df = dfs.get('Timeline')
        print(f"[DEBUG-ANALYZER] Timeline Type: {type(timeline_df)}")
        if timeline_df is not None:
            print(f"[DEBUG-ANALYZER] Timeline DF rows: {timeline_df.height} Columns: {timeline_df.columns[:5]}")
            # [Feature 3] Enhanced with UNC Lateral Movement Tools
            # Tuple Format: (Pattern, Tag, Score, Match_Mode[Optional default="partial"])
            HIGH_VALUE_PATTERNS = [
                ("putty", "REMOTE_ACCESS", 300),
                ("winscp", "REMOTE_ACCESS", 300),
                ("setmace", "ANTI_FORENSICS", 400),
                ("sdelete", "ANTI_FORENSICS", 300),
                ("bcwipe", "ANTI_FORENSICS", 400),
                ("dd.exe", "DATA_EXFIL", 200),
                ("ssh-add", "DATA_EXFIL", 200),
                # [Feature 3] Lateral Movement Tools
                ("robocopy.exe", "FILE_COPY_TOOL", 50),
                ("xcopy.exe", "FILE_COPY_TOOL", 50),
                ("dcode", "FORENSIC_TOOL", 400),
                ("wmic.exe", "WMI_EXECUTION", 50),
                ("psexec", "LATERAL_MOVEMENT", 250),
                ("plink", "REMOTE_ACCESS", 300),
                # [FIX] Exact Match for Sync to avoid mobsync/tzsync noise
                ("sync.exe", "SYSINTERNALS_SYNC", 150, "exact"),
                ("sync64.exe", "SYSINTERNALS_SYNC", 150, "exact"),
                ("sysinternals", "SYSINTERNALS_TOOL", 150),
                # [Case 6] Metasploit & Staging
                ("back_door.rb", "METASPLOIT_SCRIPT", 800),
                ("exploit.", "METASPLOIT_FRAMEWORK", 800),
                ("7za.exe", "STAGING_TOOL", 600),
                ("choco.exe", "STAGING_TOOL", 400),
            ]
            
            # [Optimization] Construct Vectorized Filter for Pre-filtering
            # Iterate only on rows that contain at least one pattern in FileName or Path
            try:
                patterns_list = [p[0] for p in HIGH_VALUE_PATTERNS]
                # Escape patterns for regex
                escaped_patterns = [re.escape(p) for p in patterns_list]
                combined_regex = "(?i)(" + "|".join(escaped_patterns) + ")"
                
                
                # Check column existence
                cols = timeline_df.columns
                f_col = None
                for c in ["FileName", "Target_FileName", "File_Name", "Source_File", "Target_Path"]:
                    if c in cols:
                        f_col = c
                        break
                if not f_col: f_col = "FileName" # Fallback to avoid NoneType error, though likely will fail in filter if missing

                p_col = None
                for c in ["ParentPath", "Target_Path", "Path"]:
                    if c in cols:
                        p_col = c
                        break
                if not p_col: p_col = "Target_Path"
                
                # Filter Expression
                # Only keep rows where FileName OR Path matches the combined regex
                # UNC paths start with \\ (escaped as \\\\)
                timeline_df_filtered = timeline_df.filter(
                    pl.col(f_col).str.contains(combined_regex) | 
                    pl.col(p_col).str.contains(combined_regex) |
                    pl.col(p_col).str.starts_with(r"\\") 
                )
                print(f"[DEBUG-ANALYZER] Timeline High-Value Hits: {timeline_df_filtered.height} (Filtered from {timeline_df.height})")
                
                target_iter = timeline_df_filtered.iter_rows(named=True)
            except Exception as e:
                print(f"[!] Analyzer Optimization Failed: {e}. Fallback to full scan.")
                target_iter = timeline_df.iter_rows(named=True)

            for row in target_iter:
                fname = str(row.get("Target_FileName") or row.get("FileName") or row.get("File_Name") or "").lower()
                path = str(row.get("Target_Path") or row.get("ParentPath") or "").lower()
                score = int(float(row.get("Score") or row.get("Threat_Score") or 0)) # [FIX] Handle Threat_Score column
                
                matched_pattern = False
                for entry in HIGH_VALUE_PATTERNS:
                    pattern = entry[0]
                    ioc_type = entry[1]
                    min_score = entry[2]
                    mode = entry[3] if len(entry) > 3 else "partial"

                    is_hit = False
                    if mode == "exact":
                        # Exact Match: Filename must match exactly (ignoring path)
                        if fname == pattern: is_hit = True
                    else:
                        # Partial Match: Contains in filename or path
                        if pattern in fname or pattern in path: is_hit = True

                    if is_hit:
                         is_unc = path.startswith("\\\\") and not path.startswith("\\\\?\\")
                         if is_unc:
                             ioc_type = "LATERAL_MOVEMENT"
                             # [Feature 3] UNC Lateral Movement = Score 900
                             min_score = 900
                         
                         display_name = fname if fname else path.split("\\")[-1]
                         if is_unc and path:
                             display_name = f"{display_name} [FROM: {path}]"
                         
                         self._add_unique_visual_ioc({
                             "Type": ioc_type,
                             "Value": display_name,
                             "Path": path,
                             "Note": "UNC Execution (Network Share)" if is_unc else "Timeline Artifact",
                             # [FIX] Use best timestamp
                             "Time": self._get_best_timestamp(row),
                             "Score": max(score, min_score),
                             "Tag": f"{ioc_type},UNC_EXECUTION" if is_unc else ioc_type,
                             "Reason": "Remote Execution Detected" if is_unc else "High-Value Pattern Detected"
                         })
                         matched_pattern = True
                         break
                
                if matched_pattern: continue

                path = str(row.get("Target_Path") or row.get("ParentPath") or "").lower()
                
                if path.startswith(r"\\") and not path.startswith(r"\\?\\") and "127.0.0.1" not in path:
                     display_name = path.split("\\")[-1] or "Remote Exec"
                     self._add_unique_visual_ioc({
                         "Type": "LATERAL_MOVEMENT",
                         "Value": f"{display_name} [FROM: {path}]", 
                         "Path": path,
                         "Note": "UNC Execution (Network Share)",
                         # [FIX] Use best timestamp
                         "Time": self._get_best_timestamp(row),
                         "Score": 300,
                         "Tag": "UNC_PATH_EXECUTION,LATERAL_MOVEMENT",
                         "Reason": "Remote Execution Detected"
                     })

    def _correlate_cross_evidence(self, dfs):
        rules = self.intel.get('correlation_rules', [])
        if not rules: return
        data_cache = {}
        if dfs.get('Plutos_Srum') is not None:
            srum_map = {}
            for row in dfs['Plutos_Srum'].iter_rows(named=True):
                proc = str(row.get("Process", "")).lower().split("\\")[-1]
                sent = int(row.get("BytesSent", 0) or 0)
                if proc in srum_map: srum_map[proc] += sent
                else: srum_map[proc] = sent
            data_cache['Plutos_Srum'] = srum_map

        for ioc in self.visual_iocs:
            ioc_tags = str(ioc.get("Tag", "")).upper()
            ioc_val = str(ioc.get("Value", "")).lower()

            for rule in rules:
                triggers = rule.get('triggers', {})
                target_tags = triggers.get('tags', [])
                if not any(t in ioc_tags for t in target_tags):
                    continue

                validator = rule.get('validator', {})
                source_name = validator.get('source')
                source_data = data_cache.get(source_name)
                if not source_data: continue

                metric_val = source_data.get(ioc_val, 0)
                threshold = validator.get('threshold', 0)
                operator = validator.get('operator', '>')
                
                is_hit = False
                if operator == '>' and metric_val > threshold: is_hit = True
                elif operator == '>=' and metric_val >= threshold: is_hit = True
                
                if not is_hit: continue

                action = rule.get('action', {})
                if 'score_override' in action:
                    ioc['Score'] = action['score_override']
                elif 'score_min' in action:
                    ioc['Score'] = max(int(ioc.get('Score', 0)), action['score_min'])
                
                if 'tag_append' in action:
                    new_tags = action['tag_append']
                    if new_tags not in ioc.get('Tag', ''):
                        ioc['Tag'] = (ioc.get('Tag', '') + "," + new_tags).strip(',')

                fmt_data = {"value": metric_val, "value_mb": metric_val // 1024 // 1024}
                if 'note_append' in action:
                    ioc['Note'] = (ioc.get('Note', '') + action['note_append'].format(**fmt_data))
                if 'insight_template' in action:
                    insight = action['insight_template'].format(**fmt_data)
                    ioc['Insight'] = (ioc.get('Insight', '') + "\n\n" + insight).strip()
                
                print(f"    [!] Correlation Hit ({rule['id']}): {ioc_val} -> Score {ioc['Score']}")


    def _extract_visual_iocs_from_chronos(self, dfs):
        """[OPTIMIZED] Pre-filter Chronos by score/tag before iter_rows"""
        if dfs.get('Chronos') is None:
            return
        df = dfs['Chronos']
        cols = df.columns
        score_col = "Chronos_Score" if "Chronos_Score" in cols else "Threat_Score"
        if score_col not in cols:
            return
        
        try:
            # [OPTIMIZATION v2] Strict filter: score >= 500 OR has ROLLBACK OR critical dual-use tools
            # Limit to 5000 rows max to prevent freeze
            anomaly_col = "Anomaly_Time" if "Anomaly_Time" in cols else None
            tag_col = "Threat_Tag" if "Threat_Tag" in cols else None
            fname_col = "FileName" if "FileName" in cols else None
            path_col = "ParentPath" if "ParentPath" in cols else None
            
            # Build filter expression - STRICTER threshold (500 instead of 200)
            filter_expr = pl.col(score_col).cast(pl.Float64, strict=False).fill_null(0) >= 500
            
            # Include ROLLBACK detection (critical, always include)
            if anomaly_col:
                filter_expr = filter_expr | pl.col(anomaly_col).fill_null("").str.contains("ROLLBACK")
            
            # Include critical dual-use tools only (putty, setmace - not psexec/winscp)
            if fname_col:
                filter_expr = filter_expr | pl.col(fname_col).fill_null("").str.to_lowercase().str.contains(r"(?i)(putty|setmace)")
            if path_col:
                filter_expr = filter_expr | pl.col(path_col).fill_null("").str.to_lowercase().str.contains(r"(?i)(putty|setmace)")
            
            # Sort by score descending and limit to 5000 rows max
            df_filtered = df.filter(filter_expr).sort(score_col, descending=True).head(5000)
            
            if df_filtered.height == 0:
                return
            
            print(f"    [Chronos] Processing {df_filtered.height} high-value entries (from {df.height}, max 5000)")
            
            for row in df_filtered.iter_rows(named=True):
                fname = row.get("FileName") or ""
                path = row.get("ParentPath") or ""
                score = int(float(row.get(score_col, 0)))
                
                bypass_reason = None
                is_trusted_loc = self.intel.is_trusted_system_path(path)
                is_dual = self.intel.is_dual_use(fname)

                if "ROLLBACK" in str(row.get("Anomaly_Time", "")):
                    bypass_reason = "🚨 SYSTEM TIME ROLLBACK DETECTED 🚨"
                    if not fname and path: fname = f"System Artifact ({path})"
                    self.intel.log_noise("TIME PARADOX", f"{fname} triggered Rollback Alert")
                    self._add_unique_visual_ioc({
                        "Type": "TIME_PARADOX", 
                        "Value": fname if fname else "Unknown", 
                        "Path": path, 
                        "Note": str(row.get("Anomaly_Time", "")), 
                        "Time": self._get_best_timestamp(row),
                        "Reason": bypass_reason,
                        "Score": score,
                        "FileName": fname,
                        "Action": "Rollback Detected" 
                    })
                    continue

                path_lower = str(path).lower()
                fname_lower = str(fname).lower()
                tag = str(row.get("Threat_Tag", "")).upper()
                
                if "putty" in path_lower or "putty" in fname_lower:
                    score = max(score, 300)
                    if "REMOTE_ACCESS" not in tag:
                        tag += ",REMOTE_ACCESS_CLIENT"
                        
                if "setmace" in path_lower:
                    score = max(score, 400)
                    tag += ",CRITICAL_TIMESTOMP"

                extra_info = {}
                timeline_df = dfs.get('Timeline')
                if is_dual or "TIMESTOMP" in str(row.get("Threat_Tag", "")):
                    _, _, _, is_executed = self.enricher.enrich_from_timeline(fname, timeline_df)
                    extra_info["Execution"] = is_executed

                if is_dual: bypass_reason = "Dual-Use Tool [DROP]" 
                elif score >= 220:
                    if is_trusted_loc:
                        self.intel.log_noise("Trusted Path (Update)", fname)
                        continue
                    else:
                        bypass_reason = "High Score (Timestomp) [DROP]"
                
                if self.intel.is_noise(fname, path):
                    self.intel.log_noise("Explicit Noise Filter", fname)
                    continue

                if bypass_reason:
                    if "False Positive" in bypass_reason or "NOISE" in bypass_reason: 
                        continue
                elif score < 200: 
                    continue 
                
                if not bypass_reason: bypass_reason = "High Score (>200)"
                self._add_unique_visual_ioc({
                    "Type": "TIMESTOMP", "Value": fname, "Path": path, "Note": "Time Anomaly", 
                    "Time": self._get_best_timestamp(row),
                    "Reason": bypass_reason, 
                    "Score": score,
                    "Extra": extra_info,
                    "FileName": fname, 
                    "Action": "Timestomp Detected" 
                })
        except Exception as e:
            print(f"    [!] Chronos Extract Error: {e}")


    def _extract_visual_iocs_from_pandora(self, dfs):
        """[OPTIMIZED] Pre-filter Pandora by score/tag before iter_rows"""
        if dfs.get('Pandora') is None:
            return
        df = dfs['Pandora']
        timeline_df = dfs.get('Timeline') 
        
        if "Threat_Score" not in df.columns:
            return
        
        try:
            SYSTEM_NOISE_PATHS = [
                "winsxs", "assembly", "servicing", "manifests", 
                "catalogs", "driverstore", "installer"
            ]
            
            # [OPTIMIZATION] Pre-filter: score >= 50 OR critical tags OR dual-use patterns
            cols = df.columns
            filter_expr = pl.col("Threat_Score").cast(pl.Float64, strict=False).fill_null(0) >= 50
            
            if "Threat_Tag" in cols:
                filter_expr = filter_expr | pl.col("Threat_Tag").fill_null("").str.to_uppercase().str.contains(
                    r"(MASQUERADE|PHISH|BACKDOOR|CREDENTIALS|TIMESTOMP|REMOTE_ACCESS|LATERAL|CRITICAL)"
                )
            
            if "Ghost_FileName" in cols:
                filter_expr = filter_expr | pl.col("Ghost_FileName").fill_null("").str.to_lowercase().str.contains(r"(?i)(putty|setmace)")
            if "ParentPath" in cols:
                filter_expr = filter_expr | pl.col("ParentPath").fill_null("").str.to_lowercase().str.contains(r"(?i)(putty|setmace)")
                # Include UNC paths
                filter_expr = filter_expr | pl.col("ParentPath").fill_null("").str.starts_with(r"\\")
            
            df_filtered = df.filter(filter_expr)
            
            if df_filtered.height == 0:
                return
            
            print(f"    [Pandora] Processing {df_filtered.height} high-value entries (from {df.height})")
            
            for row in df_filtered.iter_rows(named=True):
                fname = row.get("Ghost_FileName", "")
                path = row.get("ParentPath", "")
                tag = str(row.get("Threat_Tag", "")).upper()
                score = int(float(row.get("Threat_Score", 0)))
                
                path_lower = str(path).lower()
                fname_lower = str(fname).lower()
                
                if "setmace" in path_lower or "TIMESTOMP_TOOL" in tag: 
                    fname = "SetMACE.exe (Recovered)"
                    score = max(score, 400)
                    tag += ",CRITICAL_TIMESTOMP"
                
                elif "putty" in path_lower or "putty" in fname_lower:
                    if score < 300: score = 300 
                    if "REMOTE_ACCESS" not in tag: tag += ",REMOTE_ACCESS_CLIENT"
                
                elif path.startswith("\\\\") and not path.startswith("\\\\?\\"):
                    if score < 200: score = max(score, 200)
                    if "LATERAL" not in tag: tag += ",LATERAL_MOVEMENT_EXEC"
                
                if any(noise in path_lower for noise in SYSTEM_NOISE_PATHS): 
                    continue

                bypass_reason = None
                is_trusted_loc = self.intel.is_trusted_system_path(path)

                if "MASQUERADE" in tag: bypass_reason = "Critical Criteria (CRITICAL_MASQUERADE) [DROP]"
                elif "PHISH" in tag: bypass_reason = "Critical Criteria (PHISHING) [DROP]"
                elif "BACKDOOR" in tag: bypass_reason = "Backdoor Detected [DROP]"
                elif "CREDENTIALS" in tag and score >= 200: bypass_reason = "Credential Dump [DROP]"
                elif is_trusted_loc:
                    self.intel.log_noise("Trusted Path (Update)", fname)
                    continue
                
                is_crit_bypass = "TIMESTOMP" in tag or "REMOTE_ACCESS" in tag or "CRITICAL" in tag
                if not is_crit_bypass and self.intel.is_noise(fname, path):
                    self.intel.log_noise("Explicit Noise Filter", fname)
                    continue

                if self.intel.is_dual_use(fname): bypass_reason = "Dual-Use Tool [DROP]"
                elif "TIMESTOMP" in tag: bypass_reason = "Timestomp [DROP]"
                elif score >= 250: bypass_reason = "Critical Score [DROP]"

                if bypass_reason: pass
                elif score < 50: continue 

                if not bypass_reason: bypass_reason = "High Confidence"
                clean_name = os.path.basename(fname.split("] ")[-1])
                
                extra_info = {}
                final_tag = tag

                if ".lnk" in fname.lower():
                    target_path, timeline_tag, args, _ = self.enricher.enrich_from_timeline(fname, timeline_df)
                    if target_path: extra_info["Target_Path"] = target_path
                    if args: extra_info["Arguments"] = args
                    if "DEFCON" in clean_name.upper() or "BYPASS" in clean_name.upper():
                        extra_info["Risk"] = "SECURITY_TOOL_MASQUERADE"
                    if timeline_tag:
                        merged_tags = set(tag.split(",") + timeline_tag.split(","))
                        merged_tags.discard("")
                        final_tag = ",".join(list(merged_tags))
                
                ioc_type = final_tag
                if "REMOTE_ACCESS" in tag.upper(): ioc_type = "REMOTE_ACCESS"
                elif "LATERAL" in tag.upper(): ioc_type = "LATERAL_MOVEMENT"
                
                self._add_unique_visual_ioc({
                    "Type": ioc_type,
                    "Value": clean_name, 
                    "Path": path, 
                    "Note": "File Artifact", 
                    "Time": self._get_best_timestamp(row),
                    "Reason": bypass_reason,
                    "Extra": extra_info,
                    "Score": score,
                    "FileName": fname,
                    "Target_Path": path,
                    "Tag": final_tag
                })
        except Exception as e:
            print(f"[ERROR] Pandora IOC Extract Failed: {e}")
            import traceback
            traceback.print_exc()


    def _extract_visual_iocs_from_aion(self, dfs):
        """[OPTIMIZED] Pre-filter AION by score >= 50 before iter_rows"""
        if dfs.get('AION') is None:
            return
        df = dfs['AION']
        if "AION_Score" not in df.columns:
            return
        
        try:
            # [OPTIMIZATION] Pre-filter: Only rows with AION_Score >= 50
            df_filtered = df.filter(
                pl.col("AION_Score").cast(pl.Float64, strict=False).fill_null(0) >= 50
            )
            
            if df_filtered.height == 0:
                return
            
            print(f"    [AION] Processing {df_filtered.height} high-score entries (score >= 50)")
            
            for row in df_filtered.iter_rows(named=True):
                try: 
                    score = int(float(row.get("AION_Score", 0)))
                except: 
                    score = 0
                
                name = row.get("Target_FileName")
                tags = str(row.get("AION_Tags", ""))
                is_scavenge = "SAM_SCAVENGE" in tags
                
                if is_scavenge:
                    if score < 150: 
                        continue
                    rid = row.get("RID", "")
                    sid = row.get("SID", "")
                    hash_st = row.get("Hash_State", "")
                    hash_can = row.get("Hash_Detail", "")
                    
                    entry_loc = ""
                    for k, v in row.items():
                        if "entry" in k.lower() and "location" in k.lower():
                            entry_loc = v
                            break
                    
                    path_parts = []
                    if sid: path_parts.append(f"SID: {sid}")
                    if rid: path_parts.append(f"RID: {rid}")
                    if hash_can and hash_st == "Hash Candidate":
                        path_parts.append(f"Hash: {hash_can} (NTLM Candidate)")
                    elif hash_st: 
                        path_parts.append(f"Hash: {hash_st}")
                         
                    if entry_loc and "HEX" in entry_loc:
                        import re
                        hex_match = re.search(r'\[HEX: ([a-fA-F0-9\.]+)\]', entry_loc)
                        if hex_match:
                            path_parts.append(f"[HEX: {hex_match.group(1)}]")
                    
                    if entry_loc and "Linked to Group" in entry_loc:
                        start = entry_loc.find("[Linked to Group")
                        end = entry_loc.find("]", start)
                        if start != -1 and end != -1:
                            link_note = entry_loc[start:end+1]
                            path_parts.append(link_note)
                    
                    path_str = " | ".join(path_parts) if path_parts else (entry_loc or row.get("Full_Path", ""))
                else:
                    path_str = row.get("Entry_Location") or row.get("Full_Path", "")

                if not self.intel.is_noise(name, path_str):
                    self._add_unique_visual_ioc({
                        "Type": "PERSISTENCE", "Value": name, "Path": path_str, "Note": "Persist", 
                        "Time": self._get_best_timestamp(row),
                        "Reason": "Persistence",
                        "Tag": tags,
                        "Score": score,
                        "Target_FileName": name,
                        "Target_Path": path_str
                    })
        except Exception as e:
            print(f"    [!] AION Extract Error: {e}")

                
    def _extract_visual_iocs_from_plutos_recon(self, dfs):
        if dfs.get('Recon') is not None:
             df = dfs['Recon']
             if df.height > 0:
                 for row in df.iter_rows(named=True):
                     url = row.get("URL") or ""
                     title = row.get("Title") or ""
                     verdict = row.get("Plutos_Verdict") or "RECON_ACTIVITY"
                     score = row.get("Heat_Score") or 0
                     
                     # [FIX] Use best timestamp
                     timestamp = self._get_best_timestamp(row)
                     
                     self._add_unique_visual_ioc({
                         "Type": verdict, 
                         "Value": url if url else title,
                         "Path": "Browser History",
                         "Note": title if url else "Reconnaissance",
                         "Time": str(timestamp), 
                         "Reason": f"High Score ({score})",
                         "Score": int(score),
                         "Tag": verdict,
                         "Analysis": "Reconnaissance Detected"
                     })

    def _extract_visual_iocs_from_events(self, events):
        # [v6.9.3] Universal Indicator Extraction (No Hardcoding)
        re_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        # General FQDN/local domain pattern (e.g., ccdfir.local, google.com)
        re_domain = re.compile(r'\b([a-zA-Z0-9.-]+\.(?:local|com|net|org|edu|gov|io|biz|info))\b', re.IGNORECASE)
        
        infra_ips = self.intel.infra_ips
        if not infra_ips:
            infra_ips = {"10.0.2.15", "10.0.2.2", "127.0.0.1", "0.0.0.0", "::1"} 

        for ev in events:
            # [Fix] Pre-process content to handle common PowerShell escapes that break word boundaries
            content = ev['Summary'] + " " + str(ev.get('Detail', ''))
            content_clean = content.replace("`n", " ").replace("`t", " ").replace("`r", " ")
            
            # 1. IP Traces
            ips = re_ip.findall(content_clean)
            for ip in ips:
                if ip in infra_ips or ip.startswith("127."): 
                    self.infra_ips_found.add(ip); continue
                parts = ip.split('.')
                if len(parts) == 4:
                    try:
                        p1 = int(parts[0]); p2 = int(parts[1])
                        if p1 < 10 and ip != "1.1.1.1" and ip != "8.8.8.8" and ip != "8.8.4.4": continue 
                    except: continue
                
                # [Context Boost] Add note if found in a hosts-related event
                is_hosts_context = "HOSTS" in str(ev.get('Tag', '')).upper()
                note = f"Detected in {ev['Source']}"
                if is_hosts_context:
                    note = f"📍 Extracted from suspected Hosts modification ({ev['Source']})"

                self._add_unique_visual_ioc({
                    "Type": "IP_TRACE", "Value": ip, "Path": "Network", 
                    "Note": note, "Score": 400 if is_hosts_context else 300, "Tag": "IP_IOC"
                })

            # 2. Domain Traces (Automated Extraction)
            # Use content_clean to avoid `twww.domain.com
            domains = re_domain.findall(content_clean)
            for domain in domains:
                domain = domain.strip()
                dom_lower = domain.lower()
                
                # Skip noise/system infrastructure
                if any(x in dom_lower for x in ["microsoft.com", "windows.com", "bing.com", "localhost"]): continue
                
                is_hosts_context = "HOSTS" in str(ev.get('Tag', '')).upper()
                note = f"Detected in {ev['Source']}"
                if is_hosts_context:
                    note = f"🌐 Extracted from suspected Hosts modification ({ev['Source']})"

                self._add_unique_visual_ioc({
                    "Type": "DOMAIN_TRACE", "Value": domain, "Path": "Network",
                    "Note": note, "Score": 400 if is_hosts_context else 300, "Tag": "DOMAIN_IOC"
                })
            
            is_dual = self.intel.is_dual_use(ev.get('Summary', ''))
            tag = str(ev.get('Tag', '')).upper()
            summary_lower = str(ev.get('Summary', '')).lower()
            category = str(ev.get('Category', '')).upper()  # [FIX v6.7] Handle None
            
            is_af = "ANTI_FORENSICS" in tag or "ANTIFORENSICS" in tag or "TIMESTOMP" in tag or "HOSTS" in tag
            is_remote = "REMOTE_ACCESS" in tag or "SSH" in tag or "putty" in summary_lower or "winscp" in summary_lower
            is_lateral = "LATERAL" in tag or category == "LATERAL" or "\\\\" in summary_lower
            is_webshell = "WEBSHELL" in tag or "OBFUSCATION" in tag
            score_val = ev.get('Score') or ev.get('Criticality', 0)
            score = int(float(score_val))

            allowed_cats = ['EXEC', 'ANTI', 'FILE', 'LATERAL', 'PERSIST', 'EXECUTION', 'LOG_ENTRY', 'ARTIFACT_WRITE']
            
            if (score >= 90 or is_dual or is_af or is_webshell or is_remote or is_lateral) and ( any(c in category for c in allowed_cats) or "CRITICAL" in tag):
                kws = ev.get('Keywords', [])
                if not kws:
                     tgt = ev.get('Target_Path') or ev.get('FileName') or ev.get('Summary')
                     if tgt: kws = [tgt]

                if kws:
                    kw = str(kws[0]).lower()
                    is_crit_bypass = "TIMESTOMP" in tag or "REMOTE_ACCESS" in tag or "CRITICAL" in tag
                    
                    if is_crit_bypass or not self.intel.is_noise(kw):
                        if is_af:
                            type_label = "ANTI_FORENSICS"
                            reason_label = "Evidence Destruction"
                        elif is_remote:
                            type_label = "REMOTE_ACCESS"
                            reason_label = "Remote Access Tool"
                        elif is_webshell:
                            type_label = "WEBSHELL"
                            reason_label = "WebShell / Obfuscation"
                        elif is_lateral:
                            type_label = "LATERAL_MOVEMENT"
                            reason_label = "Lateral Movement"
                        elif "PERSIST" in tag or ev['Category'] == "PERSIST":
                            type_label = "PERSISTENCE"
                            reason_label = "Persistence Mechanism"
                        elif "VULN" in tag:
                            type_label = "VULNERABLE_APP"
                            reason_label = "Vulnerable Application"
                        else:
                            type_label = "EXECUTION"
                            reason_label = "Execution"

                        # [Implementation: Display Decoupling]
                        # Disconnect raw evidence (for storage) from display value (for report)
                        raw_summary = ev.get('Summary', '')
                        raw_val = str(kws[0]) if kws else raw_summary
                        
                        # Apply heavy cleaning for JSON/Scripts
                        if "{" in raw_val or "}" in raw_val:
                            cleaned_val = self._clean_json_garbage(raw_val)
                            # If it's still too messy or leaked through
                            if len(cleaned_val) > 200 or "{" in cleaned_val:
                                cleaned_val = self._clean_json_garbage(raw_summary)
                        else:
                            cleaned_val = raw_val

                        # Final safety cap for the Analyzer stage
                        if len(cleaned_val) > 300:
                            cleaned_val = cleaned_val[:300] + "..."

                        self._add_unique_visual_ioc({
                            "Type": type_label, 
                            "Value": cleaned_val, # Decoupled display value 
                            "Path": "Process" if type_label=="EXECUTION" else "File", 
                            "Note": f"{reason_label} ({ev['Source']})",
                            "Reason": reason_label,
                            # [FIX] Use raw time (events usually have it normalized)
                            "Time": ev.get('Time'),
                            "Score": score,
                            "Tag": tag,
                            "Summary": self._clean_json_garbage(raw_summary),
                            "FileName": ev.get('FileName'),
                            "Target_FileName": ev.get('Target_FileName'),
                            "Target_Path": ev.get('Target_Path'),
                            "Action": ev.get('Action'),
                            "Payload": ev.get('Payload'),
                            "Reg_Key": ev.get('Reg_Key'),
                            "CommandLine": ev.get('CommandLine')
                        })

    def _add_unique_visual_ioc(self, ioc_dict):
        tag = str(ioc_dict.get("Tag", "")).upper()
        path = str(ioc_dict.get("Path", "")).upper()
        val = str(ioc_dict.get("Value", ""))
        val_lower = val.lower()
        
        # [v6.9] Semantic Value Override - Transform raw values into human-readable labels
        # Store original value in Payload for evidence preservation
        original_value = val
        
        # 1. Defender Tampering - Extract actual command from JSON or Action field
        if "DEFENDER_DISABLE" in tag:
            extracted_cmd = None
            source_path = None
            source_field = str(ioc_dict.get("Source", ""))
            action_field = str(ioc_dict.get("Action", ""))
            
            # [Case 10 Fix] ConsoleHost_history events have command in Action field primarily
            # Value field might have been overwritten with the path in _extract_visual_iocs_from_events
            if "history" in source_field.lower():
                # Use Action field if available, otherwise fallback to Value
                cmd_candidate = action_field if action_field and len(action_field) > 5 else val
                if cmd_candidate and not cmd_candidate.startswith("{"):
                    extracted_cmd = cmd_candidate[:500]
                    source_path = str(ioc_dict.get("Target_Path", ""))
                
            # For ScriptBlock events, try to parse JSON from Value
            elif val.startswith("{"):
                try:
                    data = json.loads(val)
                    if "EventData" in data and "Data" in data["EventData"]:
                        for item in data["EventData"]["Data"]:
                            if isinstance(item, dict):
                                name = item.get("@Name", "")
                                text = str(item.get("#text", ""))
                                if name == "Path" and text:
                                    source_path = text
                                elif name == "ScriptBlockText" and text:
                                    # Handle both real newlines and escaped newlines
                                    text_norm = text.replace("\\n", "\n").replace("\\r", "\r")
                                    # Search for actual Defender commands
                                    patterns = [
                                        r'Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true',
                                        r'Set-MpPreference\s+-ExclusionPath',
                                        r'Add-MpPreference\s+-ExclusionPath',
                                        r'-DisableRealtimeMonitoring\s+\$true',
                                    ]
                                    for pattern in patterns:
                                        match = re.search(pattern, text_norm, re.IGNORECASE)
                                        if match:
                                            # Get surrounding context (40 chars before, 60 after)
                                            start = max(0, match.start() - 40)
                                            end = min(len(text_norm), match.end() + 60)
                                            extracted_cmd = text_norm[start:end].strip()[:200]
                                            break
                                    # Fallback: show first mppreference occurrence with context
                                    if not extracted_cmd and "mppreference" in text_norm.lower():
                                        idx = text_norm.lower().find("mppreference")
                                        if idx >= 0:
                                            start = max(0, idx - 20)
                                            end = min(len(text_norm), idx + 100)
                                            extracted_cmd = text_norm[start:end].strip()[:200]
                except:
                    pass
            
            # Build Payload with both command and source
            if extracted_cmd:
                payload = extracted_cmd
                if source_path:
                    payload = f"Source: {source_path}\nCommand: {extracted_cmd}"
                ioc_dict["Payload"] = payload
            elif source_path:
                ioc_dict["Payload"] = f"Source: {source_path}"
            else:
                ioc_dict["Payload"] = original_value
            ioc_dict["Value"] = "🛡️ Defender Tampering (Realtime Disable)"
        
        # 2. Hosts File Modification - Dynamic Labeling to prevent duplication loss
        elif "HOSTS_FILE_MODIFICATION" in tag:
            source_field = str(ioc_dict.get("Source", ""))
            action_field = str(ioc_dict.get("Action", ""))
            
            # [Fix] Extract specific value for dynamic labeling
            label_val = ""
            # Priority: Action field (raw command) > original_value (summarized)
            cmd_candidate = action_field if action_field and len(action_field) > 5 else original_value
            
            # Improved Regex: Capture IP or Domain, allowing for surrounding delimiters like \t or \n
            match = re.search(r'((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.(?:local|com|net|org))', cmd_candidate)
            if match: 
                extracted = match.group(1).strip()
                label_val = f": {extracted}"
            
            if "history" in source_field.lower():
                target_path = str(ioc_dict.get("Target_Path", ""))
                if target_path:
                    ioc_dict["Payload"] = f"Source: {target_path}\nCommand: {cmd_candidate}"
                else:
                    ioc_dict["Payload"] = cmd_candidate
            else:
                ioc_dict["Payload"] = original_value
            
            # Decouple Display Value - Dynamic Label prevents O(1) deduplication
            ioc_dict["Value"] = f"📝 Hosts Change{label_val}"
        
        # 3. A: Drive / Phantom Drive - Generalized keyword-based labeling
        # [FIX v6.9.1] Removed hardcoded filenames, using keyword patterns instead
        elif val.startswith("A:\\") or val.startswith("A:/") or "A:\\\\" in val:
            ioc_dict["Payload"] = original_value
            
            # Extract filename for display
            fname = val.split("\\")[-1] if "\\" in val else val.split("/")[-1]
            
            # Keyword-based generalized labeling (no hardcoded filenames)
            if any(kw in val_lower for kw in ["update", "patch", "upgrade"]):
                label = "🚨 Fake Update Suspicion"
            elif any(kw in val_lower for kw in ["setup", "install", "provision", "deploy"]):
                label = "🔧 Attack Tooling Setup"
            elif any(kw in val_lower for kw in ["winrm", "remote", "ssh", "psexec", "wmi"]):
                label = "🌐 Remote Access Setup"
            elif any(kw in val_lower for kw in ["persist", "autologon", "startup", "schedule"]):
                label = "🔁 Persistence Mechanism"
            else:
                label = "💾 Phantom Drive Execution"
            
            ioc_dict["Value"] = f"{label} ({fname})"
        
        is_critical = "TIMESTOMP" in tag or "CRITICAL" in tag or "REMOTE_ACCESS" in tag or "LATERAL" in tag
        is_critical = is_critical or "SETMACE" in path or "PUTTY" in path

        # [Fix] Check Force Include BEFORE Noise Check
        if not self.is_force_include_ioc(ioc_dict):
             if self._is_noise(ioc_dict): return
        
        # [OPTIMIZATION] O(1) Hash Check
        ioc_key = (ioc_dict.get("Value"), ioc_dict.get("Type"))
        if ioc_key in self.visual_iocs_hashes: return
        
        self.visual_iocs_hashes.add(ioc_key)
        
        if is_critical or "setmace" in path.lower():
             # [PERFORMANCE FIX] Removed file I/O logging to prevent 78s stall
             pass
                 
        self.visual_iocs.append(ioc_dict)

    def _generate_pivot_seeds(self):
        # CRITICAL_RECON patterns for Browser/SRUM artifacts
        RECON_PATTERNS = [
            "history", "srudb.dat", "webcache", "places.sqlite", 
            "cookies.sqlite", "favicons.sqlite", "formhistory.sqlite"
        ]
        PHISHING_PATTERNS = [
            "attachment", "invoice", "receipt", "urgent", "payment",
            ".hta", ".js", ".vbs", ".wsf", ".scr", "downloads\\"
        ]
        
        for ioc in self.visual_iocs:
            val_lower = str(ioc.get("Value", "")).lower()
            path_lower = str(ioc.get("Path", "")).lower()
            tag = str(ioc.get("Tag", "")).upper()
            ioc_type = str(ioc.get("Type", "")).upper()
            combined = val_lower + path_lower
            
            # Determine category
            category = "GENERAL"
            if any(p in combined for p in RECON_PATTERNS):
                category = "CRITICAL_RECON"
            elif any(p in combined for p in PHISHING_PATTERNS) or "PHISHING" in tag or "PHISHING" in ioc_type:
                category = "CRITICAL_PHISHING"
            elif "ANTI_FORENSICS" in ioc_type or "TIMESTOMP" in ioc_type:
                category = "CRITICAL_ANTI_FORENSICS"
            elif "LATERAL" in tag or "UNC_" in ioc_type:
                category = "CRITICAL_LATERAL"
            
            self.pivot_seeds.append({
                "Category": category,
                "Target_File": ioc["Value"],
                "Target_Path": ioc.get("Path", ""),
                "Reason": ioc.get("Reason", ioc["Type"]),
                "Timestamp_Hint": ioc.get("Time", "")
            })

    def is_force_include_ioc(self, ioc):
        force_keywords = [
            "TIME_PARADOX", "CRITICAL_MASQUERADE", "CRITICAL_PHISHING", 
            "SUSPICIOUS_CMDLINE", "CRITICAL_SIGMA", "ROLLBACK", "BACKDOOR",
            "SAM_SCAVENGE", "NEW_USER_CREATED"
        ]
        ioc_type = str(ioc.get('Type', '')).upper()
        reason = str(ioc.get('Reason', '')).upper()
        tag = str(ioc.get('Tag', '')).upper()
        
        if any(k in ioc_type for k in force_keywords):
            return True
        if any(k in reason for k in force_keywords):
            return True
        if any(k in tag for k in force_keywords):
            return True
        # [Case 6] Force Include 7za even if filtered
        if "7za" in str(ioc.get('Value','')).lower():
            return True
        if "DUAL-USE" in reason or "DUAL_USE" in ioc_type:
            return True
        if "TIMESTOMP" in ioc_type:
            # [Case 6 Noise Fix] STRICT TIMESTOMP FILTERING
            # Rule 1: Discard low confidence (Score <= 500)
            score = int(ioc.get('Score', 0) or 0)
            if score > 500 or "CRITICAL" in tag:
                return True
                
            # Rule 2: Exception (Safety Net)
            # Even if low score, KEEP if in suspicious path or high-risk extension
            path_lower = str(ioc.get("Path", "")).lower()
            val_lower = str(ioc.get("Value", "")).lower()
            
            # A. Path-based Rescue (Temp/Downloads)
            # Fix: Raw strings cannot end with odd backslashes
            suspicious_paths = ["\\downloads\\", "\\temp\\", "appdata\\local\\temp"]
            if any(x in path_lower for x in suspicious_paths):
                return True
                

                
            # [Case 6 Noise Fix] STRICT NOISE FILTER (Killer Rule)
            # Unified Regex for Windows Diagnostics, Chocolatey, Pester Tests, and App/Infra Noise
            fn_lower = val_lower.split("\\")[-1]
            
            # 1. Script Noise (PS1)
            ps1_noise = r"(?i)^((rs|ts|rc|cl|vf|mf)_.*\.ps1$|.*chocolatey.*\.ps1$|.*\.tests\.ps1$|^(describe|mock|should|context|pester.*)\.ps1$)"
            
            # 2. App/Infra Noise (Executables & Sys)
            app_noise = r"(?i)^(googleupdate.*|chrome|chrmstp|notification_helper|onedrive.*|filecoauth|msmpeng|mpcmdrun|nissrv|shimgen|checksum)\.exe$"
            sys_noise = r"(?i)^(pagefile|swapfile|wd(boot|filter|nisdrv))\.sys$"
            cmd_noise = r"(?i)^(collectsynclogs|onedrivepersonal)\.(bat|cmd)$"
            misc_noise = r"(?i).*\.(ignore|manifest)$"
            
            if re.match(ps1_noise, fn_lower) or re.match(app_noise, fn_lower) or re.match(sys_noise, fn_lower) or re.match(cmd_noise, fn_lower) or re.match(misc_noise, fn_lower):
                 # EXCEPT if in Temp/Downloads (handled above by Path-based Rescue which runs first)
                 # Double check: if Path Rescue didn't trigger, these are in system/safe paths -> KILL
                 return False

            # B. Extension-based Rescue (Scripts)
            target_exts = [".ps1", ".bat", ".cmd", ".vbs", ".js", ".rb", ".py", ".sh"]
            if any(val_lower.endswith(x) for x in target_exts):
                return True
                
            return False  # Discard (Noise)
            
        return False
    
    def generate_ioc_insight(self, ioc):
        """
        [v3.0 REFACTORED] Delegate to InsightGenerator.
        Maintains backward compatibility with existing callers.
        """
        return self._insight_generator.generate(ioc)

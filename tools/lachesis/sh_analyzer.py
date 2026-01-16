import re
import os
import polars as pl
from datetime import datetime, timedelta
from tools.lachesis.intel import TEXT_RES
# [NEW] Correlatorをインポート
from tools.lachesis.correlator import CrossCorrelationEngine

# Threat patterns: boost score (always prioritized)
THREAT_BOOST_PATTERNS = [
    ("setmace", 300, "CRITICAL_TIMESTOMP"),
    ("sdelete", 300, "ANTI_FORENSICS"),      
    ("psexec", 250, "LATERAL_MOVEMENT"),
    ("putty", 300, "REMOTE_ACCESS"),
    ("mimikatz", 500, "CREDENTIAL_THEFT"),
    ("procdump", 150, "CREDENTIAL_DUMP"),
    ("\\\\\\\\", 150, "UNC_EXECUTION"),
    ("dd.exe", 900, "DATA_EXFIL_TOOL"),           
    ("cipher.exe$", 600, "WIPING_TOOL"),          
    ("bcwipe", 600, "WIPING_TOOL"),
    ("vssadmin.exe$", 600, "SHADOW_COPY_KILLER"), 
    ("wbadmin.exe$", 600, "BACKUP_DESTRUCTION"),  
    ("attributedialog", 800, "ADS_CREATION"),
    
    # [Fix] Webshell Critical Boosting
    ("c99", 800, "CRITICAL_WEBSHELL"),
    ("webshell", 800, "CRITICAL_WEBSHELL"),
    ("phpshell", 800, "CRITICAL_WEBSHELL"),
    ("b374k", 800, "CRITICAL_WEBSHELL"),
    ("r57", 800, "CRITICAL_WEBSHELL"),
    
    # [Feature 3] UNC Lateral Movement Tools
    # [Fix] Admin Tool Tuning (Base Score Lowered, Context Boosted via adjust_score)
    ("robocopy.exe", 50, "FILE_COPY_TOOL"),
    ("xcopy.exe", 50, "FILE_COPY_TOOL"),
    ("dcode", 400, "FORENSIC_TOOL"),
    ("wmic.exe", 50, "WMI_EXECUTION"),
    # [FIX] Refine "sync" to avoid OneDrive/SettingsSync noise
    ("sync.exe", 300, "SYSINTERNALS_SYNC"),
    ("sync64.exe", 300, "SYSINTERNALS_SYNC"),
    ("ssh-add", 900, "DATA_EXFIL"),
]


# [Feature 3] UNC Lateral Movement Tool Patterns
UNC_LATERAL_TOOLS = [
    "dcode", "robocopy", "xcopy", "psexec", "wmic", "sync",
    "dcode", "robocopy", "xcopy", "psexec", "wmic", "sync",
    "bcwipe",
    "dd.exe", "putty", "plink", "ssh"
]

# [PUBLIC] Garbage Patterns
GARBAGE_PATTERNS = [
    r"windows\winsxs", 
    r"windows\assembly", 
    r"windows\microsoft.net", 
    r"windows\servicing",
    r"windows\systemapps",
    r"windows\inf",
    r"windows\driverstore",
    r"driverstore", 
    r"windows\diagtrack",
    r"windows\biometry",
    r"windows\softwaredistribution",
    r"program files\windowsapps",
    r"windowsapps", 
    r"deletedalluserpackages",
    r"\apprepository",
    r"\contentdeliverymanager",
    r"\infusedapps",
    r"system32\driverstore" 
]

class LachesisAnalyzer:
    def __init__(self, intel_module, enricher_module, lang="jp"):
        self.intel = intel_module
        self.enricher = enricher_module
        self.lang = lang
        self.txt = TEXT_RES[self.lang if self.lang in TEXT_RES else "jp"]
        self.visual_iocs = []
        self.visual_iocs_hashes = set() # [OPTIMIZATION] O(1) Lookup
        self.pivot_seeds = []
        self.infra_ips_found = set()
        self.noise_stats = {}
        self.total_events_analyzed = 0
        self.dynamic_verdict = None
        
        context_scoring = self.intel.get('context_scoring', {})
        self.path_penalties = context_scoring.get('path_penalties', [])

    @staticmethod
    def adjust_score(path: str, base_score: int, penalties=None, command_line: str = "") -> tuple:
        adjusted = base_score
        tags = []
        path_lower = path.lower() if path else ""
        
        SENSITIVE_KEYWORDS = [
            "password", "secret", "confidential", "credentials", "login", 
            "shadow", "kimitachi", "topsecret", "機密", "社外秘", "pass.txt"
        ]
        
        filename = path_lower.split("\\")[-1]
        
        if any(k in filename for k in SENSITIVE_KEYWORDS):
            adjusted = max(adjusted, 800)
            tags.append("SENSITIVE_DATA_ACCESS")
        
        if penalties is None:
            penalties = [] 

        for rule in penalties:
            p_pat = rule.get('path', '')
            p_val = int(rule.get('penalty', 0))
            if p_pat and p_pat in path_lower:
                adjusted = max(0, adjusted + p_val)
                tags.append("SYSTEM_NOISE")
                break 
        
        for pattern, boost, tag in THREAT_BOOST_PATTERNS:
            if pattern in path_lower:
                adjusted += boost
                tags.append(tag)
        
        # [Case 7] Masquerade Detection Logic
        filename = path_lower.split("\\")[-1]
        
        # 1. Fake SysInternals (sysinternals.exe does not exist)
        if filename == "sysinternals.exe":
            adjusted = max(adjusted, 600)
            tags.append("CRITICAL_MASQUERADE")
            tags.append("FAKE_TOOL_NAME")
            
        # 2. Suspicious System Binary Location (vmtoolsio.exe in Windows root)
        if filename == "vmtoolsio.exe":
            if "program files" not in path_lower and "system32" not in path_lower:
                adjusted = max(adjusted, 600)
                tags.append("SUSPICIOUS_LOCATION")
                tags.append("PERSISTENCE_CANDIDATE")

        # 3. Security Tools in Temp/Downloads (Wireshark, Fiddler, ProcExp)
        masq_tools = ["procexp", "procmon", "wireshark", "fiddler", "tcpview", "autoruns"]
        suspicious_dirs = ["downloads", "temp", "users\\public"]
        
        for tool in masq_tools:
            if tool in filename:
                if any(sdir in path_lower for sdir in suspicious_dirs):
                    adjusted = max(adjusted, 500)
                    tags.append("SECURITY_TOOL_IN_USER_PATH")

        # [User Request] Bonus for Suspicious Extensions in User Paths
        # .lnk, .crx, .jar in Downloads/Desktop -> +200 Score
        # This highlights potential Initial Access vectors or dropped tools.
        target_exts = [".lnk", ".crx", ".jar"]
        target_dirs = ["downloads", "desktop"]

        if any(filename.endswith(ext) for ext in target_exts):
             # Ensure we don't boost legitimate shortcuts in Start Menu (which might have 'desktop' in path rarely, but usually not)
             # But here we look for "downloads" or "desktop" string in path.
             if any(tdir in path_lower for tdir in target_dirs):
                 adjusted += 200
                 tags.append("SUSPICIOUS_USER_DOWNLOAD")

        # [Case 6] Context-Aware Tool Scoring
        # Prevent legitimate admin tools from flooding the timeline unless suspicious
        cmd_lower = command_line.lower() if command_line else ""
        
        # Robocopy / Xcopy
        if "robocopy" in filename or "xcopy" in filename:
            # Boost only if sensitive/network paths involved
            if "admin$" in cmd_lower or "c$" in cmd_lower or "\\\\" in cmd_lower:
                adjusted = max(adjusted, 450)
                tags.append("LATERAL_MOVEMENT_COPY")
            if "backup" in cmd_lower or "archive" in cmd_lower:
                adjusted = max(adjusted, 100) # Slightly higher but not critical
                tags.append("BACKUP_ACTIVITY")

        # WMIC
        if "wmic" in filename:
            if "process call create" in cmd_lower or "shadowcopy" in cmd_lower or "/node:" in cmd_lower:
                adjusted = max(adjusted, 500)
                tags.append("SUSPICIOUS_WMI")
                if "shadowcopy" in cmd_lower: tags.append("SHADOW_COPY_TAMPERING")

        
        # [Final Noise Tuning] WinRM System Path Context Logic
        if "winrm" in filename:
            # If in System32/SysWOW64 and NO suspicious args -> Low Score
            is_system_path = "system32" in path_lower or "syswow64" in path_lower
            is_suspicious_arg = "http" in cmd_lower or "invoke" in cmd_lower or "-r" in cmd_lower
            
            if is_system_path and not is_suspicious_arg:
                 # Likely Windows Update or Service Activity
                 adjusted = min(adjusted, 40) 
                 tags.append("WINRM_SYSTEM_SERVICE")

        # ═══════════════════════════════════════════════════════════
        # [Noise Reduction v2] Explicit Noise Filter (Tagging Strategy)
        # ═══════════════════════════════════════════════════════════
        
        # A. Path-based Noise Tagging
        noise_paths = [
            "programdata\\chocolatey", "programdata\\microsoft\\windows defender",
            "appdata\\local\\google\\chrome", "appdata\\local\\microsoft\\onedrive",
            "windows\\diagnostics", "windows\\servicing",
            "program files\\windowsapps", "windows\\systemapps",
            "program files\\microsoft", "program files (x86)\\microsoft"
        ]
        if any(np in path_lower for np in noise_paths):
            tags.append("SYSTEM_NOISE")
            # Special Handling for Windows Temp (only if filename is also noisy)
            # but user said 'Windows\Temp' is NOT bulk noise. So we rely on Filename whitelist below.

        # B. Filename-based Whitelist (Regex)
        noise_filename_patterns = [
            r"^\.tmp$", r"^googlecrashhandler.*", r"^shapecollector.*", r"^tabtip.*",
            r"^mpcmdrun\.exe", r"^msmpeng\.exe", r"^conhost\.exe", r"^searchindexer\.exe", r"^dllhost\.exe"
        ]
        if any(re.match(fp, filename, re.IGNORECASE) for fp in noise_filename_patterns):
             tags.append("SYSTEM_NOISE")

        # C. TIMESTOMP Tuning (Logic from User)
        # Chocolatey related -> specific downscore
        if "chocolatey" in path_lower:
            adjusted = 100
            if "SYSTEM_NOISE" not in tags: tags.append("SYSTEM_NOISE")
        
        # Diagnostic .ps1 -> specific downscore
        if filename.endswith(".ps1") and "diagnostics" in path_lower:
            adjusted = 100
            if "SYSTEM_NOISE" not in tags: tags.append("SYSTEM_NOISE")

        # ═══════════════════════════════════════════════════════════

        # [Final Noise Tuning] Sync Tool Dampening (msfeedssync, mobsync, cipher)
        # Prevents these from being flagged as TIMESTOMP unless score is very high
        sync_tools = ["msfeedssync.exe", "mobsync.exe", "tzsync.exe", "cipher.exe", "microsoft.uev.synccontroller.exe"]
        if filename in sync_tools:
             is_system_path = "system32" in path_lower or "syswow64" in path_lower
             # If no suspicious args/paths, force score low to fail TIMESTOMP filter
             if is_system_path:
                 adjusted = min(adjusted, 250) 
                 tags.append("SYSTEM_SYNC_PROCESS")

        # [User Request] LOLBins Context Bonus (Post-Dampening Boost)
        # robocopy, xcopy, cipher, vssadmin, bitsadmin
        # If suspicious args or location -> +300 Score (Overrides dampening)
        target_lolbins = ["robocopy", "xcopy", "cipher", "vssadmin", "bitsadmin"]
        suspicious_args = ["/wipe", "shadow", "transfer", "download", "upload", "-r", "job"]

        if any(bin_name in filename for bin_name in target_lolbins):
            is_suspicious_context = False
            
            # 1. Args Check
            if any(arg in cmd_lower for arg in suspicious_args):
                is_suspicious_context = True
                tags.append("SUSPICIOUS_ARGS")
                
            # 2. Users Dir Check (excluding system32 to avoid FP on admins running tools)
            if "users" in path_lower and "system32" not in path_lower: 
                 is_suspicious_context = True
                 tags.append("LOLBIN_IN_USER_PATH")
                 
            # Apply Bonus
            if is_suspicious_context:
                adjusted += 300
                tags.append("CONTEXT_BOOST_HIGH")
        
        # [Final Noise Tuning] Puppet/Ruby Test File Filter
        if "test" in path_lower or "vendor" in path_lower:
            if "callback" in filename or "indent" in filename:
                adjusted = min(adjusted, 50) # Reduce from 300 -> 50
                tags.append("DEV_TEST_FILE")
        
        return adjusted, tags

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

        for trash in GARBAGE_PATTERNS:
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

    def process_events(self, analysis_result, dfs):
        raw_events = analysis_result.get("events", [])
        self.total_events_analyzed = len(raw_events)
        self.noise_stats = self.intel.noise_stats 
        
        high_crit_times = []
        critical_events = []
        medium_events = []

        for ev in raw_events:
            try: score = int(float(ev.get('Criticality', 0)))
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
        print(f"[DEBUG-ANALYZER] Visual IOCs after Timeline: {len(self.visual_iocs)}")
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
        # [Feature] SRUM High Heat Extraction
        srum_df = dfs.get('Plutos_Srum')
        if srum_df is None: return

        for row in srum_df.iter_rows(named=True):
             proc = row.get('App_Name', '') or row.get('Process', '')
             if not proc: continue
             
             bytes_sent = int(row.get('Bytes_Sent', 0) or 0)
             # Threshold: 1MB sent
             if bytes_sent > 1000000:
                  mb_sent = bytes_sent // 1024 // 1024
                  self._add_unique_visual_ioc({
                      "Type": "SRUM_HIGH_HEAT",
                      "Value": f"Proc: {proc}<br>Sent: {mb_sent} MB",
                      "Path": "SRUM Database",
                      "Time": self._get_best_timestamp(row),
                      "Score": 500, # High Score
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
                score = int(row.get("Score", 0))
                
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
        if dfs.get('Chronos') is not None:
            df = dfs['Chronos']
            cols = df.columns
            score_col = "Chronos_Score" if "Chronos_Score" in cols else "Threat_Score"
            if score_col in cols:
                try:
                    df_sorted = df.sort(score_col, descending=True)
                    for row in df_sorted.iter_rows(named=True):
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
                                # [FIX] Use best timestamp
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
                             if "False Positive" in bypass_reason or "NOISE" in bypass_reason: continue
                        elif score < 200: continue 
                        
                        if not bypass_reason: bypass_reason = "High Score (>200)"
                        self._add_unique_visual_ioc({
                            "Type": "TIMESTOMP", "Value": fname, "Path": path, "Note": "Time Anomaly", 
                            # [FIX] Use best timestamp
                            "Time": self._get_best_timestamp(row),
                            "Reason": bypass_reason, 
                            "Score": score,
                            "Extra": extra_info,
                            "FileName": fname, 
                            "Action": "Timestomp Detected" 
                        })
                except: pass

    def _extract_visual_iocs_from_pandora(self, dfs):
        if dfs.get('Pandora') is not None:
            df = dfs['Pandora']
            timeline_df = dfs.get('Timeline') 
            
            if "Threat_Score" in df.columns:
                try:
                    SYSTEM_NOISE_PATHS = [
                        "winsxs", "assembly", "servicing", "manifests", 
                        "catalogs", "driverstore", "installer"
                    ]
                    
                    for i, row in enumerate(df.iter_rows(named=True)):
                        fname = row.get("Ghost_FileName", "")
                        path = row.get("ParentPath", "")
                        tag = str(row.get("Threat_Tag", "")).upper()
                        score = int(float(row.get("Threat_Score", 0)))
                        
                        path_lower = str(path).lower()
                        fname_lower = str(fname).lower()

                        if "TIMESTOMP" in tag or "REMOTE_ACCESS" in tag or "setmace" in path_lower or "putty" in fname_lower:
                             with open("pipeline_trace.log", "a") as f:
                                 f.write(f"[ANALYZER] Found: {fname} Path={path} Score={score} Tag={tag}\n")
                        
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
                        
                        if any(noise in path_lower for noise in SYSTEM_NOISE_PATHS): continue

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

                        elif self.intel.is_dual_use(fname): bypass_reason = "Dual-Use Tool [DROP]"
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
                            # [FIX] Use best timestamp
                            "Time": self._get_best_timestamp(row),
                            "Reason": bypass_reason,
                            "Extra": extra_info,
                            "Score": score,
                            "FileName": fname,
                            "Target_Path": path,
                            "Tag": final_tag
                        })
                except Exception as e:
                     print(f"[ERROR] Pandora IOC Extract Failed: {e} | Row: {row.get('Ghost_FileName')}")
                     import traceback
                     traceback.print_exc()

    def _extract_visual_iocs_from_aion(self, dfs):
         if dfs.get('AION') is not None:
            df = dfs['AION']
            if "AION_Score" in df.columns:
                try:
                    for row in df.iter_rows(named=True):
                        try: score = int(float(row.get("AION_Score", 0)))
                        except: score = 0
                        if score >= 50:
                            name = row.get("Target_FileName")
                            tags = str(row.get("AION_Tags", ""))
                            is_scavenge = "SAM_SCAVENGE" in tags
                            
                            if is_scavenge:
                                if score < 150: continue
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
                                    # [FIX] Use best timestamp
                                    "Time": self._get_best_timestamp(row),
                                    "Reason": "Persistence",
                                    "Tag": tags,
                                    "Score": score,
                                    "Target_FileName": name,
                                    "Target_Path": path_str
                                })
                except: pass
                
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
        re_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        infra_ips = self.intel.infra_ips
        if not infra_ips:
            infra_ips = {"10.0.2.15", "10.0.2.2", "127.0.0.1", "0.0.0.0", "::1"} 
        for ev in events:
            content = ev['Summary'] + " " + str(ev.get('Detail', ''))
            ips = re_ip.findall(content)
            for ip in ips:
                if ip in infra_ips or ip.startswith("127."): 
                    self.infra_ips_found.add(ip); continue
                parts = ip.split('.')
                if len(parts) == 4:
                    try:
                        p1 = int(parts[0]); p2 = int(parts[1])
                        if p1 < 10 and ip != "1.1.1.1" and ip != "8.8.8.8" and ip != "8.8.4.4": continue 
                    except: continue
                self._add_unique_visual_ioc({
                    "Type": "IP_TRACE", "Value": ip, "Path": "Network", "Note": f"Detected in {ev['Source']}"
                })
            
            is_dual = self.intel.is_dual_use(ev.get('Summary', ''))
            tag = str(ev.get('Tag', '')).upper()
            summary_lower = str(ev.get('Summary', '')).lower()
            
            is_af = "ANTI_FORENSICS" in tag or "ANTIFORENSICS" in tag or "TIMESTOMP" in tag
            is_remote = "REMOTE_ACCESS" in tag or "SSH" in tag or "putty" in summary_lower or "winscp" in summary_lower
            is_lateral = "LATERAL" in tag or ev['Category'].upper() == "LATERAL" or "\\\\" in summary_lower
            is_webshell = "WEBSHELL" in tag or "OBFUSCATION" in tag
            score = ev.get('Criticality', 0)

            allowed_cats = ['EXEC', 'ANTI', 'FILE', 'LATERAL', 'PERSIST', 'EXECUTION', 'LOG_ENTRY', 'ARTIFACT_WRITE']
            
            if (score >= 90 or is_dual or is_af or is_webshell or is_remote or is_lateral) and ( any(c in ev['Category'].upper() for c in allowed_cats) or "CRITICAL" in tag):
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

                        self._add_unique_visual_ioc({
                            "Type": type_label, "Value": kws[0], "Path": "Process" if type_label=="EXECUTION" else "File", 
                            "Note": f"{reason_label} ({ev['Source']})",
                            "Reason": reason_label,
                            # [FIX] Use raw time (events usually have it normalized)
                            "Time": ev.get('Time'),
                            "Score": score,
                            "Tag": tag,
                            "Summary": ev.get('Summary', ''),
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
        is_critical = "TIMESTOMP" in tag or "CRITICAL" in tag or "REMOTE_ACCESS" in tag or "LATERAL" in tag
        is_critical = is_critical or "SETMACE" in path or "PUTTY" in path

        if self._is_noise(ioc_dict): return
        
        # [OPTIMIZATION] O(1) Hash Check
        ioc_key = (ioc_dict.get("Value"), ioc_dict.get("Type"))
        if ioc_key in self.visual_iocs_hashes: return
        
        self.visual_iocs_hashes.add(ioc_key)
        
        if "downloads" in path.lower():
             print(f"[DEBUG-DL] Path={path} Val={ioc_dict['Value']} Tags={tag}")

        if is_critical or "setmace" in path.lower():
             # [PERFORMANCE FIX] Removed file I/O logging to prevent 78s stall
             # print(f"[DEBUG-ADD] Adding IOC: {ioc_dict['Value']} (Reason: {tag})")
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
        ioc_type = str(ioc.get('Type', '')).upper()
        tag = str(ioc.get('Tag', '')).upper()
        
        if "ANTI_FORENSICS" in ioc_type:
            return "🚨 **Evidence Destruction**: 証拠隠滅ツールです。実行回数やタイムスタンプを確認してください。"
        
        val = str(ioc.get('Value', ''))
        val_lower = val.lower()
        reason = str(ioc.get('Reason', '')).upper()
        path = str(ioc.get('Path', ''))
        
        if "SAM_SCAVENGE" in tag or "SAM_SCAVENGE" in ioc_type:
            insights = ["☠️ **Chain Scavenger Detection** (Dirty Hive Hunter)"]
            insights.append("- **Detection**: 破損または隠蔽されたSAMハイブから、バイナリレベルのカービングでユーザーアカウントを物理抽出しました。")
            
            if "[HEX:" in path:
                try:
                    hex_part = path.split("[HEX:")[1].split("]")[0].strip()
                    insights.append(f"- **Binary Context**: `{hex_part}`")
                except: pass

            if "hacker" in val_lower or "user" in val_lower:
                insights.append(f"- **Suspicion**: ユーザー名 `{val}` は典型的な攻撃用アカウントの命名パターンです。")
            insights.append("- **Action**: 即時にこのアカウントの作成日時周辺（イベントログ削除の痕跡がある場合はその直前）のタイムラインを確認してください。[LOG_WIPE_INDUCED_MISSING_EVENT]")
            return "\n".join(insights)

        if "WEBSHELL" in tag or "WEBSHELL" in ioc_type:
            insights = ["🕷️ **CRITICAL WebShell Detection**"]
            
            if "tmp" in val_lower and ".php" in val_lower:
                insights.append("- **Pattern**: `tmp*.php` - SQLインジェクション攻撃によって動的生成されたWebShellの典型的なファイル名です。")
                insights.append("- **Attack Vector**: 高確率で IIS/Apache への SQL Injection 経由のRCE (Remote Code Execution) です。")
            elif any(x in val_lower for x in ["c99", "r57", "b374k", "wso", "chopper"]):
                insights.append("- **Signature**: 既知のWebShellシグネチャ（China Chopper, c99, r57など）を検知しました。")
            else:
                insights.append("- **Detection**: Webサーバーディレクトリ内のスクリプトファイルを検知しました。")
            
            if "htdocs" in path.lower() or "wwwroot" in path.lower() or "inetpub" in path.lower():
                insights.append("- **Location**: Webルートディレクトリ内に配置 → 外部からのHTTPアクセス可能な状態です。")
            insights.append("- **Next Step**: IISログの同時刻リクエスト、w3wp.exe のプロセス履歴を即座に調査してください。")
            return "<br/>".join(insights)
        
        if "USER_CREATION" in tag or "PRIVILEGE_ESCALATION" in tag or "SAM_REGISTRY" in tag:
            insights = ["👤 **CRITICAL: User Creation/Privilege Escalation Detected**"]
            
            if "4720" in val or "user" in val_lower:
                insights.append("- **Event**: 新規ユーザーアカウントが作成されました (EID 4720)。")
            if "4732" in val or "4728" in val:
                insights.append("- **Event**: ユーザーがセキュリティグループに追加されました。")
            if "administrators" in val_lower:
                insights.append("- **Impact**: **Administrator権限の付与** - 最高権限の取得です。")
            if "remote" in val_lower and "desktop" in val_lower:
                insights.append("- **Impact**: **Remote Desktop Usersへの追加** - RDP経由の永続アクセスが可能になりました。")
            if "sam" in val_lower or "SAM" in tag:
                insights.append("- **Registry**: SAMレジストリへのアクセス - ローカルアカウント情報の操作が行われています。")
            
            insights.append("- **Next Step**: net user /domain で作成されたアカウントを確認、即座に無効化してください。")
            return "<br/>".join(insights)
        
        if "LOG_DELETION" in tag or "EVIDENCE_WIPING" in tag:
            insights = ["🗑️ **CRITICAL: Log Deletion/Evidence Wiping Detected**"]
            
            if "1102" in val:
                insights.append("- **Event**: Securityログがクリアされました (EID 1102)。")
            if "104" in val:
                insights.append("- **Event**: Systemログがクリアされました (EID 104)。")
            if "wevtutil" in val_lower or "clear-eventlog" in val_lower:
                insights.append("- **Tool**: イベントログ消去コマンドが実行されました。")
            if "clearev" in val_lower:
                insights.append("- **Tool**: Meterpreter clearevコマンド - 攻撃者がログを完全消去しようとしています。")
            if "usnjrnl" in val_lower or "mft" in val_lower:
                insights.append("- **Target**: ファイルシステムジャーナル ($USNJRNL/$MFT) の削除 - フォレンジック証拠の抹消です。")
            
            insights.append("- **Impact**: **アンチフォレンジック活動** - 攻撃者が活動痕跡を隠蔽しようとしています。")
            insights.append("- **Next Step**: バックアップログ、VSS (Volume Shadow Copy) からの復元を試みてください。")
            return "<br/>".join(insights)

        if "EXECUTION_CONFIRMED" in ioc_type:
            return "🚨 **Confirmed**: このツールは実際に実行された痕跡があります。調査優先度：高"
        
        elif "TIME_PARADOX" in ioc_type or "ROLLBACK" in reason:
            rb_sec = "Unknown"
            if "Rollback:" in val:
                match = re.search(r"Rollback:\s*(-?\d+)", val)
                if match: rb_sec = match.group(1)
            return f"USNジャーナルの整合性分析により、システム時刻の巻き戻し(約{rb_sec}秒)を検知しました。これは高度なアンチフォレンジック活動を示唆します。"
        
        elif "MASQUERADE" in ioc_type:
            is_sysinternals = "sysinternals" in val_lower or "procexp" in val_lower or "autoruns" in val_lower or "psexec" in val_lower or "procmon" in val_lower
            is_user_path = any(p in path.lower() for p in ["downloads", "public", "temp", "appdata"])
            
            if is_sysinternals or is_user_path:
                insights = ["🔧 **攻撃ツールセットの展開を検知**"]
                if is_sysinternals:
                    insights.append(f"- **Tool**: `{val}` は Sysinternalsツール群（または類似ツール）と推定されます。")
                if is_user_path:
                    insights.append(f"- **Location**: ユーザーパス (`{path}`) から実行 - 典型的な攻撃者の手法です。")
                insights.append("- **Intent**: 🎯 **Possible Hands-on-Keyboard Intrusion** (Short Burst Activity)")
                insights.append("- **Note**: 管理者のメンテナンス作業ではなく、攻撃者による手動探索の可能性が高いです。")
                return "<br/>".join(insights)
            
            elif ".crx" in val_lower:
                masq_app = "正規アプリケーション"
                if "adobe" in path.lower(): masq_app = "Adobe Reader"
                elif "microsoft" in path.lower(): masq_app = "Microsoft Office"
                elif "google" in path.lower(): masq_app = "Google Chrome"
                return f"{masq_app}のフォルダに、無関係なChrome拡張機能(.crx)が配置されています。これは典型的なPersistence（永続化）手法です。"
            else:
                return f"正規ファイル名を偽装した不審なファイル (`{val}`) を検知しました。マルウェアの可能性があります。"
        
        elif ".lnk" in val_lower and ("SUSPICIOUS" in ioc_type or "PHISHING" in ioc_type or "PS_" in ioc_type or "CMD_" in ioc_type or "MSHTA" in ioc_type):
            insights = []
            extra = ioc.get('Extra', {})
            target = extra.get('Target_Path', '')
            args = extra.get('Arguments', '')
            risk = extra.get('Risk', '')

            intel_desc = self.intel.match_intel(val)
            if intel_desc:
                insights.append(intel_desc)

            if not target:
                if "Target:" in val: target = val.split("Target:")[-1].strip()
                elif "🎯" in val: target = val.split("🎯")[-1].strip()
            
            if target:
                insights.append(f"🎯 **Target**: `{target}`")
                
                if "cmd.exe" in target.lower() or "powershell" in target.lower():
                     insights.append("⚠️ **Critical**: OS標準シェルを悪用した攻撃の起点です。")
                elif ".exe" in target.lower() or ".bat" in target.lower() or ".vbs" in target.lower():
                     insights.append("⚠️ **High**: 実行可能ファイルを呼び出すショートカットです。")

            if args:
                args_disp = (args[:100] + "...") if len(args) > 100 else args
                insights.append(f"📝 **Args**: `{args_disp}`")
                
                if "-enc" in args.lower() or "-encoded" in args.lower():
                    insights.append("🚫 **Encoded**: Base64エンコードされたPowerShellコマンドを検知。即座に解析が必要です。")
                if "-windowstyle hidden" in args.lower() or "-w hidden" in args.lower():
                    insights.append("🕶️ **Stealth**: ユーザーからウィンドウを隠蔽するフラグを確認。")
            else:
                 if "-enc" in target.lower():
                      insights.append("🚫 **Encoded**: ターゲットパス内にエンコードされたコマンドを確認。")

            if risk == "SECURITY_TOOL_MASQUERADE":
                insights.append("🎭 **Masquerade**: セキュリティツールやカンファレンス資料(DEFCON等)への偽装が疑われます。")

            if insights:
                return "<br/>".join(insights)
            elif "PHISHING" in ioc_type:
                return "不審なショートカットファイルが作成されました。フィッシング攻撃の可能性があります。"
            else:
                return "不審なショートカットファイルを検知しました。"
        
        elif "PHISHING" in ioc_type:
            return "フィッシング活動に関連するアーティファクトを検知しました。"
        
        elif "TIMESTOMP" in ioc_type:
            name = ioc.get("Value", "Unknown")
            return self.txt["note_timestomp"].format(name=name)
        
        elif "CREDENTIALS" in ioc_type:
            return "認証情報の窃取または不正ツールの配置を検知しました。"
        
        elif "COMMUNICATION_CONFIRMED" in reason or "COMMUNICATION_CONFIRMED" in ioc_type:
            return "🚨 ブラウザ履歴との照合により、**実際にネットワーク通信が成功した痕跡**を確認しました。C2サーバへのビーコン送信、またはペイロードダウンロードの可能性が極めて高いです。"
        
        return None
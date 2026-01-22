"""
ScoringEngine - Dynamic Score Adjustment Module
Extracted from sh_analyzer.py for better modularity.

This module handles:
- YAML-based threat scoring rules
- Context-aware score adjustments
- Noise filtering and dampening
"""
import re


class ScoringEngine:
    """
    [v2.2] Dynamic score adjustment using YAML-defined rules.
    Migrated from LachesisAnalyzer.adjust_score for better modularity.
    """
    
    def __init__(self, intel_module, rule_engine=None, ledger_manager=None):
        """
        Args:
            intel_module: Intel module for accessing YAML config
            rule_engine: Optional CompiledRuleEngine for fast pattern matching
            ledger_manager: Optional LedgerManager for audit trail
        """
        self.intel = intel_module
        self._rule_engine = rule_engine
        self._ledger_manager = ledger_manager
    
    def adjust_score(self, path: str, base_score: int, penalties=None, command_line: str = "", ledger=None) -> tuple:
        """
        Dynamic score adjustment using YAML-defined rules.
        
        Args:
            path: File path to evaluate
            base_score: Initial score
            penalties: Optional list of penalty rules
            command_line: Optional command line for context matching
            ledger: Optional ScoreLedger instance for audit trail
            
        Returns:
            tuple: (adjusted_score, tags_list)
        """
        adjusted = base_score
        tags = []
        path_lower = path.lower() if path else ""
        
        # Auto-create ledger for high-score paths
        if ledger is None and self._ledger_manager and base_score >= 200 and path:
            ledger = self._ledger_manager.get_or_create(path[:100])
        
        if ledger:
            ledger.set_base(base_score, "Initial Score")
        
        # Sensitive keyword detection
        SENSITIVE_KEYWORDS = [
            "password", "secret", "confidential", "credentials", "login", 
            "shadow", "kimitachi", "topsecret", "機密", "社外秘", "pass.txt"
        ]
        
        filename = path_lower.split("\\")[-1]
        
        if any(k in filename for k in SENSITIVE_KEYWORDS):
            delta = max(0, 800 - adjusted)
            adjusted = max(adjusted, 800)
            tags.append("SENSITIVE_DATA_ACCESS")
            if ledger and delta > 0:
                ledger.record_context_boost(f"Sensitive keyword: {filename}", delta)
        
        # Apply penalties
        if penalties is None:
            penalties = [] 

        for rule in penalties:
            p_pat = rule.get('path', '')
            p_val = int(rule.get('penalty', 0))
            if p_pat and p_pat in path_lower:
                adjusted = max(0, adjusted + p_val)
                tags.append("SYSTEM_NOISE")
                if ledger:
                    ledger.record_penalty(f"Path penalty: {p_pat}", p_val)
                break 
        
        # Use CompiledRuleEngine if available
        if self._rule_engine:
            engine_score, engine_tags = self._rule_engine.match(path_lower, 0)
            adjusted += engine_score
            tags.extend(engine_tags)
            if ledger and engine_score > 0:
                ledger.record("YAML_RULES", engine_score, f"Matched {len(engine_tags)} rules", engine_tags)
        else:
            # Fallback: Load threat_scores from YAML
            threat_rules = self.intel.get('threat_scores', [])
            for rule in threat_rules:
                pattern = rule.get('pattern', '')
                score = int(rule.get('score', 0))
                rule_tags = rule.get('tags', [])
                match_mode = rule.get('match_mode', 'contains')
                
                if not pattern:
                    continue
                
                is_match = False
                if match_mode == 'contains':
                    is_match = pattern.lower() in path_lower
                elif match_mode == 'exact':
                    is_match = filename == pattern.lower()
                elif match_mode == 'startswith':
                    is_match = path_lower.startswith(pattern.lower())
                elif match_mode == 'endswith':
                    is_match = path_lower.endswith(pattern.lower())
                elif match_mode == 'regex':
                    try:
                        is_match = bool(re.search(pattern, path_lower, re.IGNORECASE))
                    except re.error:
                        pass
                
                if is_match:
                    adjusted += score
                    tags.extend(rule_tags)
        
        # Context-specific adjustments
        adjusted, tags = self._apply_context_rules(path_lower, filename, adjusted, tags, command_line)
        
        return adjusted, tags
    
    def _apply_context_rules(self, path_lower: str, filename: str, adjusted: int, tags: list, command_line: str) -> tuple:
        """Apply context-specific scoring rules."""
        cmd_lower = command_line.lower() if command_line else ""
        
        # OpenSSH Documentation Noise
        if "openssh" in path_lower and ("manual" in path_lower or ".htm" in path_lower):
            adjusted = 50
            if "DATA_EXFIL" in tags:
                tags.remove("DATA_EXFIL")
            tags.append("DOCUMENTATION_NOISE")

        # SSH-Add Context Scoring
        if "ssh-add" in filename:
            if "program files" in path_lower and "openssh" in path_lower:
                adjusted = 100 
                if "DATA_EXFIL" in tags: tags.remove("DATA_EXFIL")
                tags.append("LEGITIMATE_TOOL_PATH")
            elif any(s in path_lower for s in ["users\\", "temp\\", "downloads", "desktop"]):
                adjusted = max(adjusted, 900)
                tags.append("DATA_EXFIL")
                tags.append("SUSPICIOUS_PATH")
            else:
                if adjusted > 500:
                    adjusted = 450
                    tags.append("AMBIGUOUS_PATH_CAP")
        
        # Masquerade Detection
        if filename == "sysinternals.exe":
            adjusted = max(adjusted, 600)
            tags.extend(["CRITICAL_MASQUERADE", "FAKE_TOOL_NAME"])
            
        if filename == "vmtoolsio.exe":
            if "program files" not in path_lower and "system32" not in path_lower:
                adjusted = max(adjusted, 600)
                tags.extend(["SUSPICIOUS_LOCATION", "PERSISTENCE_CANDIDATE"])

        # Security Tools in Suspicious Dirs
        masq_tools = ["procexp", "procmon", "wireshark", "fiddler", "tcpview", "autoruns"]
        suspicious_dirs = ["downloads", "temp", "users\\public"]
        
        for tool in masq_tools:
            if tool in filename:
                if any(sdir in path_lower for sdir in suspicious_dirs):
                    adjusted = max(adjusted, 500)
                    tags.append("SECURITY_TOOL_IN_USER_PATH")

        # User Path Extension Bonus
        target_exts = [".lnk", ".crx", ".jar"]
        target_dirs = ["downloads", "desktop"]

        if any(filename.endswith(ext) for ext in target_exts):
            if any(tdir in path_lower for tdir in target_dirs):
                adjusted += 200
                tags.append("SUSPICIOUS_USER_DOWNLOAD")

        # LOLBin Context (Robocopy, Xcopy, etc.)
        if "robocopy" in filename or "xcopy" in filename:
            if "admin$" in cmd_lower or "c$" in cmd_lower or "\\\\" in cmd_lower:
                adjusted = max(adjusted, 450)
                tags.append("LATERAL_MOVEMENT_COPY")
            if "backup" in cmd_lower or "archive" in cmd_lower:
                adjusted = max(adjusted, 100)
                tags.append("BACKUP_ACTIVITY")

        # WMIC Context
        if "wmic" in filename:
            if "process call create" in cmd_lower or "shadowcopy" in cmd_lower or "/node:" in cmd_lower:
                adjusted = max(adjusted, 500)
                tags.append("SUSPICIOUS_WMI")
                if "shadowcopy" in cmd_lower: tags.append("SHADOW_COPY_TAMPERING")

        # WinRM System Path Logic
        if "winrm" in filename:
            is_system_path = "system32" in path_lower or "syswow64" in path_lower
            is_suspicious_arg = "http" in cmd_lower or "invoke" in cmd_lower or "-r" in cmd_lower
            
            if is_system_path and not is_suspicious_arg:
                adjusted = min(adjusted, 40) 
                tags.append("WINRM_SYSTEM_SERVICE")

        # Noise Path Tagging
        noise_paths = [
            "programdata\\chocolatey", "programdata\\microsoft\\windows defender",
            "appdata\\local\\google\\chrome", "appdata\\local\\microsoft\\onedrive",
            "windows\\diagnostics", "windows\\servicing",
            "program files\\windowsapps", "windows\\systemapps",
            "program files\\microsoft", "program files (x86)\\microsoft"
        ]
        if any(np in path_lower for np in noise_paths):
            tags.append("SYSTEM_NOISE")

        # Noise Filename Patterns
        noise_filename_patterns = [
            r"^\.tmp$", r"^googlecrashhandler.*", r"^shapecollector.*", r"^tabtip.*",
            r"^mpcmdrun\.exe", r"^msmpeng\.exe", r"^conhost\.exe", r"^searchindexer\.exe", r"^dllhost\.exe"
        ]
        if any(re.match(fp, filename, re.IGNORECASE) for fp in noise_filename_patterns):
            tags.append("SYSTEM_NOISE")

        # TIMESTOMP Tuning
        if "chocolatey" in path_lower:
            adjusted = 100
            if "SYSTEM_NOISE" not in tags: tags.append("SYSTEM_NOISE")
        
        if filename.endswith(".ps1") and "diagnostics" in path_lower:
            adjusted = 100
            if "SYSTEM_NOISE" not in tags: tags.append("SYSTEM_NOISE")

        # Sync Tool Dampening
        sync_tools = ["msfeedssync.exe", "mobsync.exe", "tzsync.exe", "cipher.exe", "microsoft.uev.synccontroller.exe"]
        if filename in sync_tools:
            is_system_path = "system32" in path_lower or "syswow64" in path_lower
            if is_system_path:
                adjusted = min(adjusted, 250) 
                tags.append("SYSTEM_SYNC_PROCESS")

        # LOLBins Context Boost
        target_lolbins = ["robocopy", "xcopy", "cipher", "vssadmin", "bitsadmin"]
        suspicious_args = ["/wipe", "shadow", "transfer", "download", "upload", "-r", "job"]

        if any(bin_name in filename for bin_name in target_lolbins):
            is_suspicious_context = False
            
            if any(arg in cmd_lower for arg in suspicious_args):
                is_suspicious_context = True
                tags.append("SUSPICIOUS_ARGS")
                
            if "users" in path_lower and "system32" not in path_lower: 
                is_suspicious_context = True
                tags.append("LOLBIN_IN_USER_PATH")
                 
            if is_suspicious_context:
                adjusted += 300
                tags.append("CONTEXT_BOOST_HIGH")
        
        # Dev/Test File Filter
        if "test" in path_lower or "vendor" in path_lower:
            if "callback" in filename or "indent" in filename:
                adjusted = min(adjusted, 50)
                tags.append("DEV_TEST_FILE")
        
        return adjusted, tags

import polars as pl
from tools.detectors.base_detector import BaseDetector

class NoiseFilter(BaseDetector):
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        print("    -> [Detector] Running NoiseFilter...")
        cols = df.columns
        
        # 1. Path-based Noise Filter
        path_col = "ParentPath" if "ParentPath" in cols else ("Source_File" if "Source_File" in cols else None)
        noise_config = self.config.get("noise_filters", {})
        noise_paths = noise_config.get("paths", [])
        
        if noise_paths:
            combined_noise = "|".join(noise_paths)
            
            # [PERF v10.1] Optimized: Use any_horizontal instead of concat_str
            # This avoids creating intermediate columns and processes in place
            check_candidates = ["ParentPath", "Source_File", "CommandLine", "Target_Path", "Target_FileName", "Payload", "Message", "Action", "FileName"]
            existing_candidates = [c for c in check_candidates if c in cols]
            
            if existing_candidates:
                # Build parallel match expressions for each column
                noise_matches = [pl.col(c).fill_null("").str.to_lowercase().str.contains(combined_noise) for c in existing_candidates]
                is_noise = pl.any_horizontal(noise_matches)
            else:
                is_noise = pl.lit(False)
            
            # Additional column check for Judge_Verdict
            if "Judge_Verdict" not in cols:
                df = df.with_columns(pl.lit("").alias("Judge_Verdict"))
            
            # [v6.2 Case10 Fix] Extended critical tag pattern (precompiled)
            CRITICAL_TAG_PATTERN = r"(?i)(CRITICAL|METASPLOIT|COBALT|MIMIKATZ|WEBSHELL|BACKDOOR|RANSOM|WIPING|ANTI_FORENSICS|PHANTOM_DRIVE|DEFENDER_DISABLE|HOSTS_FILE|HISTORY_DETECTED|CONFIRMED|EXECUTION_CONFIRMED|REMOVABLE_DRIVE|NEW_USER_CREATION|LATERAL_MOVEMENT|STAGING_TOOL)"
            has_critical_tag = pl.col("Tag").fill_null("").str.contains(CRITICAL_TAG_PATTERN)
            
            # [PERF v10.1] Critical tool check with any_horizontal too
            CRITICAL_TOOLS_PATTERN = "(?i)(7za\\.exe|sdelete|bcwipe|mimikatz|psexec|lazagne)"
            tool_check_cols = [c for c in ["FileName", "Target_FileName", "Target_Path", "Message", "Action"] if c in cols]
            if tool_check_cols:
                tool_matches = [pl.col(c).fill_null("").str.contains(CRITICAL_TOOLS_PATTERN) for c in tool_check_cols]
                is_critical_tool = pl.any_horizontal(tool_matches)
            else:
                is_critical_tool = pl.lit(False)
            
            is_noise_final = is_noise & ~has_critical_tag & ~is_critical_tool

            df = df.with_columns([
                pl.when(is_noise_final).then(0).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                pl.when(is_noise_final).then(pl.lit("NOISE_FILTERED")).otherwise(pl.col("Tag")).alias("Tag"),
                pl.when(is_noise_final).then(pl.lit("False Positive (Cache)")).otherwise(pl.col("Judge_Verdict")).alias("Judge_Verdict")
            ])
            
        # 2. Context Filtering (System File Whitelisting & Time Sync)
        silencer_config = self.config.get("silencer", {})
        time_agents = silencer_config.get("time_agents", [])
        
        whitelist_config = self.config.get("system_whitelist", {})
        sys_paths = whitelist_config.get("paths", [])
        sys_files = whitelist_config.get("files", [])
        
        # (A) Time Sync Whitelist
        is_time_event = pl.col("Tag").str.contains("TIME") | pl.col("Tag").str.contains("4616")
        is_legit_agent = pl.lit(False)
        
        check_cols = [c for c in ["Action", "Target_Path", "Payload"] if c in cols]
        for agent in time_agents:
            for c in check_cols:
                is_legit_agent = is_legit_agent | pl.col(c).str.to_lowercase().str.contains(agent)
                
        df = df.with_columns([
            pl.when(is_time_event & is_legit_agent).then(0).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
            pl.when(is_time_event & is_legit_agent).then(pl.lit("INFO_VM_TIME_SYNC")).otherwise(pl.col("Tag")).alias("Tag")
        ])
        
        # (B) System File Whitelisting [v6.0 - Enhanced for Case7]
        # (Timestomp/AF判定) AND (システムパス OR システムファイル) -> Demote
        is_timestomp_or_af = pl.col("Tag").str.contains("TIMESTOMP") | pl.col("Tag").str.contains("ANTI_FORENSICS")
        
        is_system_item = pl.lit(False)
        target_col = "Target_Path" if "Target_Path" in cols else None
        fname_col = "FileName" if "FileName" in cols else None
        
        # [NEW v6.0] Trusted System Paths (Score -> 0 if no execution evidence)
        trusted_system_pattern = r"(?i)\\\\windows\\\\(system32|syswow64|winsxs)\\\\"
        is_trusted_system = pl.lit(False)
        if target_col:
            is_trusted_system = pl.col(target_col).str.contains(trusted_system_pattern)
        
        # [NEW v6.1] User/Suspicious Paths (Score BOOST for Timestomp)
        user_path_pattern = r"(?i)(\\\\users\\\\public\\\\|\\\\downloads\\\\|\\\\temp\\\\|\\\\appdata\\\\local\\\\temp\\\\|\\\\programdata\\\\)"
        is_user_path = pl.lit(False)
        if target_col:
            is_user_path = pl.col(target_col).str.contains(user_path_pattern)
        
        # [NEW v6.0] Execution Evidence Check
        execution_artifacts = ["UserAssist", "Amcache", "Prefetch", "Shimcache", "AppCompatCache", "Process"]
        has_execution_evidence = pl.lit(False)
        if "Artifact_Type" in cols:
            exec_pattern = "(?i)(" + "|".join(execution_artifacts) + ")"
            has_execution_evidence = pl.col("Artifact_Type").str.contains(exec_pattern)
        
        if target_col and sys_paths:
            for pat in sys_paths:
                is_system_item = is_system_item | pl.col(target_col).str.contains(pat)
        
        if fname_col and sys_files:
            for pat in sys_files:
                is_system_item = is_system_item | pl.col(fname_col).str.contains(pat)
                
        # [Signal Rescue] Bypass Demotion for Critical Threats
        # Even if it is a system file (e.g. vssadmin), if it has a CRITICAL tag or Score > 200, do NOT demote.
        is_critical = pl.col("Tag").str.contains("CRITICAL") | (pl.col("Threat_Score") >= 200)
        
        # [NEW v6.0] COMPLETE ZERO for trusted system files without execution
        # If Timestomp + Trusted System Path + NO Execution Evidence -> Score = 0
        should_zero = is_timestomp_or_af & is_trusted_system & (~has_execution_evidence) & (~is_critical)
        
        # Standard demotion for other system items
        should_demote = is_timestomp_or_af & is_system_item & (~is_critical) & (~should_zero)
        
        # [NEW v6.1] BOOST for User Path Timestomp - これは偽装ファイルの可能性が高い
        # If Timestomp + User Path -> Score BOOST +150
        should_boost = is_timestomp_or_af & is_user_path & (~is_trusted_system)
        
        df = df.with_columns([
            # Score adjustments: Boost user path timestomps, Zero trusted system, Demote others
            pl.when(should_boost)
              .then(pl.col("Threat_Score") + 150)
              .when(should_zero)
              .then(0)
              .when(should_demote)
              .then((pl.col("Threat_Score") / 4).cast(pl.Int64))
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score"),
              
            # Tag update
            pl.when(should_boost)
              .then(pl.format("{},CRITICAL_USER_PATH_TIMESTOMP", pl.col("Tag")))
              .when(should_zero)
              .then(pl.lit("TIMESTOMP_BENIGN"))
              .when(should_demote)
              .then(pl.format("{},LOW_CONFIDENCE_SYSTEM_FILE", pl.col("Tag")))
              .otherwise(pl.col("Tag"))
              .alias("Tag")
        ])
        
        # 3. Strict Evidence Hierarchy (Dual-Use)
        dual_use_config = self.config.get("dual_use", {})
        tools = dual_use_config.get("tools", [])
        exec_artifacts = dual_use_config.get("execution_artifacts", [])
        
        combined_tools = "|".join(tools)
        combined_exec = "|".join(exec_artifacts)
        
        if "Artifact_Type" in cols:
            target_col = "FileName" if "FileName" in cols else ("Message" if "Message" in cols else None)
            
            if target_col and tools:
                is_tool = pl.col(target_col).str.to_lowercase().str.contains(combined_tools)
                has_exec_evidence = pl.col("Artifact_Type").str.contains(combined_exec)
                has_anomaly = pl.col("Tag").str.contains("TIMESTOMP|PARADOX|MASQUERADE")
                
                is_innocent_tool = (is_tool & (~has_exec_evidence) & (~has_anomaly))
                
                df = df.with_columns([
                    pl.when(is_innocent_tool).then(0).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                    pl.when(is_innocent_tool).then(pl.lit("DUAL_USE_BENIGN")).otherwise(pl.col("Tag")).alias("Tag")
                ])

        return df

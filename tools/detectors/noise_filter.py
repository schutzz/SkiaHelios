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
            
            # [v5.7.1] Enhanced Context Filter: Check ALL relevant text columns
            # This ensures "choco install" in CommandLine is caught even if ParentPath is generic (e.g. powershell.exe)
            check_candidates = ["ParentPath", "Source_File", "CommandLine", "Target_Path", "Target_FileName", "Payload", "Message", "Action", "FileName"]
            
            # Build a boolean mask that is True if ANY candidate column matches the noise pattern
            is_noise = pl.lit(False)
            
            for col_name in check_candidates:
                if col_name in cols:
                    is_noise = is_noise | pl.col(col_name).str.to_lowercase().str.contains(combined_noise)


            
            # Additional column check for Judge_Verdict
            if "Judge_Verdict" not in cols:
                df = df.with_columns(pl.lit("").alias("Judge_Verdict"))

            df = df.with_columns([
                pl.when(is_noise).then(0).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                pl.when(is_noise).then(pl.lit("NOISE_FILTERED")).otherwise(pl.col("Tag")).alias("Tag"),
                pl.when(is_noise).then(pl.lit("False Positive (Cache)")).otherwise(pl.col("Judge_Verdict")).alias("Judge_Verdict")
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
        
        # (B) System File Whitelisting
        # (Timestomp/AF判定) AND (システムパス OR システムファイル) -> Demote
        is_timestomp_or_af = pl.col("Tag").str.contains("TIMESTOMP") | pl.col("Tag").str.contains("ANTI_FORENSICS")
        
        is_system_item = pl.lit(False)
        target_col = "Target_Path" if "Target_Path" in cols else None
        fname_col = "FileName" if "FileName" in cols else None
        
        if target_col and sys_paths:
            for pat in sys_paths:
                is_system_item = is_system_item | pl.col(target_col).str.contains(pat)
        
        if fname_col and sys_files:
            for pat in sys_files:
                is_system_item = is_system_item | pl.col(fname_col).str.contains(pat)
                
        # [Signal Rescue] Bypass Demotion for Critical Threats
        # Even if it is a system file (e.g. vssadmin), if it has a CRITICAL tag or Score > 200, do NOT demote.
        is_critical = pl.col("Tag").str.contains("CRITICAL") | (pl.col("Threat_Score") >= 200)
        
        # Demote ONLY if it's (Timestomp/AF) AND (System Item) AND (NOT Critical)
        should_demote = is_timestomp_or_af & is_system_item & (~is_critical)
        
        df = df.with_columns([
            pl.when(should_demote)
              .then((pl.col("Threat_Score") / 4).cast(pl.Int64))
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score"),
              
            pl.when(should_demote)
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

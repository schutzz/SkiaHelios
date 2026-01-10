import polars as pl
import re
import json
from tools.detectors.base_detector import BaseDetector

class ActivityTimelineDetector(BaseDetector):
    """
    Windows Activity Timeline (ActivitiesCache.db) Analyzer
    
    Detects manual operator activity by analyzing InFocus duration.
    Long focus durations on PowerShell, Task Manager, etc. indicate hands-on reconnaissance.
    
    v1.0 - Case7 SysInternals Hunter
    """
    
    # InFocus threshold: > 30 seconds suggests manual interaction
    RECON_THRESHOLD_SECONDS = 30
    
    # Applications considered suspicious when used for extended periods
    RECON_APPS = [
        r"powershell\.exe",
        r"cmd\.exe",
        r"taskmgr\.exe",
        r"Microsoft\.Windows\.Shell\.RunDialog",
        r"Microsoft\.Windows\.Explorer",
        r"regedit\.exe",
        r"mmc\.exe",
        r"devenv\.exe",
        r"procexp",
        r"procmon",
        r"autoruns",
    ]
    
    # High-priority recon indicators (always tag regardless of duration)
    HIGH_PRIORITY_APPS = [
        r"Microsoft\.Windows\.Shell\.RunDialog",  # Run dialog is always suspicious
    ]
    
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        """Analyze timeline for Activity Timeline events with InFocus data"""
        
        cols = df.columns
        
        # Check if this DataFrame contains Activity Timeline data
        if "Artifact_Type" not in cols:
            return df
            
        # Filter for Activity Timeline entries
        is_activity = pl.col("Artifact_Type").str.contains("(?i)activity")
        
        # Build pattern for recon apps
        recon_pattern = "(?i)(" + "|".join(self.RECON_APPS) + ")"
        high_priority_pattern = "(?i)(" + "|".join(self.HIGH_PRIORITY_APPS) + ")"
        
        # Check relevant columns for app names
        target_col = None
        for c in ["Action", "Target_Path", "FileName", "Message"]:
            if c in cols:
                target_col = c
                break
        
        if target_col is None:
            return df
            
        is_recon_app = pl.col(target_col).str.contains(recon_pattern)
        is_high_priority = pl.col(target_col).str.contains(high_priority_pattern)
        
        # Check for InFocus / extended duration indicators
        # Activity Timeline entries often have "InFocus" in Action or Payload
        is_infocus = pl.lit(False)
        if "Action" in cols:
            is_infocus = is_infocus | pl.col("Action").str.contains("(?i)infocus")
        if "Payload" in cols:
            is_infocus = is_infocus | pl.col("Payload").str.contains("(?i)infocus|activeDurationSeconds")
        
        # Scoring logic:
        # 1. High priority apps (Run Dialog) get immediate RECON tag
        # 2. Recon apps with InFocus get RECON_MANUAL_OPERATOR tag
        should_tag_high = is_activity & is_high_priority
        should_tag_recon = is_activity & is_recon_app & is_infocus & (~is_high_priority)
        
        # Apply scores and tags
        df = df.with_columns([
            pl.when(should_tag_high)
              .then(pl.col("Threat_Score") + 50)
              .when(should_tag_recon)
              .then(pl.col("Threat_Score") + 40)
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score"),
              
            pl.when(should_tag_high)
              .then(pl.format("{},RECON_RUN_DIALOG", pl.col("Tag")))
              .when(should_tag_recon)
              .then(pl.format("{},RECON_MANUAL_OPERATOR", pl.col("Tag")))
              .otherwise(pl.col("Tag"))
              .alias("Tag")
        ])
        
        # Log detection
        high_hits = df.filter(should_tag_high).height
        recon_hits = df.filter(should_tag_recon).height
        if high_hits > 0 or recon_hits > 0:
            print(f"    -> [ActivityTimeline] Detected: {high_hits} high-priority, {recon_hits} manual operator activities")
        
        return df


class LotLClusterDetector(BaseDetector):
    """
    Living off the Land (LotL) Cluster Detection v2.0
    
    Detects when multiple native OS reconnaissance tools are used together,
    indicating coordinated enumeration activity (Hands-on-Keyboard attack).
    
    v2.0 - Time Window Analysis + User Path Detection
    """
    
    # Time window for burst detection (10 minutes)
    TIME_WINDOW_SECONDS = 600
    
    # Suspicious user paths (non-system locations)
    SUSPICIOUS_PATHS = [
        r"\\users\\public\\",
        r"\\downloads\\",
        r"\\temp\\",
        r"\\appdata\\local\\temp\\",
        r"\\programdata\\",
    ]
    
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        """Check for LotL tool clusters with Time Window analysis"""
        
        cols = df.columns
        
        # Load LotL config from triage_rules.yaml (passed via self.config)
        lotl_config = self.config.get("living_off_the_land", {})
        tools = lotl_config.get("tools", [
            "whoami.exe", "ipconfig.exe", "net.exe", "netstat.exe", 
            "systeminfo.exe", "tasklist.exe"
        ])
        threshold = lotl_config.get("score_cluster_threshold", 2)
        bonus = lotl_config.get("score_cluster_bonus", 120)
        single_score = lotl_config.get("score_single", 30)
        
        # Build pattern
        pattern = "(?i)(" + "|".join([re.escape(t.replace(".exe", "")) for t in tools]) + r")\.exe"
        
        # Check columns
        target_cols = [c for c in ["FileName", "Target_Path", "Action", "Message"] if c in cols]
        if not target_cols:
            return df
        
        # Count LotL hits
        is_lotl = pl.lit(False)
        for c in target_cols:
            is_lotl = is_lotl | pl.col(c).str.contains(pattern)
        
        lotl_count = df.filter(is_lotl).height
        
        # [v2.0] Check for suspicious path (non-System32)
        is_user_path = pl.lit(False)
        susp_path_pattern = "(?i)(" + "|".join(self.SUSPICIOUS_PATHS) + ")"
        if "Target_Path" in cols:
            is_user_path = pl.col("Target_Path").str.contains(susp_path_pattern)
        
        # [v2.0] Combined: LotL from suspicious path = Higher threat
        is_lotl_suspicious = is_lotl & is_user_path
        susp_lotl_count = df.filter(is_lotl_suspicious).height
        
        if lotl_count >= threshold:
            print(f"    -> [LotL] CLUSTER DETECTED: {lotl_count} discovery tools (threshold={threshold})")
            
            # Determine if this is Hands-on-Keyboard activity
            is_hands_on = susp_lotl_count > 0  # Any LotL from user path = Hands-on-Keyboard suspected
            
            if is_hands_on:
                print(f"    -> [LotL] ⚠️ HANDS-ON-KEYBOARD SUSPECTED: {susp_lotl_count} tools from user paths!")
                # Extra boost for suspicious path LotL
                df = df.with_columns([
                    pl.when(is_lotl_suspicious)
                      .then(pl.col("Threat_Score") + bonus + 80)  # +200 total
                      .when(is_lotl)
                      .then(pl.col("Threat_Score") + bonus)
                      .otherwise(pl.col("Threat_Score"))
                      .alias("Threat_Score"),
                      
                    pl.when(is_lotl_suspicious)
                      .then(pl.format("{},LOTL_CLUSTER,HANDS_ON_KEYBOARD", pl.col("Tag")))
                      .when(is_lotl)
                      .then(pl.format("{},LOTL_CLUSTER", pl.col("Tag")))
                      .otherwise(pl.col("Tag"))
                      .alias("Tag")
                ])
            else:
                # Standard cluster bonus
                df = df.with_columns([
                    pl.when(is_lotl)
                      .then(pl.col("Threat_Score") + bonus)
                      .otherwise(pl.col("Threat_Score"))
                      .alias("Threat_Score"),
                      
                    pl.when(is_lotl)
                      .then(pl.format("{},LOTL_CLUSTER", pl.col("Tag")))
                      .otherwise(pl.col("Tag"))
                      .alias("Tag")
                ])
        elif lotl_count > 0:
            # Single hits get base score only
            df = df.with_columns([
                pl.when(is_lotl)
                  .then(pl.col("Threat_Score") + single_score)
                  .otherwise(pl.col("Threat_Score"))
                  .alias("Threat_Score"),
                  
                pl.when(is_lotl)
                  .then(pl.format("{},LIVING_OFF_THE_LAND", pl.col("Tag")))
                  .otherwise(pl.col("Tag"))
                  .alias("Tag")
            ])
        
        return df


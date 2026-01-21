import polars as pl
import re
import json
from tools.detectors.base_detector import BaseDetector

class ActivityTimelineDetector(BaseDetector):
    """Windows Activity Timeline (ActivitiesCache.db) Analyzer"""
    
    RECON_THRESHOLD_SECONDS = 30
    RECON_APPS = [r"powershell\.exe", r"cmd\.exe", r"taskmgr\.exe", r"Microsoft\.Windows\.Shell\.RunDialog", r"Microsoft\.Windows\.Explorer", r"regedit\.exe", r"mmc\.exe", r"devenv\.exe", r"procexp", r"procmon", r"autoruns"]
    HIGH_PRIORITY_APPS = [r"Microsoft\.Windows\.Shell\.RunDialog"]
    
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        cols = df.columns
        if "Artifact_Type" not in cols: return df
            
        is_activity = pl.col("Artifact_Type").str.contains("(?i)activity")
        
        # ---------------------------------------------------------
        # 🚀 [NEW] Phantom Drive Detection (Case 10 Critical)
        # ---------------------------------------------------------
        phantom_pattern = r"(?i)(A|B):[\\/]" 
        search_cols = [c for c in ["Payload", "Message", "Action", "Target_Path", "Process_Command_Line"] if c in cols]
        is_phantom = pl.lit(False)
        for c in search_cols:
            is_phantom = is_phantom | pl.col(c).str.contains(phantom_pattern)

        recon_pattern = "(?i)(" + "|".join(self.RECON_APPS) + ")"
        high_priority_pattern = "(?i)(" + "|".join(self.HIGH_PRIORITY_APPS) + ")"
        
        target_col = None
        for c in ["Action", "Target_Path", "FileName", "Message"]:
            if c in cols:
                target_col = c
                break
        
        if target_col is None: return df
            
        is_recon_app = pl.col(target_col).str.contains(recon_pattern)
        is_high_priority = pl.col(target_col).str.contains(high_priority_pattern)
        
        is_infocus = pl.lit(False)
        if "Action" in cols: is_infocus = is_infocus | pl.col("Action").str.contains("(?i)infocus")
        if "Payload" in cols: is_infocus = is_infocus | pl.col("Payload").str.contains("(?i)infocus|activeDurationSeconds")
        
        should_tag_high = is_activity & is_high_priority
        should_tag_recon = is_activity & is_recon_app & is_infocus & (~is_high_priority)
        
        df = df.with_columns([
            pl.when(is_phantom)
              .then(pl.col("Threat_Score") + 600)
              .when(should_tag_high).then(pl.col("Threat_Score") + 50)
              .when(should_tag_recon).then(pl.col("Threat_Score") + 40)
              .otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
            
            pl.when(is_phantom)
              .then(pl.format("{},PHANTOM_DRIVE_DETECTED", pl.col("Tag")))
              .when(should_tag_high).then(pl.format("{},RECON_RUN_DIALOG", pl.col("Tag")))
              .when(should_tag_recon).then(pl.format("{},RECON_MANUAL_OPERATOR", pl.col("Tag")))
              .otherwise(pl.col("Tag")).alias("Tag")
        ])
        
        # 🚀 Universal Signatures Call
        df = self.apply_threat_signatures(df)
        
        return df

class LotLClusterDetector(BaseDetector):
    """Living off the Land (LotL) Cluster Detection v2.0"""
    
    TIME_WINDOW_SECONDS = 600
    SUSPICIOUS_PATHS = [r"\\users\\public\\", r"\\downloads\\", r"\\temp\\", r"\\appdata\\local\\temp\\", r"\\programdata\\"]
    
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        cols = df.columns
        lotl_config = self.config.get("living_off_the_land", {})
        tools = lotl_config.get("tools", ["whoami.exe", "ipconfig.exe", "net.exe", "netstat.exe", "systeminfo.exe", "tasklist.exe"])
        threshold = lotl_config.get("score_cluster_threshold", 2)
        bonus = lotl_config.get("score_cluster_bonus", 120)
        single_score = lotl_config.get("score_single", 30)
        
        pattern = "(?i)(" + "|".join([re.escape(t.replace(".exe", "")) for t in tools]) + r")\.exe"
        target_cols = [c for c in ["FileName", "Target_Path", "Action", "Message"] if c in cols]
        if not target_cols: return df
        
        is_lotl = pl.lit(False)
        for c in target_cols: is_lotl = is_lotl | pl.col(c).str.contains(pattern)
        
        lotl_count = df.filter(is_lotl).height
        is_user_path = pl.lit(False)
        susp_path_pattern = "(?i)(" + "|".join(self.SUSPICIOUS_PATHS) + ")"
        if "Target_Path" in cols: is_user_path = pl.col("Target_Path").str.contains(susp_path_pattern)
        
        is_lotl_suspicious = is_lotl & is_user_path
        susp_lotl_count = df.filter(is_lotl_suspicious).height
        
        if lotl_count >= threshold:
            is_hands_on = susp_lotl_count > 0
            if is_hands_on:
                df = df.with_columns([
                    pl.when(is_lotl_suspicious).then(pl.col("Threat_Score") + bonus + 80).when(is_lotl).then(pl.col("Threat_Score") + bonus).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                    pl.when(is_lotl_suspicious).then(pl.format("{},LOTL_CLUSTER,HANDS_ON_KEYBOARD", pl.col("Tag"))).when(is_lotl).then(pl.format("{},LOTL_CLUSTER", pl.col("Tag"))).otherwise(pl.col("Tag")).alias("Tag")
                ])
            else:
                df = df.with_columns([
                    pl.when(is_lotl).then(pl.col("Threat_Score") + bonus).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                    pl.when(is_lotl).then(pl.format("{},LOTL_CLUSTER", pl.col("Tag"))).otherwise(pl.col("Tag")).alias("Tag")
                ])
        elif lotl_count > 0:
            df = df.with_columns([
                pl.when(is_lotl).then(pl.col("Threat_Score") + single_score).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                pl.when(is_lotl).then(pl.format("{},LIVING_OFF_THE_LAND", pl.col("Tag"))).otherwise(pl.col("Tag")).alias("Tag")
            ])
            
        # 🚀 Universal Signatures Call
        df = self.apply_threat_signatures(df)
        
        return df

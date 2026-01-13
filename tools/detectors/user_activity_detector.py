import polars as pl
from tools.detectors.base_detector import BaseDetector

class UserActivityDetector(BaseDetector):
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        print("    -> [Detector] Running UserActivityDetector...")
        cols = df.columns
        
        priv_config = self.config.get("privilege_escalation", {})
        user_create = priv_config.get("user_creation", [])
        sam_patterns = priv_config.get("sam_registry", [])
        
        user_create_combined = "|".join(user_create)
        sam_combined = "|".join(sam_patterns)
        
        msg_col = None
        for c in ["Message", "Action", "Description"]:
            if c in cols: msg_col = c; break
            
        check_cols = [c for c in [msg_col, "Target_Path", "Payload", "FileName"] if c and c in cols]
        
        # User Creation / PrivEsc
        for check_col in check_cols:
            if user_create:
                is_user_creation = pl.col(check_col).str.to_lowercase().str.contains(user_create_combined)
                df = df.with_columns([
                    pl.when(is_user_creation).then(300).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                    pl.when(is_user_creation).then(pl.format("{},CRITICAL_USER_CREATION,PRIVILEGE_ESCALATION", pl.col("Tag"))).otherwise(pl.col("Tag")).alias("Tag")
                ])
                
        # SAM Registry Access
        path_col = "ParentPath" if "ParentPath" in cols else ("Source_File" if "Source_File" in cols else None)
        if path_col and sam_patterns:
             is_sam_access = pl.col(path_col).str.to_lowercase().str.contains(sam_combined)
             df = df.with_columns([
                pl.when(is_sam_access).then(pl.col("Threat_Score") + 200).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                pl.when(is_sam_access).then(pl.format("{},SAM_REGISTRY_ACCESS,PRIVILEGE_ESCALATION", pl.col("Tag"))).otherwise(pl.col("Tag")).alias("Tag")
            ])
            
        # 🚀 Universal Signatures Call
        df = self.apply_threat_signatures(df)
            
        return df

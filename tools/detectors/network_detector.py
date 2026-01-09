import polars as pl
from tools.detectors.base_detector import BaseDetector

class NetworkDetector(BaseDetector):
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        print("    -> [Detector] Running NetworkDetector...")
        cols = df.columns
        
        net_config = self.config.get("network_detection", {})
        c2_patterns = net_config.get("c2_patterns", [])
        lateral_patterns = net_config.get("lateral_patterns", [])
        
        c2_combined = "|".join(c2_patterns)
        lateral_combined = "|".join(lateral_patterns)
        
        msg_col = None
        for c in ["Message", "Action", "Description"]:
            if c in cols: msg_col = c; break
            
        check_cols = [c for c in [msg_col, "Target_Path", "Payload", "FileName"] if c and c in cols]
        
        for check_col in check_cols:
            if c2_patterns:
                is_c2 = pl.col(check_col).str.to_lowercase().str.contains(c2_combined)
                df = df.with_columns([
                    pl.when(is_c2).then(pl.col("Threat_Score") + 100).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                    pl.when(is_c2).then(pl.format("{},POTENTIAL_C2_CALLBACK", pl.col("Tag"))).otherwise(pl.col("Tag")).alias("Tag")
                ])
                
            if lateral_patterns:
                is_lateral = pl.col(check_col).str.to_lowercase().str.contains(lateral_combined)
                df = df.with_columns([
                    pl.when(is_lateral).then(pl.col("Threat_Score") + 80).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                    pl.when(is_lateral).then(pl.format("{},LATERAL_MOVEMENT_DETECTED", pl.col("Tag"))).otherwise(pl.col("Tag")).alias("Tag")
                ])
                
        return df

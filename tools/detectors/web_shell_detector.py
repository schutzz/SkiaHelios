import polars as pl
import re
from tools.detectors.base_detector import BaseDetector

class WebShellDetector(BaseDetector):
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        print("    -> [Detector] Running WebShellDetector...")
        
        cols = df.columns
        path_col = "ParentPath" if "ParentPath" in cols else ("Source_File" if "Source_File" in cols else None)
        if not path_col: return df

        # Load signatures from config
        web_config = self.config.get("web_intrusion", {})
        web_dirs = web_config.get("directories", [])
        webshell_files = web_config.get("suspicious_files", [])
        indicators = web_config.get("indicators", [])

        if not web_dirs:
            return df
            
        web_dirs_combined = "|".join(web_dirs)
        webshell_files_combined = "|".join(webshell_files)
        indicators_combined = "|".join(indicators)

        if "FileName" in cols:
            # Condition 1: Script in Web Directory
            is_web_script = (
                pl.col("FileName").str.to_lowercase().str.contains(r"(?i)\.(php|asp|aspx|jsp|jspx)$") &
                pl.col(path_col).str.to_lowercase().str.contains(web_dirs_combined)
            )
            
            # Condition 2: Suspicious webshell filename
            is_webshell_name = pl.col("FileName").str.to_lowercase().str.contains(webshell_files_combined)
            
            is_webshell = is_web_script | is_webshell_name
            
            df = df.with_columns([
                pl.when(is_webshell)
                  .then(300)
                  .otherwise(pl.col("Threat_Score"))
                  .alias("Threat_Score"),
                
                pl.when(is_webshell)
                  .then(pl.format("{},CRITICAL_WEBSHELL,WEB_INTRUSION_CHAIN", pl.col("Tag")))
                  .otherwise(pl.col("Tag"))
                  .alias("Tag")
            ])
            
        # Indicator check in other columns
        check_cols = [c for c in ["Message", "Action", "Description"] if c in cols]
        for col in check_cols:
             is_indicator = pl.col(col).str.to_lowercase().str.contains(indicators_combined)
             df = df.with_columns([
                 pl.when(is_indicator)
                   .then(pl.col("Threat_Score") + 150)
                   .otherwise(pl.col("Threat_Score"))
                   .alias("Threat_Score"),
                 
                 pl.when(is_indicator)
                   .then(pl.format("{},WEB_INTRUSION_CHAIN", pl.col("Tag")))
                   .otherwise(pl.col("Tag"))
                   .alias("Tag")
             ])
             
        return df

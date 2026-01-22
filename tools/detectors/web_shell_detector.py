import polars as pl
import re
from tools.detectors.base_detector import BaseDetector

class WebShellDetector(BaseDetector):
    """
    WebShell Detector v2.0 (YAML統合版)
    - 除外リスト (allowlist_patterns) を YAML から読み込み
    - スコープ制御 (force_web_dirs_only) による安全装置
    """
    
    def __init__(self, config):
        super().__init__(config)
        self._load_webshell_config()
    
    def _load_webshell_config(self):
        """Load webshell detector configuration from YAML."""
        ws_config = self.config.get("webshell_detector", {})
        
        # Allowlist patterns (システムファイル除外)
        self.allowlist_patterns = []
        for item in ws_config.get("allowlist_patterns", []):
            pattern = item.get("pattern", "")
            if pattern:
                try:
                    self.allowlist_patterns.append(re.compile(pattern))
                except re.error as e:
                    print(f"    [!] Invalid allowlist pattern: {pattern} - {e}")
        
        # Scan scope settings
        scope = ws_config.get("scan_scope", {})
        self.force_web_dirs_only = scope.get("force_web_dirs_only", False)
        self.default_paths = scope.get("default_paths", [])
    
    def _is_allowlisted(self, filename: str, path: str) -> bool:
        """Check if file matches any allowlist pattern."""
        combined = f"{path}/{filename}" if path else filename
        for pattern in self.allowlist_patterns:
            if pattern.search(filename) or pattern.search(combined):
                return True
        return False
    
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        print("    -> [Detector] Running WebShellDetector v2.0...")
        
        cols = df.columns
        path_col = "ParentPath" if "ParentPath" in cols else ("Source_File" if "Source_File" in cols else None)
        if not path_col: 
            return df

        # Load web intrusion config
        web_config = self.config.get("web_intrusion", {})
        web_dirs = web_config.get("directories", [])
        webshell_files = web_config.get("suspicious_files", [])
        indicators = web_config.get("indicators", [])

        # [P0 Safety] force_web_dirs_only check
        if not web_dirs and self.force_web_dirs_only:
            print("    -> [WebShellDetector] SKIPPED: No web directories found and force_web_dirs_only is ON.")
            # Fallback to default paths if configured
            if self.default_paths:
                web_dirs = self.default_paths
                print(f"    -> [WebShellDetector] Using default paths: {web_dirs}")
            else:
                return df  # Skip entirely

        if not web_dirs:
            # 🚀 Universal Signatures (no web dirs defined)
            df = self.apply_threat_signatures(df)
            return df
        
        # Build allowlist regex for Polars (combined pattern)
        allowlist_regex = None
        if self.allowlist_patterns:
            # Combine all patterns into one for Polars
            pattern_strs = [p.pattern for p in self.allowlist_patterns]
            allowlist_regex = "|".join(f"({p})" for p in pattern_strs)
            
        web_dirs_combined = "|".join(web_dirs)
        webshell_files_combined = "|".join(webshell_files) if webshell_files else None
        indicators_combined = "|".join(indicators) if indicators else None

        if "FileName" in cols:
            # Condition 1: Script in Web Directory
            is_web_script = (
                pl.col("FileName").str.to_lowercase().str.contains(r"(?i)\.(php|asp|aspx|jsp|jspx|sh|cgi|pl)$") &
                pl.col(path_col).str.to_lowercase().str.contains(web_dirs_combined)
            )
            
            # Condition 2: Suspicious webshell filename
            is_webshell_name = pl.lit(False)
            if webshell_files_combined:
                is_webshell_name = pl.col("FileName").str.to_lowercase().str.contains(webshell_files_combined)
            
            # [P0] Condition 3: Allowlist exclusion (NOT webshell if in allowlist)
            is_allowlisted = pl.lit(False)
            if allowlist_regex:
                # Check both filename and path
                is_allowlisted = (
                    pl.col("FileName").str.contains(allowlist_regex) |
                    pl.col(path_col).str.contains(allowlist_regex)
                )
            
            # Final condition: WebShell AND NOT allowlisted
            is_webshell = (is_web_script | is_webshell_name) & ~is_allowlisted
            
            df = df.with_columns([
                pl.when(is_webshell)
                  .then(pl.lit(300))
                  .otherwise(pl.col("Threat_Score"))
                  .alias("Threat_Score"),
                
                pl.when(is_webshell)
                  .then(pl.format("{},CRITICAL_WEBSHELL,WEB_INTRUSION_CHAIN", pl.col("Tag")))
                  .otherwise(pl.col("Tag"))
                  .alias("Tag")
            ])
            
        # Indicator check in other columns
        if indicators_combined:
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

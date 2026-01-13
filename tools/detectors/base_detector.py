from abc import ABC, abstractmethod
import polars as pl
import re

class BaseDetector(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        """
        Analyze the timeline DataFrame and apply scoring/tagging rules.
        Must allow streaming-compatible operations where possible.
        """
        pass

    def _get_column_or_default(self, df: pl.DataFrame, col_name: str, default_val="") -> str:
        if col_name in df.columns:
            return col_name
        return default_val

    # ==========================================
    # 🚀 [NEW] Universal Threat Signature Engine
    # ==========================================
    def apply_threat_signatures(self, df: pl.DataFrame) -> pl.DataFrame:
        """
        Applies generic threat signatures defined in 'threat_signatures' section of YAML.
        This ensures that ALL detectors can detect basic threats like 'confidential' files 
        or 'UNC paths' regardless of their specific logic.
        """
        threat_sigs = self.config.get("threat_signatures", [])
        if not threat_sigs:
            return df
            
        # Optimization: Check if DataFrame is empty
        if df.height == 0:
            return df

        cols = df.columns
        # Target priority: Full_Path > Target_Path > FileName > Message
        target_candidates = ["Full_Path", "Target_Path", "FileName", "Message", "Command_Line", "Payload"]
        available_targets = [c for c in target_candidates if c in cols]
        
        if not available_targets:
            return df

        # Pre-calculate lowercase columns for performance
        # (This avoids repeated lower() calls inside the loop)
        exprs = []
        for col_name in available_targets:
            exprs.append(pl.col(col_name).str.to_lowercase().alias(f"_lower_{col_name}"))
        
        df = df.with_columns(exprs)

        for sig in threat_sigs:
            sig_tag = sig.get("tag", "THREAT_DETECTED")
            sig_score = sig.get("score", 100)
            sig_pattern = sig.get("pattern", "")
            target_col_config = sig.get("target", "")

            if not sig_pattern: continue

            # Determine target column
            if target_col_config and target_col_config in cols:
                target_col = f"_lower_{target_col_config}"
            else:
                target_col = f"_lower_{available_targets[0]}"

            # Check if target column exists (it might not if config specified a missing col)
            if target_col not in df.columns:
                continue

            match_expr = pl.col(target_col).str.contains(sig_pattern)

            df = df.with_columns([
                pl.when(match_expr)
                  .then(pl.col("Threat_Score") + sig_score)
                  .otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                  
                pl.when(match_expr)
                  .then(pl.format("{},{}", pl.col("Tag"), pl.lit(sig_tag)))
                  .otherwise(pl.col("Tag")).alias("Tag")
            ])
            
        # Cleanup temporary columns
        df = df.drop([c for c in df.columns if c.startswith("_lower_")])
        
        return df

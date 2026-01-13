import polars as pl
from tools.detectors.base_detector import BaseDetector

class LnkDetector(BaseDetector):
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        print("    -> [Detector] Running LnkDetector...")
        cols = df.columns
        if "Target_Path" not in cols: return df

        lnk_threats = self.config.get("lnk_threats", [])
        
        msg_col = None
        for c in ["Message", "Action", "Description"]:
            if c in cols: msg_col = c; break
            
        fname_col = "FileName" if "FileName" in cols else msg_col
        if not fname_col: return df

        # (A) Enrichment
        if msg_col and msg_col in cols:
             df = df.with_columns(
                pl.when(
                    (pl.col(fname_col).str.to_lowercase().str.contains(r"\.lnk")) & 
                    (pl.col("Target_Path").is_not_null()) &
                    (pl.col("Target_Path") != "")
                )
                .then(pl.format("{} 🎯 Target: {}", pl.col(msg_col), pl.col("Target_Path")))
                .otherwise(pl.col(msg_col))
                .alias(msg_col)
            )

        # (B) Deep LNK Analysis
        target_expr = pl.col("Target_Path").str.to_lowercase()
        msg_expr = pl.col(msg_col).str.to_lowercase() if msg_col else pl.lit("")
        is_lnk = pl.col(fname_col).str.to_lowercase().str.contains(r"\.lnk")

        if lnk_threats:
            for item in lnk_threats:
                pat = item.get("pat", "")
                tag = item.get("tag", "SUSPICIOUS_LNK")
                score = item.get("score", 50)
                if not pat: continue
                
                match_expr = is_lnk & (target_expr.str.contains(pat) | msg_expr.str.contains(pat))
                
                df = df.with_columns([
                    pl.when(match_expr).then(pl.col("Threat_Score") + score).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                    pl.when(match_expr).then(pl.format("{},{}", pl.col("Tag"), pl.lit(tag))).otherwise(pl.col("Tag")).alias("Tag")
                ])
            
            # (C) Suspicious CMDLine Generic
            combined_malicious = "|".join([item.get("pat") for item in lnk_threats if item.get("pat")])
            if combined_malicious:
                has_malicious = is_lnk & (target_expr.str.contains(combined_malicious) | msg_expr.str.contains(combined_malicious))
                df = df.with_columns(
                    pl.when(has_malicious).then(pl.format("{},SUSPICIOUS_CMDLINE", pl.col("Tag"))).otherwise(pl.col("Tag")).alias("Tag")
                )

        # 🚀 Universal Signatures Call
        df = self.apply_threat_signatures(df)
        
        return df

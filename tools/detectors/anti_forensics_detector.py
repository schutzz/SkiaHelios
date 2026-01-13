import polars as pl
from tools.detectors.base_detector import BaseDetector

class AntiForensicsDetector(BaseDetector):
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        print("    -> [Detector] Running AntiForensicsDetector...")
        cols = df.columns
        
        # 1. Anti-Forensics Tools (Wipers)
        af_config = self.config.get("anti_forensics", {})
        tools = af_config.get("tools", {})
        log_del = af_config.get("log_deletion", [])
        evidence_wiping = af_config.get("evidence_wiping", [])

        # Masquerade Config
        masq_config = self.config.get("masquerade", {})
        legit_crx_paths = masq_config.get("legit_crx_paths", [])

        msg_col = None
        for c in ["Message", "Action", "Description"]:
            if c in cols: msg_col = c; break

        # --- Tool Detection ---
        if "FileName" in cols or msg_col:
            target_col = "FileName" if "FileName" in cols else msg_col
            
            for tool, tag_label in tools.items():
                is_wiper = pl.col(target_col).str.to_lowercase().str.contains(tool)
                df = df.with_columns([
                    pl.when(is_wiper).then(300).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                    pl.when(is_wiper)
                      .then(pl.format("{},CRITICAL_ANTI_FORENSICS,{}", pl.col("Tag"), pl.lit(tag_label)))
                      .otherwise(pl.col("Tag")).alias("Tag")
                ])
                
        # --- Masquerade Detection (.crx) ---
        path_col = "ParentPath" if "ParentPath" in cols else ("Source_File" if "Source_File" in cols else None)
        if "FileName" in cols and path_col and legit_crx_paths:
            combined_legit = "|".join(legit_crx_paths)
            is_masquerade = (
                pl.col("FileName").str.to_lowercase().str.ends_with(".crx") & 
                (~pl.col(path_col).str.contains(combined_legit)) 
            )
            df = df.with_columns([
                pl.when(is_masquerade).then(300).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                pl.when(is_masquerade).then(pl.lit("CRITICAL_MASQUERADE")).otherwise(pl.col("Tag")).alias("Tag")
            ])

        # --- Log Deletion / Evidence Wiping ---
        check_cols = [c for c in [msg_col, "Target_Path", "Payload", "FileName"] if c and c in cols]
        
        log_del_combined = "|".join(log_del)
        wipe_combined = "|".join(evidence_wiping)
        
        for check_col in check_cols:
            if log_del:
                is_log_del = pl.col(check_col).str.to_lowercase().str.contains(log_del_combined)
                df = df.with_columns([
                    pl.when(is_log_del).then(300).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                    pl.when(is_log_del).then(pl.format("{},CRITICAL_LOG_DELETION,ANTI_FORENSICS", pl.col("Tag"))).otherwise(pl.col("Tag")).alias("Tag")
                ])
            
            if evidence_wiping:
                is_wipe = pl.col(check_col).str.to_lowercase().str.contains(wipe_combined)
                df = df.with_columns([
                    pl.when(is_wipe).then(300).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                    pl.when(is_wipe).then(pl.format("{},EVIDENCE_WIPING,ANTI_FORENSICS", pl.col("Tag"))).otherwise(pl.col("Tag")).alias("Tag")
                ])

        # 🚀 Universal Signatures
        df = self.apply_threat_signatures(df)

        return df

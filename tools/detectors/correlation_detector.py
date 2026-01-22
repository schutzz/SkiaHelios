import polars as pl
import yaml
import re
from pathlib import Path
from tools.detectors.base_detector import BaseDetector

class CorrelationDetector(BaseDetector):
    """
    [Logic Layer] Correlation Detector
    Cross-references 'Intent' (e.g., ConsoleHost history) with 'Fact' (EventLogs 4104/4688).
    Adds timestamps to stateless artifacts and validates execution.
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.rules = self._load_rules()
        
    def _load_rules(self):
        """Load external correlation rules from YAML"""
        # Try relative path first
        rule_path = Path("rules/correlation_rules.yaml")
        if not rule_path.exists():
            # Fallback for different execution contexts
            rule_path = Path(__file__).parent.parent.parent / "rules/correlation_rules.yaml"

        if not rule_path.exists():
            print("    [!] Correlation Rules not found. Using empty set.")
            return []
            
        try:
            with open(rule_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                print(f"    [DEBUG] Loaded {len(data.get('correlation_rules', []))} correlation rules.")
                return data.get("correlation_rules", [])
        except Exception as e:
            print(f"    [!] Error loading correlation rules: {e}")
            return []

    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        """
        Main Analysis Interface called by Hercules.
        df: The main timeline DataFrame.
        """
        if df is None or df.height == 0:
            return df

        # 1. Split Data: "History" (Stateless) vs "Events" (Timestamped Facts)
        history_df = df.filter(
            (pl.col("Source") == "PowerShell History") | 
            (pl.col("Tag").str.contains("HISTORY_DETECTED"))
        )
        
        # Events: EID 4104 (ScriptBlock) or 4688 (Process)
        # Check if EventId column exists before filtering
        if "EventId" not in df.columns:
             return df
             
        target_events = df.filter(
            pl.col("EventId").cast(pl.Int64).is_in([4104, 4688])
        )

        if history_df.height == 0:
            return df 

        print(f"    -> [Correlation] Matching {history_df.height} history lines against {target_events.height} events...")

        updates = []

        # 2. Iterate Rules
        for rule in self.rules:
            trigger = rule.get("history_trigger", {})
            keywords = trigger.get("keywords", [])
            
            pattern = "|".join([re.escape(k) for k in keywords])
            if trigger.get("is_regex"):
                pattern = "|".join(keywords)
            
            # [Fix] Typo fixed: matched_history
            matched_history = history_df.filter(
                pl.col("Action").str.contains(f"(?i){pattern}")
            )

            if matched_history.height == 0:
                continue

            # 3. Validate against Event Logs
            validator = rule.get("event_validator", {})
            val_pattern = validator.get("search_pattern", "")
            
            supporting_events = target_events.filter(
                pl.col("Payload").str.contains(val_pattern)
            )

            if supporting_events.height > 0:
                # Found evidence
                # Determine timestamp (using first match for now)
                found_timestamps = supporting_events["Timestamp_UTC"].to_list()
                valid_ts = found_timestamps[0] if found_timestamps else None
                
                # Determine tags to add
                add_tags_list = rule.get("tags", [])
                if "EXECUTION_CONFIRMED" not in add_tags_list:
                    add_tags_list.append("EXECUTION_CONFIRMED")
                add_tags_str = ",".join(add_tags_list)
                
                if valid_ts:
                     updates.append({
                         "history_pattern": pattern,
                         "timestamp": valid_ts,
                         "score_boost": rule.get("score", 0),
                         "add_tags": add_tags_str,
                         "rule_id": rule.get("id")
                     })

        # 4. Apply Updates to Main DataFrame
        if not updates:
            return df
            
        print(f"    [+] Correlation Verified: Updating {len(updates)} patterns with real timestamps.")
        
        # [PERF v10.0] Batch Expression: Build all conditions and apply once
        # Instead of looping with df.with_columns() per update, we build chained expressions
        ts_expr = pl.col("Timestamp_UTC")
        score_expr = pl.col("Threat_Score")
        tag_expr = pl.col("Tag")
        insight_expr = pl.col("Insight")
        
        for up in updates:
            cond = (pl.col("Source") == "PowerShell History") & \
                   (pl.col("Action").str.contains(f"(?i){up['history_pattern']}"))
            
            ts_expr = pl.when(cond).then(pl.lit(up['timestamp'])).otherwise(ts_expr)
            score_expr = pl.when(cond).then(score_expr + up['score_boost']).otherwise(score_expr)
            tag_expr = pl.when(cond).then(pl.format("{},{}", tag_expr, pl.lit(up['add_tags']))).otherwise(tag_expr)
            insight_expr = pl.when(cond).then(pl.format("{}\n[Correlation Verified: matched EID 4104/4688]", insight_expr)).otherwise(insight_expr)
        
        # Single with_columns call for all updates
        df = df.with_columns([
            ts_expr.alias("Timestamp_UTC"),
            score_expr.alias("Threat_Score"),
            tag_expr.str.replace(r"^,", "").alias("Tag"),
            insight_expr.alias("Insight")
        ])
            
        return df
import yaml
import polars as pl
from pathlib import Path
import re
import sys

# ============================================================
#  SH_ThemisLoader v1.2 [AION Enabled]
#  Mission: Compile YAML rules into Polars Expressions.
#  Update: Added 'persistence_targets' loader for AION.
# ============================================================

class ThemisLoader:
    def __init__(self, rule_path="rules/triage_rules.yaml"):
        self.rule_path = Path(rule_path)
        self.noise_rules = []
        self.threat_rules = []
        self.persistence_targets = [] # [NEW] AION用
        self._load_yaml()

    def _load_yaml(self):
        """
        YAMLファイルをロードし、各種ルールをメモリに展開するっス。
        """
        if not self.rule_path.exists():
            print(f"[!] Themis Warning: Rule file '{self.rule_path}' not found. Running without external laws.")
            return

        try:
            with open(self.rule_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data:
                    self.noise_rules = data.get("noise_filters", [])
                    self.threat_rules = data.get("threat_signatures", [])
                    # [NEW] AIONスキャン対象のロード
                    self.persistence_targets = data.get("persistence_targets", [])
            
            print(f"[*] Themis Loaded: {len(self.noise_rules)} Noise, {len(self.threat_rules)} Threat, {len(self.persistence_targets)} Targets.")
        except Exception as e:
            print(f"[!] Themis Error: Failed to load YAML ({e})")

    def get_persistence_targets(self, category="Registry"):
        """
        [NEW] 指定カテゴリのスキャン対象パターン（Regexリスト）を返すっス。
        """
        patterns = []
        for target in self.persistence_targets:
            if target.get("category") == category:
                p = target.get("pattern")
                if p: patterns.append(p)
        return patterns

    def _build_condition(self, col_name, condition, pattern):
        if condition == "contains":
            return pl.col(col_name).str.contains(pattern, literal=True)
        elif condition == "regex" or condition == "matches":
            return pl.col(col_name).str.contains(pattern)
        elif condition == "ends_with":
            return pl.col(col_name).str.ends_with(pattern)
        elif condition == "starts_with":
            return pl.col(col_name).str.starts_with(pattern)
        elif condition == "eq" or condition == "equals":
            return pl.col(col_name) == pattern
        elif condition == "is_in":
            if isinstance(pattern, list):
                return pl.col(col_name).is_in(pattern)
            else:
                return pl.col(col_name) == pattern
        return pl.lit(False)

    def get_noise_filter_expr(self, available_columns):
        exprs = []
        for rule in self.noise_rules:
            target = rule.get("target")
            if target not in available_columns: continue
            expr = self._build_condition(target, rule.get("condition"), rule.get("pattern"))
            exprs.append(expr)
        if not exprs: return pl.lit(False)
        return pl.any_horizontal(exprs)

    def apply_threat_scoring(self, lf):
        cols = lf.collect_schema().names()
        if "Threat_Score" not in cols:
            lf = lf.with_columns(pl.lit(0, dtype=pl.Int64).alias("Threat_Score"))
        else:
            lf = lf.with_columns(pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0))

        if "Threat_Tag" not in cols:
            lf = lf.with_columns(pl.lit("", dtype=pl.Utf8).alias("Threat_Tag"))
        else:
            lf = lf.with_columns(pl.col("Threat_Tag").cast(pl.Utf8).fill_null(""))

        for rule in self.threat_rules:
            target = rule.get("target")
            if target not in cols: continue
            condition_expr = self._build_condition(target, rule.get("condition"), rule.get("pattern"))
            score_boost = rule.get("score", 0)
            tag_name = rule.get("tag", "THREAT")

            lf = lf.with_columns([
                pl.when(condition_expr)
                .then(pl.col("Threat_Score") + score_boost)
                .otherwise(pl.col("Threat_Score"))
                .alias("Threat_Score"),

                pl.when(condition_expr)
                .then(
                    pl.when(pl.col("Threat_Tag") == "")
                    .then(pl.lit(tag_name))
                    .otherwise(pl.concat_str([pl.col("Threat_Tag"), pl.lit(f",{tag_name}")], separator=""))
                )
                .otherwise(pl.col("Threat_Tag"))
                .alias("Threat_Tag")
            ])
        return lf

    def suggest_new_noise_rules(self, df, threshold_ratio=50):
        total_count = df.height
        if total_count == 0: return []
        threat_count = df.filter(pl.col("Threat_Score") > 0).height
        if threat_count == 0: threat_count = 1
        ratio = total_count / threat_count
        if ratio < threshold_ratio: return []

        print(f"[*] Themis Insight: High Noise Ratio detected ({ratio:.1f}x). Analyzing noise candidates...")
        noise_candidates = df.filter(pl.col("Threat_Score") == 0)
        
        # AION用にTarget_FileNameやFull_Pathも候補に入れる
        target_cols = ["ParentPath", "Entry_Location", "Target_FileName"]
        suggestions = []
        
        for t_col in target_cols:
            if t_col in df.columns:
                stats = noise_candidates.group_by(t_col).len().sort("len", descending=True).head(3)
                for row in stats.iter_rows(named=True):
                    val = row[t_col]
                    count = row["len"]
                    if val:
                        suggestions.append(f"  - Target: {t_col} | Pattern: {str(val)[:50]} (Count: {count})")
        return suggestions
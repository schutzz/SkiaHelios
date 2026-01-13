import yaml
import polars as pl
from pathlib import Path
import re
import sys

# ============================================================
#  SH_ThemisLoader v2.3 [Tag Normalizer]
#  Mission: Compile YAML rules and Cleanse Threat Tags.
#  Update: Added _normalize_tags to align with set13 style.
# ============================================================

class ThemisLoader:
    def __init__(self, rule_paths=None):
        if rule_paths is None:
            self.rule_paths = ["rules/triage_rules.yaml"]
        else:
            self.rule_paths = [rule_paths] if isinstance(rule_paths, str) else rule_paths

        self.noise_rules = []
        self.threat_rules = []
        self.persistence_targets = []
        self.dual_use_config = {
            "keywords": [],      # Lachesis/Chronos 用
            "noise_paths": []    # Chronos/Pandora 用
        }
        self.sensitive_data = {} # [v5.3] For Sensitive Document Detection
        
        # [NEW] Tag Mapping Dictionary
        self.tag_map = {
            "attack.credential-access": "CREDENTIALS",
            "attack.persistence": "PERSISTENCE",
            "attack.privilege-escalation": "PRIVESC",
            "attack.defense-evasion": "EVASION",
            "attack.command-and-control": "C2",
            "attack.discovery": "DISCOVERY",
            "attack.execution": "EXECUTION",
            "attack.impact": "IMPACT",
            "attack.initial-access": "INIT_ACCESS",
            "attack.lateral-movement": "LATERAL",
            "attack.collection": "COLLECTION",
            "attack.exfiltration": "EXFILTRATION",
            "attack.t1003": "CREDENTIAL_DUMP",
            "attack.t1055": "INJECTION",
            "attack.t1059": "CMD_EXEC",
        }
        
        self._load_all_yamls()

    def _load_all_yamls(self):
        total_loaded = 0
        for path_str in self.rule_paths:
            p = Path(path_str)
            if not p.exists():
                print(f"[!] Themis Warning: Rule file '{p}' not found. Skipping.")
                continue
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data:
                        noise_data = data.get("noise_filters", [])
                        if isinstance(noise_data, list):
                            self.noise_rules.extend(noise_data)
                        elif isinstance(noise_data, dict):
                            # [FIX] Handle intel_signatures.yaml style key-value noise config
                            paths = noise_data.get("paths", [])
                            for p in paths:
                                self.noise_rules.append({
                                    "target": "Normalized_Path", 
                                    "condition": "regex", 
                                    "pattern": p
                                })
                        self.threat_rules.extend(data.get("threat_signatures", []))
                        self.persistence_targets.extend(data.get("persistence_targets", []))
                        
                        # [NEW] Enhanced Intel Loading (for deep intel_signatures.yaml support)
                        self._load_intel_section(data, "anti_forensics_tools")
                        self._load_intel_section(data, "remote_access_tools")
                        
                        # [NEW] Load Dual-Use Tools Configuration
                        if "dual_use_tools" in data:
                            for tool in data["dual_use_tools"]:
                                self.dual_use_config["keywords"].extend([k.lower() for k in tool.get("keywords", [])])
                                self.dual_use_config["noise_paths"].extend([p.lower() for p in tool.get("noise_paths", [])])

                        # [v5.3] Load Sensitive Data Config
                        if "sensitive_data" in data:
                             self.sensitive_data = data["sensitive_data"]
                        
                        total_loaded += 1
            except Exception as e:
                print(f"[!] Themis Error: Failed to load {p} ({e})")
        # print(f"[*] Themis Logic Assembled: {len(self.noise_rules)} Noise, {len(self.threat_rules)} Threat Rules from {total_loaded} files.")

    def _load_intel_section(self, data, key):
        """
        [NEW] Load specialized intel sections (flatten nested structure)
        """
        section = data.get(key)
        if not section: return
        
        # Default targets to check for generic patterns if target not specified
        default_targets = ["FileName", "Ghost_FileName", "Target_Path", "CommandLine", "Image"]
        
        for category, rules in section.items():
            if not isinstance(rules, list): continue
            for rule in rules:
                pat = rule.get("pat")
                if not pat: continue
                
                # Use specified target or defaults
                targets = [rule.get("target")] if rule.get("target") else default_targets
                
                for tgt in targets:
                    new_rule = {
                        "target": tgt,
                        "condition": "regex", 
                        "pattern": pat,
                        "score": rule.get("score", 0),
                        "tag": rule.get("tag", "THREAT")
                    }
                    self.threat_rules.append(new_rule)

    def get_persistence_targets(self, category="Registry"):
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

    # --- [NEW] Helper Methods for Dual-Use ---
    
    def get_dual_use_keywords(self):
        """報告書に強制掲載すべきキーワードリストを返す"""
        return list(set(self.dual_use_config["keywords"]))

    def get_tool_noise_paths(self):
        """ツールごとの除外すべきゴミフォルダリストを返す"""
        return list(set(self.dual_use_config["noise_paths"]))

    def _clean_tag(self, raw_tag):
        """
        [NEW] Sigmaの長いタグを整形・翻訳するヘルパー関数
        """
        if not raw_tag: return ""
        # カンマ区切りで分割
        tags = [t.strip() for t in raw_tag.split(",")]
        clean_tags = set()
        
        for t in tags:
            # 1. 既知のマッピングがあれば変換
            if t in self.tag_map:
                clean_tags.add(self.tag_map[t])
            # 2. MITRE ID (attack.tXXXX) は可読性が低いので、マッピングになければ除外
            elif t.startswith("attack.t"):
                continue 
            # 3. その他の "attack." 系は、"attack." を取って大文字化
            elif t.startswith("attack."):
                clean_tags.add(t.replace("attack.", "").upper())
            # 4. AION独自のタグ (WEBSHELL等) はそのまま採用
            else:
                clean_tags.add(t.upper())
                
        # 優先度の高いタグ順に並べる（WEBSHELLなどを先頭に）
        sorted_tags = sorted(list(clean_tags), key=lambda x: 0 if x in ["WEBSHELL", "ROOTKIT", "RANSOMWARE"] else 1)
        return ",".join(sorted_tags)

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
            
            # [UPDATE] タグの正規化処理をここで適用
            raw_tag = rule.get("tag", "THREAT")
            cleaned_tag = self._clean_tag(raw_tag)

            lf = lf.with_columns([
                pl.when(condition_expr)
                .then(pl.col("Threat_Score") + score_boost)
                .otherwise(pl.col("Threat_Score"))
                .alias("Threat_Score"),

                pl.when(condition_expr)
                .then(
                    pl.when(pl.col("Threat_Tag") == "")
                    .then(pl.lit(cleaned_tag))
                    .otherwise(pl.concat_str([pl.col("Threat_Tag"), pl.lit(f",{cleaned_tag}")], separator=""))
                )
                .otherwise(pl.col("Threat_Tag"))
                .alias("Threat_Tag")
            ])
            
        # 最後に重複タグを整理（Pandora側でプレフィックスにする際に綺麗に見せるため）
        return lf

    def suggest_new_noise_rules(self, df, threshold_ratio=50):
        # ... (変更なし) ...
        total_count = df.height
        if total_count == 0: return []
        threat_count = df.filter(pl.col("Threat_Score") > 0).height
        if threat_count == 0: threat_count = 1
        ratio = total_count / threat_count
        if ratio < threshold_ratio: return []

        print(f"[*] Themis Insight: High Noise Ratio detected ({ratio:.1f}x). Analyzing noise candidates...")
        noise_candidates = df.filter(pl.col("Threat_Score") == 0)
        
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
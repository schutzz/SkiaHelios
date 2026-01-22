import yaml
import polars as pl
from pathlib import Path
import re
import sys

# ============================================================
#  SH_ThemisLoader v3.0 [Centralized Rule Engine]
#  Mission: Compile YAML rules, Noise Filters, and Scoring.
#  Update: Added filter_rules.yaml and scoring_rules.yaml support.
# ============================================================

class ThemisLoader:
    def __init__(self, rule_paths=None):
        if rule_paths is None:
            self.rule_paths = [
                "rules/triage_rules.yaml",
                "rules/filter_rules.yaml",       # [v3.0] Centralized Noise Filters
                "rules/scoring_rules.yaml",      # [v3.0] Centralized Threat Scores
                "rules/sigma_file_event_filtered.yaml",  # Sigma Integration
                "rules/sigma_custom.yaml"        # Custom Rules (Metasploit, Impacket, etc.)
            ]
        else:
            self.rule_paths = [rule_paths] if isinstance(rule_paths, str) else rule_paths

        self.noise_rules = []
        self.threat_rules = []
        self.persistence_targets = []
        self.dual_use_config = {
            "keywords": [],      # Lachesis/Chronos 用
            "noise_paths": [],   # Chronos/Pandora 用
            "folders": [],       # [v3.0] Dual-Use Tool Folders
            "protected_binaries": []  # [v3.0] Protected Executables
        }
        self.sensitive_data = {} # [v5.3] For Sensitive Document Detection
        self.scoring_rules = []  # [v3.0] Centralized Scoring Rules
        
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
                        
                        # [v3.0] Load Dual-Use Tools Configuration (new format)
                        if "dual_use_tools" in data:
                            du = data["dual_use_tools"]
                            # Handle both old (list) and new (dict) formats
                            if isinstance(du, dict):
                                self.dual_use_config["folders"].extend([f.lower() for f in du.get("folders", [])])
                                self.dual_use_config["protected_binaries"].extend([b.lower() for b in du.get("protected_binaries", [])])
                            elif isinstance(du, list):
                                for tool in du:
                                    self.dual_use_config["keywords"].extend([k.lower() for k in tool.get("keywords", [])])
                                    self.dual_use_config["noise_paths"].extend([p.lower() for p in tool.get("noise_paths", [])])

                        # [v3.0] Load Scoring Rules
                        if "threat_scores" in data:
                            self.scoring_rules.extend(data["threat_scores"])

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

    def _dedupe_tags_expr(self, lf):
        """
        [v3.2 OPTIMIZED] Deduplicate and prioritize tags using Vectorized Polars expressions.
        Replaces slow Python map_elements with native string manipulation.
        """
        # Priority mapping (Prefix with !XX_ to force sort order)
        # Note: '!' comes before letters in ASCII
        priority_map = [
            ("WEBSHELL", "!01_WEBSHELL"),
            ("ROOTKIT", "!02_ROOTKIT"),
            ("RANSOMWARE", "!03_RANSOMWARE"),
            ("MIMIKATZ", "!04_MIMIKATZ"),
            ("C2", "!05_C2"),
            ("CREDENTIAL_DUMP", "!06_CREDENTIAL_DUMP"),
            ("ANTI_FORENSICS", "!07_ANTI_FORENSICS"),
            ("LATERAL", "!08_LATERAL"),
            ("PERSISTENCE", "!09_PERSISTENCE"),
            ("PRIVESC", "!10_PRIVESC"),
            ("EXECUTION", "!11_EXECUTION"),
            ("EVASION", "!12_EVASION")
        ]

        # 1. Apply Prefixes (Vectorized String Replace)
        # Doing this on the concatenated string is faster than list.eval
        tag_col = pl.col("Threat_Tag")
        for key, prefixed in priority_map:
            tag_col = tag_col.str.replace(key, prefixed, literal=True)

        # 2. Split, Unique, Sort, Join
        # This sorts by the prefixed value (!XX_...) thus enforcing priority
        tag_col = tag_col.str.split(",").list.unique().list.sort().list.join(",")

        # 3. Remove Prefixes (Revert)
        for key, prefixed in priority_map:
            tag_col = tag_col.str.replace(prefixed, key, literal=True)

        return lf.with_columns(tag_col.alias("Threat_Tag"))

    def get_noise_filter_expr(self, available_columns):
        """
        [FIX v2.0] Column-Aware Noise Filtering
        - Falls back to Target_Path if ParentPath is missing
        - Uses case-insensitive matching for path patterns
        """
        # Column fallback mapping
        COLUMN_FALLBACKS = {
            "ParentPath": ["ParentPath", "Target_Path", "Source_File"],
            "FileName": ["FileName", "Action", "Target_FileName"]
        }
        
        exprs = []
        for rule in self.noise_rules:
            target = rule.get("target")
            condition = rule.get("condition")
            pattern = rule.get("pattern")
            
            # Find available column (with fallback)
            actual_target = None
            if target in available_columns:
                actual_target = target
            elif target in COLUMN_FALLBACKS:
                for fallback in COLUMN_FALLBACKS[target]:
                    if fallback in available_columns:
                        actual_target = fallback
                        break
            
            if actual_target is None:
                continue
            
            # [FIX] Case-insensitive path matching
            if condition == "contains" and target in ["ParentPath", "Target_Path", "Source_File"]:
                # Normalize to lowercase for reliable matching
                expr = pl.col(actual_target).str.to_lowercase().str.contains(pattern.lower(), literal=True)
            else:
                expr = self._build_condition(actual_target, condition, pattern)
            
            exprs.append(expr)
        
        if not exprs: 
            return pl.lit(False)
        return pl.any_horizontal(exprs)

    def get_noise_regex_list(self):
        """
        [v6.7] Returns a list of regex strings for renderer-side noise filtering.
        Converts YAML conditions (contains, ends_with, etc.) into equivalent regex.
        """
        regex_list = []
        for rule in self.noise_rules:
            pattern = rule.get("pattern")
            condition = rule.get("condition", "contains")
            
            if not pattern: continue
            
            # Escape pattern for safest matching if it's supposed to be literal
            import re
            
            if condition == "contains":
                # Basic contains -> raw pattern (mostly paths)
                regex_list.append(re.escape(pattern))
            elif condition == "regex" or condition == "matches":
                # Already regex
                regex_list.append(pattern)
            elif condition == "ends_with":
                regex_list.append(re.escape(pattern) + "$")
            elif condition == "starts_with":
                regex_list.append("^" + re.escape(pattern))
            elif condition == "is_in":
                if isinstance(pattern, list):
                    patterns = [re.escape(p) for p in pattern]
                    regex_list.append("^(" + "|".join(patterns) + ")$")
                else:
                    regex_list.append("^" + re.escape(pattern) + "$")
        
        return list(set(regex_list))

    # --- [NEW] Helper Methods for Dual-Use ---
    
    def get_dual_use_keywords(self):
        """報告書に強制掲載すべきキーワードリストを返す"""
        return list(set(self.dual_use_config["keywords"]))

    def get_tool_noise_paths(self):
        """ツールごとの除外すべきゴミフォルダリストを返す"""
        return list(set(self.dual_use_config["noise_paths"]))

    def get_dual_use_filter_expr(self, available_columns):
        """
        [v3.0] Dual-Use Tool Trap: ツールフォルダ内の正規バイナリ以外をノイズ判定
        Returns: Polars expression that evaluates to True for noise items
        """
        # Require both columns
        if "ParentPath" not in available_columns:
            return pl.lit(False)
        
        fn_col = "FileName" if "FileName" in available_columns else (
            "Action" if "Action" in available_columns else (
            "Ghost_FileName" if "Ghost_FileName" in available_columns else None))
        
        if fn_col is None:
            return pl.lit(False)
        
        # Get from config or use defaults
        folders = self.dual_use_config.get("folders", []) or [
            "nmap", "wireshark", "python", "perl", "ruby", "java", "jdk", "jre", "tcl", "tor browser"
        ]
        protected = self.dual_use_config.get("protected_binaries", []) or [
            "nmap.exe", "wireshark.exe", "python.exe", "perl.exe", "ruby.exe", "java.exe", "tor.exe"
        ]
        
        # Build expressions
        is_tool_dir = pl.lit(False)
        for folder in folders:
            is_tool_dir = is_tool_dir | pl.col("ParentPath").str.to_lowercase().str.contains(folder, literal=True)
        
        is_protected_binary = pl.col(fn_col).str.to_lowercase().is_in(protected)
        
        # Noise = in tool folder AND NOT a protected binary
        return (is_tool_dir & (~is_protected_binary))

    def apply_scoring_rules(self, lf):
        """
        [v3.0 BATCHED] Apply centralized scoring rules from scoring_rules.yaml
        Updated to use Batch Expression Architecture (Expression List -> Single Apply)
        to eliminate memory fragmentation and CPU overhead of sequential updates.
        """
        cols = lf.collect_schema().names()
        
        # Ensure base columns exist
        if "Threat_Score" not in cols:
            lf = lf.with_columns(pl.lit(0, dtype=pl.Int64).alias("Threat_Score"))
        else:
            lf = lf.with_columns(pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0))

        if "Threat_Tag" not in cols:
            lf = lf.with_columns(pl.lit("", dtype=pl.Utf8).alias("Threat_Tag"))
        else:
            lf = lf.with_columns(pl.col("Threat_Tag").cast(pl.Utf8).fill_null(""))
        
        # 1. Build Expression Lists (No DataFrame operations yet)
        score_accumulators = []
        tag_accumulators = []
        
        for rule in self.scoring_rules:
            pattern = rule.get("pattern")
            target = rule.get("target", "Action")
            score = rule.get("score", 0)
            tags = rule.get("tags", [])
            match_mode = rule.get("match_mode", "contains")
            
            if target not in cols:
                continue
            
            # Build condition based on match_mode
            if match_mode == "exact":
                condition = pl.col(target).str.to_lowercase() == pattern.lower()
            elif match_mode == "regex":
                condition = pl.col(target).str.to_lowercase().str.contains(pattern)
            else:  # contains
                condition = pl.col(target).str.to_lowercase().str.contains(pattern.lower(), literal=True)
            
            # Add to accumulators
            if score > 0:
                score_accumulators.append(pl.when(condition).then(score).otherwise(0))
            
            if tags:
                tag_str = ",".join(tags) 
                tag_accumulators.append(pl.when(condition).then(pl.lit(tag_str)).otherwise(pl.lit(None)))
            elif score > 0:
                 # If score but no tags, use default generic tag from rule or skip? 
                 # Original code defaulted to "HIGH_VALUE_TARGET" if tags empty?
                 # Let's check original logic: "tag_str = ... if tags else 'HIGH_VALUE_TARGET'"
                 tag_str = "HIGH_VALUE_TARGET"
                 tag_accumulators.append(pl.when(condition).then(pl.lit(tag_str)).otherwise(pl.lit(None)))

        # 2. Apply Batched Expressions (Single Pass)
        if score_accumulators:
            # Sum vertical to get score per row? No, sum_horizontal across the listed expressions
            lf = lf.with_columns(
                (pl.col("Threat_Score") + pl.sum_horizontal(score_accumulators)).alias("Threat_Score")
            )
            
        if tag_accumulators:
            # Concat new tags
            new_tags_expr = pl.concat_str(tag_accumulators, separator=",", ignore_nulls=True)
            
            lf = lf.with_columns(
                pl.when((pl.col("Threat_Tag") == "") | (pl.col("Threat_Tag").is_null()))
                .then(new_tags_expr)
                .otherwise(
                    pl.concat_str([pl.col("Threat_Tag"), new_tags_expr], separator=",", ignore_nulls=True)
                )
                .alias("Threat_Tag")
            )
            
        # 3. Deduplicate Tags (Vectorized)
        return self._dedupe_tags_expr(lf)


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
        
        # [FIX v10.0] Column Name Fallback: MFT data may have 'Action' instead of 'FileName'
        # Create FileName alias from Action if it doesn't exist (for Sigma rule compatibility)
        if "FileName" not in cols and "Action" in cols:
            lf = lf.with_columns(pl.col("Action").alias("FileName"))
            cols = lf.collect_schema().names()  # Refresh column list
        
        if "Threat_Score" not in cols:
            lf = lf.with_columns(pl.lit(0, dtype=pl.Int64).alias("Threat_Score"))
        else:
            lf = lf.with_columns(pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0))

        if "Threat_Tag" not in cols:
            lf = lf.with_columns(pl.lit("", dtype=pl.Utf8).alias("Threat_Tag"))
        else:
            lf = lf.with_columns(pl.col("Threat_Tag").cast(pl.Utf8).fill_null(""))

        # [FIX v7.0] Artifact-Type Aware Sigma Scoring
        # Process_creation rules should NOT apply to MFT (file existence ≠ execution)
        has_artifact_type = "Artifact_Type" in cols
        is_mft_expr = None
        if has_artifact_type:
            is_mft_expr = pl.col("Artifact_Type").str.to_lowercase().str.contains("mft")

        # [OPTIMIZED v6.1] Batch Rule Application with Chunking
        # Splitting 1000+ rules into chunks of 50 to avoid exploding the LogicalPlan
        
        CHUNK_SIZE = 50
        all_rules = [r for r in self.threat_rules if r.get("target") in cols]
        
        for i in range(0, len(all_rules), CHUNK_SIZE):
            chunk = all_rules[i : i + CHUNK_SIZE]
            score_accumulators = []
            tag_accumulators = []
            
            for rule in chunk:
                target = rule.get("target")
                pattern = rule.get("pattern")
                
                # [Fix] Prevent empty/short patterns from matching everything
                if not pattern or (isinstance(pattern, str) and len(pattern) < 2):
                    continue
                
                # [FIX v7.0] Category-aware rule application
                # Default to "process_creation" if category not specified (Sigma rules)
                category = rule.get("category", "process_creation")
                
                condition_expr = self._build_condition(target, rule.get("condition"), pattern)
                
                # For MFT artifacts, skip process_creation rules (file_event is OK)
                if has_artifact_type and is_mft_expr is not None and category == "process_creation":
                    # Apply rule ONLY to non-MFT rows
                    condition_expr = condition_expr & is_mft_expr.not_()
                    
                score_boost = rule.get("score", 0)
                
                raw_tag = rule.get("tag", "THREAT")
                
                # Score Accumulation
                if score_boost > 0:
                    score_accumulators.append(pl.when(condition_expr).then(score_boost).otherwise(0))
                    
                # Tag Accumulation
                tag_accumulators.append(pl.when(condition_expr).then(pl.lit(raw_tag)).otherwise(pl.lit(None)))
            
            # Apply Chunk
            if score_accumulators:
                lf = lf.with_columns(
                    (pl.col("Threat_Score") + pl.sum_horizontal(score_accumulators)).alias("Threat_Score")
                )
            
            if tag_accumulators:
                new_tags_chunk = pl.concat_str(tag_accumulators, separator=",", ignore_nulls=True)
                lf = lf.with_columns(
                     pl.when((pl.col("Threat_Tag") == "") | (pl.col("Threat_Tag").is_null()))
                    .then(new_tags_chunk)
                    .otherwise(
                        pl.concat_str([pl.col("Threat_Tag"), new_tags_chunk], separator=",", ignore_nulls=True)
                    )
                    .alias("Threat_Tag")
                )
        
        # Finally Dedupe Tags
        return self._dedupe_tags_expr(lf)

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
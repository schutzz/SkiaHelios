"""
SkiaHelios Compiled Rule Engine v1.0
Pre-compiles regex patterns at startup for optimal performance.

Usage:
    engine = CompiledRuleEngine(threat_scores_list)
    score, tags = engine.match(path, base_score)
"""

import re
from typing import List, Tuple, Optional, Any


class CompiledRule:
    """
    A single rule with precompiled regex pattern (if applicable).
    [v2.0] Added negative_context support for FP reduction.
    """
    __slots__ = ['pattern', 'pattern_lower', 'score', 'tags', 'target', 'match_mode', 
                 'compiled_regex', 'negative_contexts']
    
    def __init__(self, rule_dict: dict):
        self.pattern = rule_dict.get('pattern', '')
        self.pattern_lower = self.pattern.lower()
        self.score = int(rule_dict.get('score', 0))
        self.tags = rule_dict.get('tags', [])
        self.target = rule_dict.get('target', 'Action')
        self.match_mode = rule_dict.get('match_mode', 'contains')
        self.compiled_regex: Optional[re.Pattern] = None
        
        # [v2.0] Negative context for FP reduction
        self.negative_contexts = rule_dict.get('negative_context', [])
        
        # Precompile regex patterns
        if self.match_mode == 'regex':
            try:
                self.compiled_regex = re.compile(self.pattern, re.IGNORECASE)
            except re.error as e:
                print(f"[!] Invalid regex pattern '{self.pattern}': {e}")
                self.compiled_regex = None
    
    def match(self, text: str) -> bool:
        """
        Check if this rule matches the given text.
        Uses precompiled regex for 'regex' mode.
        """
        if not text:
            return False
        
        text_lower = text.lower()
        
        is_match = False
        
        if self.match_mode == 'contains':
            is_match = self.pattern_lower in text_lower
        elif self.match_mode == 'exact':
            # Extract filename for exact match
            filename = text_lower.split('\\')[-1].split('/')[-1]
            is_match = filename == self.pattern_lower
        elif self.match_mode == 'startswith':
            is_match = text_lower.startswith(self.pattern_lower)
        elif self.match_mode == 'endswith':
            is_match = text_lower.endswith(self.pattern_lower)
        elif self.match_mode == 'regex':
            if self.compiled_regex:
                is_match = bool(self.compiled_regex.search(text_lower))
        
        # [v2.0] Check negative context if matched
        if is_match and self.negative_contexts:
            for ctx in self.negative_contexts:
                # Condition: path_contains
                # If ANY negative condition matches, the rule match is invalidated (False Positive)
                p_contains = ctx.get('path_contains')
                if p_contains:
                    if p_contains.lower() in text_lower:
                        # print(f"[DEBUG] Negative Context Hit: '{p_contains}' in '{text_lower}' -> Ignoring Rule")
                        return False
                
        return is_match


class CompiledRuleEngine:
    """
    High-performance rule matching engine with precompiled patterns.
    
    Benefits:
    - Regex patterns compiled once at init, not per-event
    - Pattern strings converted to lowercase once
    - Efficient batch matching
    """
    
    def __init__(self, threat_scores: List[dict]):
        """
        Initialize engine with list of rule dictionaries from YAML.
        
        Args:
            threat_scores: List of rule dicts from scoring_rules.yaml
        """
        self.rules: List[CompiledRule] = []
        self._compile_rules(threat_scores)
        
    def _compile_rules(self, threat_scores: List[dict]):
        """Compile all rules at initialization"""
        compiled_count = 0
        regex_count = 0
        
        for rule_dict in threat_scores:
            rule = CompiledRule(rule_dict)
            self.rules.append(rule)
            compiled_count += 1
            if rule.match_mode == 'regex' and rule.compiled_regex:
                regex_count += 1
        
        if regex_count > 0:
            print(f"    [+] CompiledRuleEngine: {compiled_count} rules loaded, {regex_count} regex patterns precompiled.")
    
    def match(self, path: str, base_score: int = 0) -> Tuple[int, List[str]]:
        """
        Match path against all rules and return aggregated score and tags.
        
        Args:
            path: File path or text to match
            base_score: Starting score to add to
            
        Returns:
            Tuple of (total_score, list_of_tags)
        """
        total_score = base_score
        tags: List[str] = []
        
        for rule in self.rules:
            if rule.match(path):
                total_score += rule.score
                tags.extend(rule.tags)
        
        return total_score, tags
    
    def match_first(self, path: str) -> Optional[Tuple[int, List[str], str]]:
        """
        Return first matching rule (for debugging/tracing).
        
        Returns:
            Tuple of (score, tags, pattern) or None
        """
        for rule in self.rules:
            if rule.match(path):
                return (rule.score, rule.tags, rule.pattern)
        return None
    
    @property
    def rule_count(self) -> int:
        return len(self.rules)


# Factory function for easy integration
def create_rule_engine(intel_module) -> CompiledRuleEngine:
    """
    Create a CompiledRuleEngine from an intel module.
    
    Args:
        intel_module: LachesisIntel instance with get() method
        
    Returns:
        CompiledRuleEngine instance
    """
    threat_scores = intel_module.get('threat_scores', [])
    return CompiledRuleEngine(threat_scores)


# Self-test
if __name__ == "__main__":
    # Test with sample rules
    sample_rules = [
        {"pattern": "mimikatz", "score": 800, "tags": ["CREDENTIAL_THEFT"], "match_mode": "contains"},
        {"pattern": "sync.exe", "score": 300, "tags": ["SYSINTERNALS"], "match_mode": "exact"},
        {"pattern": r"\\\\[a-z0-9]+\\", "score": 150, "tags": ["UNC_PATH"], "match_mode": "regex"},
        {"pattern": ".exe", "score": 50, "tags": ["EXECUTABLE"], "match_mode": "endswith"},
    ]
    
    engine = CompiledRuleEngine(sample_rules)
    print(f"[*] Loaded {engine.rule_count} rules")
    
    test_cases = [
        "C:\\Tools\\mimikatz.exe",
        "C:\\Windows\\System32\\sync.exe",
        "\\\\server\\share\\file.txt",
        "C:\\Users\\test\\notepad.exe",
        "C:\\Users\\test\\document.txt",
    ]
    
    for path in test_cases:
        score, tags = engine.match(path, 0)
        print(f"  {path} -> Score: {score}, Tags: {tags}")

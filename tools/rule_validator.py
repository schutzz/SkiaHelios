"""
SkiaHelios Rule Schema Validator v1.0
Pydantic-based validation for scoring_rules.yaml

Usage:
    from tools.rule_validator import validate_scoring_rules
    rules = validate_scoring_rules("rules/scoring_rules.yaml")
"""

import re
import yaml
from pathlib import Path
from typing import List, Literal, Optional, Any

try:
    from pydantic import BaseModel, Field, field_validator, ValidationError
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    print("[!] Pydantic not installed. Rule validation disabled. Install with: pip install pydantic")


if PYDANTIC_AVAILABLE:
    class ContextModifier(BaseModel):
        """Context-based score modification rule"""
        condition: str
        score_modifier: int
        tag_append: Optional[str] = None

    class ScoringRule(BaseModel):
        """Individual threat scoring rule schema"""
        pattern: str = Field(..., min_length=1)
        score: int = Field(..., ge=0, le=1000)
        tags: List[str] = Field(..., min_length=1)
        target: str = Field(default="Action")
        match_mode: Literal["exact", "contains", "startswith", "endswith", "regex"] = "contains"
        context_modifiers: Optional[List[ContextModifier]] = None
        negative_context: Optional[List[dict]] = None  # [v2.0] FP reduction

        @field_validator('pattern')
        @classmethod
        def validate_regex_pattern(cls, v: str, info) -> str:
            """Validate regex patterns are syntactically correct"""
            # Access match_mode from the data being validated
            data = info.data
            if data.get('match_mode') == 'regex':
                try:
                    re.compile(v)
                except re.error as e:
                    raise ValueError(f"Invalid regex pattern '{v}': {e}")
            return v

        @field_validator('tags')
        @classmethod
        def validate_tags_uppercase(cls, v: List[str]) -> List[str]:
            """Ensure all tags are uppercase for consistency"""
            return [tag.upper() for tag in v]

    class ScoringRulesConfig(BaseModel):
        """Root schema for scoring_rules.yaml"""
        threat_scores: List[ScoringRule] = Field(default_factory=list)
        unc_lateral_tools: Optional[List[str]] = None
        garbage_patterns: Optional[List[str]] = None
        context_boosts: Optional[dict] = None


def validate_scoring_rules(yaml_path: str) -> dict:
    """
    Load and validate scoring_rules.yaml using Pydantic.
    
    Args:
        yaml_path: Path to the YAML file
        
    Returns:
        Validated configuration as dict
        
    Raises:
        SystemExit: If validation fails (prevents tool startup with bad rules)
    """
    path = Path(yaml_path)
    
    if not path.exists():
        print(f"[!] Warning: Scoring rules file not found: {yaml_path}")
        return {"threat_scores": [], "garbage_patterns": [], "unc_lateral_tools": []}
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise SystemExit(f"[FATAL] YAML parsing error in {yaml_path}:\n{e}")
    
    if not raw_data:
        print(f"[!] Warning: Empty scoring rules file: {yaml_path}")
        return {"threat_scores": [], "garbage_patterns": [], "unc_lateral_tools": []}
    
    if not PYDANTIC_AVAILABLE:
        print("[!] Pydantic not available. Skipping schema validation.")
        return raw_data
    
    try:
        validated = ScoringRulesConfig(**raw_data)
        print(f"[+] Scoring rules validated: {len(validated.threat_scores)} rules loaded.")
        return validated.model_dump()
    except ValidationError as e:
        error_details = []
        for err in e.errors():
            loc = " -> ".join(str(x) for x in err['loc'])
            error_details.append(f"  [{loc}] {err['msg']}")
        
        raise SystemExit(
            f"[FATAL] Invalid scoring rules in {yaml_path}:\n" + 
            "\n".join(error_details) +
            "\n\nPlease fix the YAML file and try again."
        )


def get_validated_rules(intel_base_path: str = None) -> dict:
    """
    Convenience function to load validated rules from default location.
    
    Args:
        intel_base_path: Base path to SkiaHelios root (auto-detected if None)
        
    Returns:
        Validated rules dict
    """
    if intel_base_path:
        yaml_path = Path(intel_base_path) / "rules" / "scoring_rules.yaml"
    else:
        # Auto-detect from this file's location
        yaml_path = Path(__file__).parent.parent / "rules" / "scoring_rules.yaml"
    
    return validate_scoring_rules(str(yaml_path))


# Self-test when run directly
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        yaml_file = sys.argv[1]
    else:
        yaml_file = str(Path(__file__).parent.parent / "rules" / "scoring_rules.yaml")
    
    print(f"[*] Validating: {yaml_file}")
    try:
        rules = validate_scoring_rules(yaml_file)
        print(f"[+] SUCCESS: {len(rules.get('threat_scores', []))} threat rules validated.")
        print(f"[+] Garbage patterns: {len(rules.get('garbage_patterns', []))}")
        print(f"[+] UNC lateral tools: {len(rules.get('unc_lateral_tools', []))}")
    except SystemExit as e:
        print(e)
        sys.exit(1)

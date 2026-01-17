"""
SkiaHelios Score Ledger v1.0
Tracks score changes throughout the detection pipeline for explainability.

Usage:
    ledger = ScoreLedger(event_id)
    ledger.record("Base Score", 100, "Initial MFT score")
    ledger.record("YAML Rule", 300, "mimikatz -> CREDENTIAL_THEFT")
    ledger.record("Context Boost", 200, "Suspicious path: Users\\Downloads")
    print(ledger.get_breakdown())
"""

from typing import List, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ScoreEntry:
    """Single score change entry"""
    stage: str
    delta: int
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S.%f")[:-3])
    
    def __str__(self) -> str:
        sign = "+" if self.delta >= 0 else ""
        return f"[{self.stage}] {sign}{self.delta}: {self.reason}"


class ScoreLedger:
    """
    Audit trail for score changes throughout the detection pipeline.
    
    Provides:
    - Full history of all score modifications
    - Human-readable breakdown for reports
    - Debug export for troubleshooting
    """
    
    __slots__ = ['event_id', '_entries', '_base_score', '_final_score', '_tags']
    
    def __init__(self, event_id: str = ""):
        self.event_id = event_id
        self._entries: List[ScoreEntry] = []
        self._base_score: int = 0
        self._final_score: int = 0
        self._tags: List[str] = []
    
    def set_base(self, score: int, source: str = "Initial"):
        """Record the initial/base score"""
        self._base_score = score
        self._final_score = score
        self._entries.append(ScoreEntry("BASE", score, source))
    
    def record(self, stage: str, delta: int, reason: str, tags: List[str] = None):
        """
        Record a score change.
        
        Args:
            stage: Pipeline stage (e.g., "YAML_RULE", "CONTEXT_BOOST", "NOISE_PENALTY")
            delta: Score change (positive for boost, negative for penalty)
            reason: Human-readable explanation
            tags: Optional tags added by this change
        """
        self._entries.append(ScoreEntry(stage, delta, reason))
        self._final_score += delta
        if tags:
            self._tags.extend(tags)
    
    def record_rule_match(self, pattern: str, score: int, tags: List[str]):
        """Convenience method for recording YAML rule matches"""
        tag_str = ", ".join(tags) if tags else "N/A"
        self.record("YAML_RULE", score, f"'{pattern}' -> [{tag_str}]", tags)
    
    def record_context_boost(self, context: str, delta: int):
        """Convenience method for context-based score changes"""
        self.record("CONTEXT", delta, context)
    
    def record_penalty(self, reason: str, delta: int):
        """Convenience method for penalties (negative score changes)"""
        self.record("PENALTY", delta, reason)
    
    @property
    def final_score(self) -> int:
        return max(0, self._final_score)
    
    @property
    def base_score(self) -> int:
        return self._base_score
    
    @property
    def total_delta(self) -> int:
        """Total score change from base"""
        return self._final_score - self._base_score
    
    @property
    def all_tags(self) -> List[str]:
        return list(set(self._tags))
    
    def get_breakdown(self, compact: bool = False) -> str:
        """
        Get human-readable score breakdown.
        
        Args:
            compact: If True, returns single-line format for tables
            
        Returns:
            Formatted string showing all score changes
        """
        if not self._entries:
            return "No score history"
        
        if compact:
            # Single line: "Base:100 +YAML:300 +CTX:200 = 600"
            parts = []
            for entry in self._entries:
                if entry.stage == "BASE":
                    parts.append(f"Base:{entry.delta}")
                else:
                    sign = "+" if entry.delta >= 0 else ""
                    abbrev = entry.stage[:4].upper()
                    parts.append(f"{sign}{abbrev}:{entry.delta}")
            parts.append(f"= {self.final_score}")
            return " ".join(parts)
        
        # Multi-line detailed breakdown
        lines = [f"[Score Breakdown] {self.event_id or 'Event'}"]
        lines.append("-" * 50)
        
        running_total = 0
        for entry in self._entries:
            if entry.stage == "BASE":
                running_total = entry.delta
                lines.append(f"  {entry.stage:12} {entry.delta:+6}  ({entry.reason})")
            else:
                running_total += entry.delta
                lines.append(f"  {entry.stage:12} {entry.delta:+6}  → {running_total:>5}  ({entry.reason})")
        
        lines.append("-" * 50)
        lines.append(f"  {'FINAL':12} {self.final_score:>6}")
        
        if self._tags:
            lines.append(f"  Tags: {', '.join(set(self._tags))}")
        
        return "\n".join(lines)
    
    def to_dict(self) -> dict:
        """Export ledger as dictionary for JSON serialization"""
        return {
            "event_id": self.event_id,
            "base_score": self._base_score,
            "final_score": self.final_score,
            "total_delta": self.total_delta,
            "tags": self.all_tags,
            "entries": [
                {"stage": e.stage, "delta": e.delta, "reason": e.reason, "time": e.timestamp}
                for e in self._entries
            ]
        }
    
    def get_top_contributors(self, n: int = 3) -> List[Tuple[str, int, str]]:
        """Get top N score contributors (excluding BASE)"""
        non_base = [e for e in self._entries if e.stage != "BASE"]
        sorted_entries = sorted(non_base, key=lambda x: abs(x.delta), reverse=True)
        return [(e.reason, e.delta, e.stage) for e in sorted_entries[:n]]


class LedgerManager:
    """
    Manages score ledgers for multiple events.
    Provides bulk operations and reporting.
    """
    
    def __init__(self):
        self._ledgers: dict = {}
    
    def get_or_create(self, event_id: str) -> ScoreLedger:
        """Get existing ledger or create new one for event"""
        if event_id not in self._ledgers:
            self._ledgers[event_id] = ScoreLedger(event_id)
        return self._ledgers[event_id]
    
    def get_high_scorers(self, threshold: int = 500) -> List[ScoreLedger]:
        """Get all ledgers with final score >= threshold"""
        return [l for l in self._ledgers.values() if l.final_score >= threshold]
    
    def export_all(self) -> List[dict]:
        """Export all ledgers as list of dicts"""
        return [l.to_dict() for l in self._ledgers.values()]
    
    def export_to_markdown(self, output_path: str, threshold: int = 500, case_name: str = "") -> str:
        """
        Export high-scoring ledgers to a markdown file.
        
        Args:
            output_path: Directory to write the file
            threshold: Minimum score to include (default: 500)
            case_name: Case identifier for the filename
            
        Returns:
            Path to the generated file
        """
        from pathlib import Path
        from datetime import datetime
        
        high_scorers = self.get_high_scorers(threshold)
        if not high_scorers:
            return ""
        
        # Sort by score descending
        high_scorers.sort(key=lambda x: x.final_score, reverse=True)
        
        lines = [
            f"# Score Breakdown Report",
            f"",
            f"**Case:** {case_name or 'N/A'}  ",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Threshold:** Score >= {threshold}  ",
            f"**Total High-Score Events:** {len(high_scorers)}",
            f"",
            f"---",
            f"",
        ]
        
        # Summary table
        lines.append("## Summary Table")
        lines.append("")
        lines.append("| Rank | Event | Final Score | Top Contributor | Tags |")
        lines.append("|------|-------|-------------|-----------------|------|")
        
        for i, ledger in enumerate(high_scorers[:50], 1):  # Top 50
            event_name = ledger.event_id[:50] + "..." if len(ledger.event_id) > 50 else ledger.event_id
            top_contrib = ledger.get_top_contributors(1)
            top_reason = top_contrib[0][0][:30] if top_contrib else "N/A"
            tags = ", ".join(ledger.all_tags[:3]) if ledger.all_tags else "-"
            lines.append(f"| {i} | `{event_name}` | **{ledger.final_score}** | {top_reason} | {tags} |")
        
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # Detailed breakdowns for top 20
        lines.append("## Detailed Breakdowns (Top 20)")
        lines.append("")
        
        for i, ledger in enumerate(high_scorers[:20], 1):
            lines.append(f"### {i}. {ledger.event_id}")
            lines.append("")
            lines.append(f"**Final Score:** {ledger.final_score} | **Base:** {ledger.base_score} | **Delta:** {ledger.total_delta:+d}")
            lines.append("")
            lines.append("```")
            for entry in ledger._entries:
                sign = "+" if entry.delta >= 0 else ""
                lines.append(f"  [{entry.stage:12}] {sign}{entry.delta:>5}  {entry.reason}")
            lines.append("```")
            lines.append("")
            if ledger.all_tags:
                lines.append(f"**Tags:** `{', '.join(ledger.all_tags)}`")
            lines.append("")
            lines.append("---")
            lines.append("")
        
        # Write file
        outdir = Path(output_path)
        outdir.mkdir(parents=True, exist_ok=True)
        filename = f"Score_Breakdown_{case_name}.md" if case_name else "Score_Breakdown.md"
        filepath = outdir / filename
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        
        print(f"    [+] Score Breakdown exported: {filepath} ({len(high_scorers)} events)")
        return str(filepath)


# Self-test
if __name__ == "__main__":
    # Create a sample ledger
    ledger = ScoreLedger("C:\\Tools\\mimikatz.exe")
    
    ledger.set_base(100, "MFT Artifact Score")
    ledger.record_rule_match("mimikatz", 800, ["CREDENTIAL_THEFT"])
    ledger.record_context_boost("Path in Users\\Downloads", 200)
    ledger.record_penalty("System path detected", -50)
    
    print(ledger.get_breakdown())
    print()
    print(f"Compact: {ledger.get_breakdown(compact=True)}")
    print()
    print(f"Top contributors: {ledger.get_top_contributors()}")

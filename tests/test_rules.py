"""
SkiaHelios Rule Unit Testing Framework v1.0
Test scoring rules independently without running the full pipeline.

Usage:
    python tests/test_rules.py                    # Run all tests
    python tests/test_rules.py -v                 # Verbose output
    python tests/test_rules.py TestMimikatz       # Run specific test class
"""

import sys
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.compiled_rule_engine import CompiledRuleEngine
from tools.rule_validator import validate_scoring_rules


class RuleTestCase(unittest.TestCase):
    """Base class for rule testing with shared setup"""
    
    @classmethod
    def setUpClass(cls):
        """Load rules once for all tests in the class"""
        yaml_path = Path(__file__).parent.parent / "rules" / "scoring_rules.yaml"
        rules_data = validate_scoring_rules(str(yaml_path))
        cls.engine = CompiledRuleEngine(rules_data.get("threat_scores", []))
    
    def assertRuleMatches(self, path: str, expected_min_score: int, expected_tags: list = None, msg: str = None):
        """
        Assert that a path matches rules and achieves minimum expected score.
        
        Args:
            path: File path to test
            expected_min_score: Minimum score the path should achieve
            expected_tags: Optional list of tags that must be present
            msg: Optional message on failure
        """
        score, tags = self.engine.match(path, 0)
        self.assertGreaterEqual(
            score, expected_min_score,
            msg or f"Path '{path}' scored {score}, expected >= {expected_min_score}"
        )
        if expected_tags:
            for tag in expected_tags:
                self.assertIn(
                    tag, tags,
                    msg or f"Path '{path}' missing tag '{tag}'. Got: {tags}"
                )
    
    def assertRuleNotMatches(self, path: str, max_score: int = 0, msg: str = None):
        """
        Assert that a path does NOT trigger high-scoring rules.
        
        Args:
            path: File path to test
            max_score: Maximum allowed score (should be low/zero)
            msg: Optional message on failure
        """
        score, _ = self.engine.match(path, 0)
        self.assertLessEqual(
            score, max_score,
            msg or f"Path '{path}' unexpectedly scored {score}, expected <= {max_score}"
        )


# ============================================================
# Test Cases for Critical Tools
# ============================================================

class TestCredentialTheftTools(RuleTestCase):
    """Test rules for credential theft tools"""
    
    def test_mimikatz_detection(self):
        """Mimikatz should be detected with high score"""
        self.assertRuleMatches(
            "C:\\Tools\\mimikatz.exe",
            expected_min_score=500,
            expected_tags=["CREDENTIAL_THEFT"]
        )
    
    def test_mimikatz_in_temp(self):
        """Mimikatz in temp folder should still be detected"""
        self.assertRuleMatches(
            "C:\\Users\\Admin\\AppData\\Local\\Temp\\mimikatz_trunk\\x64\\mimikatz.exe",
            expected_min_score=500
        )
    
    def test_procdump_detection(self):
        """Procdump (credential dumping) should be detected"""
        self.assertRuleMatches(
            "C:\\Windows\\Temp\\procdump64.exe",
            expected_min_score=100
        )


class TestAntiForensicsTools(RuleTestCase):
    """Test rules for anti-forensics tools"""
    
    def test_sdelete_detection(self):
        """SDelete should be flagged as anti-forensics"""
        self.assertRuleMatches(
            "C:\\Tools\\SDelete\\sdelete64.exe",
            expected_min_score=200,
            expected_tags=["ANTI_FORENSICS"]
        )
    
    def test_bcwipe_detection(self):
        """BCWipe should be detected"""
        self.assertRuleMatches(
            "C:\\Program Files\\BCWipe\\bcwipe.exe",
            expected_min_score=200,
            expected_tags=["ANTI_FORENSICS"]
        )
    
    def test_setmace_timestomp(self):
        """SetMACE timestomp tool should be critical"""
        self.assertRuleMatches(
            "C:\\Tools\\setmace.exe",
            expected_min_score=300,
            expected_tags=["CRITICAL_TIMESTOMP"]
        )


class TestRemoteAccessTools(RuleTestCase):
    """Test rules for remote access tools"""
    
    def test_putty_detection(self):
        """PuTTY should be detected as remote access"""
        self.assertRuleMatches(
            "C:\\Users\\Admin\\Desktop\\putty.exe",
            expected_min_score=200,
            expected_tags=["REMOTE_ACCESS"]
        )
    
    def test_psexec_lateral(self):
        """PsExec should be flagged as lateral movement"""
        self.assertRuleMatches(
            "C:\\Windows\\Temp\\PsExec64.exe",
            expected_min_score=200,
            expected_tags=["LATERAL_MOVEMENT"]
        )

    def test_psexec_negative_context(self):
        """PsExec in Sysinternals output should be ignored (FP reduction)"""
        # Should NOT match because of negative_context: path_contains: "sysinternals"
        self.assertRuleNotMatches(
            "C:\\Tools\\SysinternalsSuite\\PsExec64.exe",
            max_score=50,
            msg="PsExec in Sysinternals folder should be ignored by negative_context"
        )


class TestLateralMovementTools(RuleTestCase):
    """Test rules for lateral movement indicators"""
    
    def test_unc_path_detection(self):
        """UNC paths should be detected"""
        self.assertRuleMatches(
            "\\\\server\\share\\payload.exe",
            expected_min_score=100,
            expected_tags=["UNC_EXECUTION"]
        )
    
    def test_robocopy_low_base_score(self):
        """Robocopy should have low base score (context-dependent)"""
        score, _ = self.engine.match("robocopy.exe", 0)
        # Should be detected but with lower score (dual-use tool)
        self.assertLessEqual(score, 100)


class TestWebshells(RuleTestCase):
    """Test rules for webshell detection"""
    
    def test_c99_webshell(self):
        """C99 webshell should be critical"""
        self.assertRuleMatches(
            "C:\\inetpub\\wwwroot\\c99.php",
            expected_min_score=500,
            expected_tags=["CRITICAL_WEBSHELL"]
        )
    
    def test_b374k_webshell(self):
        """B374K webshell should be critical"""
        self.assertRuleMatches(
            "/var/www/html/b374k.php",
            expected_min_score=500
        )


class TestFalsePositivePrevention(RuleTestCase):
    """Test that legitimate files don't trigger false positives"""
    
    def test_system_dll_no_match(self):
        """System DLLs should not trigger high scores"""
        self.assertRuleNotMatches(
            "C:\\Windows\\System32\\kernel32.dll",
            max_score=50
        )
    
    def test_normal_notepad(self):
        """Normal notepad should not trigger"""
        self.assertRuleNotMatches(
            "C:\\Windows\\System32\\notepad.exe",
            max_score=50
        )
    
    def test_sync_exact_match(self):
        """sync.exe should match but mobsync.exe should NOT"""
        # sync.exe should match (Sysinternals tool)
        score_sync, _ = self.engine.match("C:\\Tools\\sync.exe", 0)
        score_mobsync, _ = self.engine.match("C:\\Windows\\System32\\mobsync.exe", 0)
        
        # sync.exe should score higher than mobsync.exe
        self.assertGreater(score_sync, score_mobsync, 
            "sync.exe should score higher than mobsync.exe (exact match rule)")


class TestStagingTools(RuleTestCase):
    """Test rules for staging/exfiltration tools"""
    
    def test_7za_detection(self):
        """7za standalone archiver should be detected"""
        self.assertRuleMatches(
            "C:\\Users\\Admin\\Downloads\\7za.exe",
            expected_min_score=400,
            expected_tags=["STAGING_TOOL"]
        )
    
    def test_choco_staging(self):
        """Chocolatey in suspicious context should be detected"""
        self.assertRuleMatches(
            "C:\\Users\\Admin\\Desktop\\choco.exe",
            expected_min_score=200
        )


# ============================================================
# Summary Report
# ============================================================

class TestRuleCoverage(RuleTestCase):
    """Verify rule coverage statistics"""
    
    def test_minimum_rules_loaded(self):
        """Ensure minimum number of rules are loaded"""
        self.assertGreaterEqual(self.engine.rule_count, 40, 
            f"Expected at least 40 rules, got {self.engine.rule_count}")
    
    def test_critical_tools_covered(self):
        """Ensure all critical tools have rules"""
        critical_tools = [
            "mimikatz", "sdelete", "bcwipe", "setmace", 
            "psexec", "putty", "procdump"
        ]
        for tool in critical_tools:
            score, _ = self.engine.match(f"C:\\{tool}.exe", 0)
            self.assertGreater(score, 0, f"No rule for critical tool: {tool}")


if __name__ == "__main__":
    # Custom test runner with summary
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=Path(__file__).parent, pattern="test_*.py")
    
    print("=" * 60)
    print("SkiaHelios Rule Unit Testing Framework v1.0")
    print("=" * 60)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary
    print("\n" + "=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("=" * 60)
    
    sys.exit(0 if result.wasSuccessful() else 1)

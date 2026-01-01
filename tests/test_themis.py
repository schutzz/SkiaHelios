import unittest
import polars as pl
from pathlib import Path
import tempfile
import yaml
import shutil
import sys

# プロジェクトルートへのパスを通す
sys.path.append(str(Path(__file__).parent.parent))

from tools.SH_ThemisLoader import ThemisLoader

class TestThemisLoader(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for test rules
        self.test_dir = tempfile.mkdtemp()
        self.rule_path = Path(self.test_dir) / "test_rules.yaml"

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_T1_Yaml_Loading_And_Fallback(self):
        """T1: Ensure loader handles non-existent YAML gracefully."""
        loader = ThemisLoader(rule_path="non_existent_file.yaml")
        self.assertEqual(len(loader.noise_rules), 0)
        self.assertEqual(len(loader.threat_rules), 0)

    def test_T2_Condition_Logic_Regex(self):
        """T2: Verify regex condition logic."""
        rules_data = {
            "noise_filters": [
                {"name": "TestRegex", "target": "ColA", "condition": "regex", "pattern": "test\\d+"}
            ]
        }
        with open(self.rule_path, "w") as f:
            yaml.dump(rules_data, f)
        
        loader = ThemisLoader(rule_path=self.rule_path)
        df = pl.DataFrame({"ColA": ["test1234", "testabcd"]})
        
        expr = loader.get_noise_filter_expr(df.columns)
        # Apply filter: should match row 0 (True) and row 1 (False)
        result = df.select(expr.alias("match")).to_series()
        
        self.assertTrue(result[0])  # matches test1234
        self.assertFalse(result[1]) # does not match testabcd

    def test_T3_Noise_Filter_Logic(self):
        """T3: Verify noise filtering boolean expression."""
        rules_data = {
            "noise_filters": [
                {"name": "NoisePath", "target": "ParentPath", "condition": "contains", "pattern": "Windows\\Temp"}
            ]
        }
        with open(self.rule_path, "w") as f:
            yaml.dump(rules_data, f)
            
        loader = ThemisLoader(rule_path=self.rule_path)
        df = pl.DataFrame({
            "ParentPath": ["C:\\Windows\\Temp\\file.txt", "C:\\Users\\file.txt"]
        })
        
        expr = loader.get_noise_filter_expr(df.columns)
        result = df.select(expr).to_series()
        
        self.assertTrue(result[0])
        self.assertFalse(result[1])

    def test_T4_Threat_Scoring_Accumulation(self):
        """T4: Verify threat score accumulation and tag concatenation."""
        rules_data = {
            "threat_signatures": [
                {"name": "Rule1", "target": "FileName", "condition": "contains", "pattern": "evil", "score": 10, "tag": "TAG1"},
                {"name": "Rule2", "target": "FileName", "condition": "ends_with", "pattern": ".exe", "score": 20, "tag": "TAG2"}
            ]
        }
        with open(self.rule_path, "w") as f:
            yaml.dump(rules_data, f)
            
        loader = ThemisLoader(rule_path=self.rule_path)
        df = pl.DataFrame({"FileName": ["evil.exe"]})
        
        # Apply logic (Threat Scoring expects LazyFrame typically, but returns LazyFrame)
        scored_df = loader.apply_threat_scoring(df.lazy()).collect()
        
        self.assertEqual(scored_df["Threat_Score"][0], 30) # 10 + 20
        self.assertTrue("TAG1" in scored_df["Threat_Tag"][0])
        self.assertTrue("TAG2" in scored_df["Threat_Tag"][0])

    def test_T5_Safe_Casting(self):
        """T5: Verify safe casting of String-typed Threat_Score."""
        loader = ThemisLoader(rule_path=self.rule_path) # Empty rules roughly
        
        # Threat_Score is String "100"
        df = pl.DataFrame({
            "FileName": ["normal.txt"],
            "Threat_Score": ["100"] 
        })
        
        # Should not crash and cast to Int64
        scored_df = loader.apply_threat_scoring(df.lazy()).collect()
        
        self.assertEqual(scored_df["Threat_Score"].dtype, pl.Int64)
        self.assertEqual(scored_df["Threat_Score"][0], 100)

    def test_T6_Osekkay_Trigger(self):
        """T6: Verify Osekkay suggestion logic based on noise ratio."""
        loader = ThemisLoader(rule_path=self.rule_path)
        
        # High Noise Ratio: 1 Threat vs 99 Noise
        # Note: suggest_new_noise_rules expects a collected DataFrame
        df_noisy = pl.DataFrame({
            "ParentPath": ["C:\\Noise"] * 99 + ["C:\\Different"],
            "Threat_Score": [0] * 99 + [100]
        })
        
        suggestions = loader.suggest_new_noise_rules(df_noisy, threshold_ratio=50)
        self.assertTrue(len(suggestions) > 0)
        self.assertTrue("C:\\Noise" in suggestions[0])
        
        # Low Noise Ratio: All threats
        df_threats = pl.DataFrame({
            "ParentPath": ["C:\\Evil"] * 10,
            "Threat_Score": [100] * 10
        })
        suggestions_empty = loader.suggest_new_noise_rules(df_threats, threshold_ratio=50)
        self.assertEqual(len(suggestions_empty), 0)

if __name__ == '__main__':
    unittest.main()

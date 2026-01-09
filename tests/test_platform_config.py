import sys
import unittest
from pathlib import Path

# Add project root to path
sys.path.append(r"C:\Users\user\.gemini\antigravity\scratch\SkiaHelios")

try:
    from tools.SH_PlutosGate import PlutosGate
    from tools.SH_LachesisWriter import LachesisWriter
except ImportError as e:
    print(f"Import Error: {e}")
    sys.exit(1)

class TestPlatformConfig(unittest.TestCase):
    def test_plutos_config_loading(self):
        print("\n[Test] Initializing PlutosGate...")
        gate = PlutosGate(kape_dir=".")
        
        # Verify config loaded
        self.assertTrue(len(gate.high_heat_processes) > 0, "Plutos: high_heat_processes should not be empty")
        self.assertIn("curl.exe", gate.high_heat_processes, "Plutos: curl.exe should be in high_heat_processes")
        
        self.assertTrue(len(gate.exfil_domains) > 0, "Plutos: exfil_domains should not be empty")
        self.assertTrue(any("drive" in d for d in gate.exfil_domains), "Plutos: google drive pattern should be in exfil_domains")
        
        print("[OK] PlutosGate config loaded successfully.")

    def test_lachesis_config_loading(self):
        print("\n[Test] Initializing LachesisWriter...")
        lachesis = LachesisWriter()
        
        # Verify config loaded
        self.assertTrue(len(lachesis.garbage_paths) > 0, "Lachesis: garbage_paths should not be empty")
        self.assertTrue(any("chrome" in p for p in lachesis.garbage_paths), "Lachesis: chrome garbage path found")
        
        self.assertTrue(len(lachesis.infra_ips) > 0, "Lachesis: infra_ips should not be empty")
        self.assertIn("127.0.0.1", lachesis.infra_ips, "Lachesis: 127.0.0.1 should be in infra_ips")
        
        # Verify backward compatibility for signatures (now full dump)
        self.assertTrue(len(lachesis.intel_sigs) > 0, "Lachesis: intel_sigs should be loaded")
        self.assertIn("masquerade", lachesis.intel_sigs, "Lachesis: intel_sigs should contain full config keys")
        
        print("[OK] LachesisWriter config loaded successfully.")

if __name__ == '__main__':
    unittest.main()

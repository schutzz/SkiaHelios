import sys
import os
from pathlib import Path
import time
import importlib

# ============================================================
#  SH_HeliosConsole v3.2 [MFT-Aware Core]
#  Mission: Coordinate all modules within a single executable.
#  Updates: Passes Raw MFT to AION for Deep Scanning.
#  "The sun must shine on every hidden artifact."
# ============================================================

def print_logo():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(r"""
          , - ~ ~ ~ - ,
      , '   _ _ _ _   ' ,
    ,      |_______|      ,
   ,        _______        ,
  ,        |_______|        ,  < SKIA HELIOS >
  ,        _______          ,  v3.2 - MFT-Aware Core
   ,       |_______|       ,
    ,                     ,
      , _ _ _ _ _ _ _ _ ,
          ' - _ _ - '
    "Illuminating the darkest artifacts with precision."
    """)

class HeliosCommander:
    def __init__(self):
        self.modules = {}
        self._load_modules()

    def _import_dynamic(self, tool_name, script_name):
        try:
            module_path = f"tools.{tool_name}.{script_name}"
            mod = importlib.import_module(module_path)
            return mod.main
        except (ImportError, ModuleNotFoundError):
            pass
        try:
            module_path = f"tools.{script_name}"
            mod = importlib.import_module(module_path)
            return mod.main
        except (ImportError, ModuleNotFoundError) as e:
            print(f"[!] Warning: Could not load {tool_name} ({e})")
            return None

    def _load_modules(self):
        tool_map = {
            "chaos":   ("SH_ChaosGrasp", "SH_ChaosGrasp"),
            "pandora": ("SH_PandorasLink", "SH_PandorasLink"),
            "chronos": ("SH_ChronosSift", "SH_ChronosSift"),
            "aion":    ("SH_AIONDetector", "SH_AIONDetector"),
            "plutos":  ("SH_PlutosGate", "SH_PlutosGate"),
            "hekate":  ("SH_HekateWeaver", "SH_HekateWeaver"),
            "sphinx":  ("SH_SphinxDeciphering", "SH_SphinxDeciphering")
        }
        for key, (folder, script) in tool_map.items():
            func = self._import_dynamic(folder, script)
            self.modules[key] = func if func else None

    def run_module(self, key, args):
        func = self.modules.get(key)
        if not func:
            print(f"[!] Module '{key}' is not available.")
            return False
        
        print(f"\n>>> [EXECUTING] {key.upper()} Stage...")
        try:
            func(args)
            return True
        except Exception as e:
            print(f"[!] {key.upper()} Error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def full_auto_scan(self, kape_dir, out_dir, case_name):
        print_logo()
        print(f"[*] --- INITIATING FULL AUTO SCAN: {case_name} ---")
        time.sleep(1.5)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        case_dir = Path(out_dir) / f"{case_name}_{timestamp}"
        case_dir.mkdir(parents=True, exist_ok=True)
        
        # 0. Identify Raw MFT first
        mft_raw = next(Path(kape_dir).rglob("*$MFT_Output.csv"), None)

        # 1. Chaos (MFT Timeline Construction)
        chaos_out = case_dir / "Master_Timeline.csv"
        self.run_module("chaos", ["-d", kape_dir, "-o", str(chaos_out)])

        # 2. Chronos (Time Paradox Analysis)
        chronos_out = case_dir / "Time_Anomalies.csv"
        if mft_raw:
            self.run_module("chronos", ["-f", str(mft_raw), "-o", str(chronos_out), "--targets-only"])

        # 3. AION (Persistence with MFT Correlation)
        aion_out = case_dir / "Persistence_Report.csv"
        # [Fix] Pass Raw MFT if available, otherwise Timeline
        mft_target = str(mft_raw) if mft_raw else str(chaos_out)
        
        self.run_module("aion", [
            "--dir", kape_dir, 
            "--mft", mft_target, # Passing Raw MFT now!
            "-o", str(aion_out)
        ])

        # 4. Pandora & Plutos
        pandora_out = case_dir / "Ghost_Report.csv"
        self.run_module("pandora", [
            "-d", kape_dir, 
            "--start", "2000-01-01", "--end", "2030-12-31", 
            "--out", str(pandora_out)
        ])
        
        plutos_out = case_dir / "Exfil_Report.csv"
        plutos_net_out = case_dir / "Exfil_Report_Network.csv"
        
        self.run_module("plutos", [
            "--dir", kape_dir, 
            "--pandora", str(pandora_out), 
            "-o", str(plutos_out),
            "--net-out", str(plutos_net_out)
        ])

        # 5. Sphinx (Script Decoding)
        sphinx_out = case_dir / "Sphinx_Decoded.csv"
        evtx_raw = next(Path(kape_dir).rglob("*EvtxECmd_Output.csv"), None)
        if evtx_raw:
            self.run_module("sphinx", ["-f", str(evtx_raw), "-o", str(sphinx_out)])

        # 6. Hekate (Final Grimoire Weaving)
        for lang in ["en", "jp"]:
            report_path = case_dir / f"Grimoire_{case_name}_{lang}.md"
            self.run_module("hekate", [
                "-i", str(chaos_out), 
                "-o", str(report_path), 
                "--lang", lang,
                "--aion", str(aion_out), 
                "--plutos", str(plutos_out),
                "--plutos-net", str(plutos_net_out),
                "--sphinx", str(sphinx_out), 
                "--chronos", str(chronos_out),
                "--pandora", str(pandora_out)
            ])

        print(f"\n[*] ALL SYSTEMS GO. Grimoire woven at: {case_dir}")

def main():
    commander = HeliosCommander()
    if len(sys.argv) > 1: pass
    try:
        kape = input("Target Artifact Path: ").strip()
        case = input("Case Name: ").strip() or "Standard_Investigation"
        kape = kape.strip('"').strip("'")
        if os.path.exists(kape) and os.path.isdir(kape):
            commander.full_auto_scan(kape, "Helios_Output", case)
        else:
            print("[!] Target path invalid.")
            input("Press Enter to exit...")
    except KeyboardInterrupt:
        print("\n[!] Aborted.")

if __name__ == "__main__":
    main()
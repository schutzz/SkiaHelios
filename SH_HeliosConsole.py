import sys
import os
from pathlib import Path
import time

# --- Monolith Imports ---
try:
    from tools.SH_ChaosGrasp.SH_ChaosGrasp import main as chaos_main
    from tools.SH_PandorasLink.SH_PandorasLink import main as pandora_main
    from tools.SH_ChronosSift.SH_ChronosSift import main as chronos_main
    from tools.SH_AIONDetector.SH_AIONDetector import main as aion_main
    from tools.SH_PlutosGate.SH_PlutosGate import main as plutos_main
    from tools.SH_HekateWeaver.SH_HekateWeaver import main as hekate_main
    from tools.SH_SphinxDeciphering.SH_SphinxDeciphering import main as sphinx_main
except ImportError as e:
    print(f"[!] Import Error (Monolith): {e}")
    sys.exit(1)

# ============================================================
#  SH_HeliosConsole v2.7 [Monolith Core]
#  Mission: Coordinate all modules within a single executable.
#  Updates: Replaced subprocess with direct function calls.
#  "The sun must shine on every hidden artifact."
# ============================================================

MODULE_MAP = {
    "chaos":   chaos_main,
    "pandora": pandora_main,
    "chronos": chronos_main,
    "aion":    aion_main,
    "plutos":  plutos_main,
    "hekate":  hekate_main,
    "sphinx":  sphinx_main
}

def print_logo():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(r"""
          , - ~ ~ ~ - ,
      , '   _ _ _ _   ' ,
    ,      |_______|      ,
   ,        _______        ,
  ,        |_______|        ,  < SKIA HELIOS >
  ,        _______          ,  v2.7 - Monolith Core
   ,       |_______|       ,
    ,                     ,
      , _ _ _ _ _ _ _ _ ,
          ' - _ _ - '
    "Illuminating the darkest artifacts with precision."
    """)

class HeliosCommander:
    def __init__(self):
        pass

    def run_module(self, key, args):
        func = MODULE_MAP.get(key)
        if not func:
            print(f"[!] Module {key} not found.")
            return False
        
        print(f"\n>>> [EXECUTING] {key.upper()} Stage...")
        try:
            # Direct call with argument list
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
        
        # 1. Chaos (MFT Timeline Construction)
        chaos_out = case_dir / "Master_Timeline.csv"
        self.run_module("chaos", ["-d", kape_dir, "-o", str(chaos_out)])

        # 2. Chronos (Time Paradox Analysis)
        chronos_out = case_dir / "Time_Anomalies.csv"
        mft_raw = next(Path(kape_dir).rglob("*$MFT_Output.csv"), None)
        if mft_raw:
            self.run_module("chronos", ["-f", str(mft_raw), "-o", str(chronos_out), "--targets-only"])

        # 3. AION (Persistence with MFT Correlation)
        aion_out = case_dir / "Persistence_Report.csv"
        self.run_module("aion", [
            "--dir", kape_dir, 
            "--mft", str(chaos_out), 
            "-o", str(aion_out)
        ])

        # 4. Pandora & Plutos (Fix: Added missing --start/--end)
        pandora_out = case_dir / "Ghost_Report.csv"
        # [FIX] Default range if not provided?
        # Since this is full auto, we pick a wide range or need config.
        # "2000-01-01" to "2030-12-31" is safe.
        self.run_module("pandora", [
            "-d", kape_dir, 
            "--start", "2000-01-01", "--end", "2030-12-31", 
            "--out", str(pandora_out)
        ])
        
        plutos_out = case_dir / "Exfil_Report.csv"
        self.run_module("plutos", ["--dir", kape_dir, "--pandora", str(pandora_out), "-o", str(plutos_out)])

        # 5. Sphinx (Script Decoding)
        sphinx_out = case_dir / "Sphinx_Decoded.csv"
        evtx_raw = next(Path(kape_dir).rglob("*EvtxECmd_Output.csv"), None)
        if evtx_raw:
            self.run_module("sphinx", ["-f", str(evtx_raw), "-o", str(sphinx_out)])

        # 6. Hekate (Final Grimoire Weaving)
        for lang in ["en", "jp"]:
            report_path = case_dir / f"Grimoire_{case_name}_{lang}.md"
            self.run_module("hekate", [
                "-i", str(chaos_out), "-o", str(report_path), "--lang", lang,
                "--aion", str(aion_out), "--plutos", str(plutos_out),
                "--sphinx", str(sphinx_out), "--chronos", str(chronos_out),
                "--pandora", str(pandora_out)
            ])

        print(f"\n[*] ALL SYSTEMS GO. Grimoire woven at: {case_dir}")

def main():
    commander = HeliosCommander()
    kape = input("Target Artifact Path: ").strip()
    case = input("Case Name: ").strip() or "Standard_Investigation"
    
    # [FIX] Remove quotes if user dragged & dropped path
    kape = kape.strip('"').strip("'")
    
    if os.path.exists(kape) and os.path.isdir(kape):
        commander.full_auto_scan(kape, "Helios_Output", case)
    else:
        print("[!] Target path invalid.")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
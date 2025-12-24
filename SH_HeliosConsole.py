import sys
import os
import subprocess
from pathlib import Path
import time

# ============================================================
#  SH_HeliosConsole v2.6.7 [Pandora Fix]
#  Mission: Coordinate all modules and fix Pandora argument error.
#  Updates: Added --start/--end to Pandora stage.
#  "The sun must shine on every hidden artifact."
# ============================================================

MODULE_MAP = {
    "chaos":   Path("tools/SH_ChaosGrasp/SH_ChaosGrasp.py"),
    "pandora": Path("tools/SH_PandorasLink/SH_PandorasLink.py"),
    "chronos": Path("tools/SH_ChronosSift/SH_ChronosSift.py"),
    "aion":    Path("tools/SH_AIONDetector/SH_AIONDetector.py"),
    "plutos":  Path("tools/SH_PlutosGate/SH_PlutosGate.py"),
    "hekate":  Path("tools/SH_HekateWeaver/SH_HekateWeaver.py"),
    "sphinx":  Path("tools/SH_SphinxDeciphering/SH_SphinxDeciphering.py")
}

def print_logo():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(r"""
          , - ~ ~ ~ - ,
      , '   _ _ _ _   ' ,
    ,      |_______|      ,
   ,        _______        ,
  ,        |_______|        ,  < SKIA HELIOS >
  ,        _______          ,  v2.6.7 - Final Sync
   ,       |_______|       ,
    ,                     ,
      , _ _ _ _ _ _ _ _ ,
          ' - _ _ - '
    "Illuminating the darkest artifacts with precision."
    """)

class HeliosCommander:
    def __init__(self):
        self.root_dir = Path(__file__).parent.resolve()
        self.modules = {k: self.root_dir / v for k, v in MODULE_MAP.items() if (self.root_dir / v).exists()}

    def run_module(self, key, args):
        if key not in self.modules:
            print(f"[!] Module {key} not found at {MODULE_MAP.get(key)}")
            return False
        
        cmd = [sys.executable, str(self.modules[key])] + args
        print(f"\n>>> [EXECUTING] {key.upper()} Stage...")
        try:
            subprocess.run(cmd, check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] {key.upper()} Error: {e}")
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
        self.run_module("pandora", [
            "-d", kape_dir, 
            "--start", "2000-01-01", "--end", "2030-12-31", # [FIX] 必須引数を追加！
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
    if os.path.isdir(kape):
        commander.full_auto_scan(kape, "Helios_Output", case)
    else:
        print("[!] Target path invalid.")

if __name__ == "__main__":
    main()
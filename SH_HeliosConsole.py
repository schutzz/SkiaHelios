import sys
import os
import subprocess
import argparse
from pathlib import Path
import time
import datetime
import glob

# ==========================================
#  SH_HeliosConsole v2.5 [Victory Edition]
#  Mission: Orchestrate the SkiaHelios Suite
#  Fixes: Corrected input mapping for Chronos & Sphinx
# ==========================================

# [Configuration] 
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
    print(r"""
         , - ~ ~ ~ - ,
     , '   _ _ _ _   ' ,
   ,      |_______|      ,
  ,        _______        ,
 ,        |_______|        ,  < SkiaHelios >
 ,        _______          ,  v2.5 Console
  ,       |_______|       ,
   ,                     ,
     , _ _ _ _ _ _ _ _ ,
         ' - _ _ - '
    "Illuminating the darkest artifacts."
    """)

class HeliosCommander:
    def __init__(self):
        self.root_dir = Path(__file__).parent.resolve()
        self.modules = {}
        self._verify_integrity()

    def _verify_integrity(self):
        print("[*] Verifying SkiaHelios Integrity...")
        missing = []
        for key, rel_path in MODULE_MAP.items():
            full_path = self.root_dir / rel_path
            if full_path.exists():
                self.modules[key] = full_path
            else:
                print(f"  [!!] MISSING: {rel_path}")
                missing.append(key)
        
        if missing:
            print(f"[!] Warning: {len(missing)} modules are missing or misplaced.")
        else:
            print(f"  [OK] All {len(self.modules)} modules are ready at battle stations.")

    def run_module(self, key, args):
        if key not in self.modules:
            print(f"[!] Error: Module '{key}' is not available.")
            return False
        
        script_path = self.modules[key]
        cmd = [sys.executable, str(script_path)] + args
        
        print(f"\n>>> Invoking {key.upper()}...")
        try:
            start_t = time.time()
            subprocess.run(cmd, check=True)
            elapsed = time.time() - start_t
            print(f">>> {key.upper()} Operation Complete ({elapsed:.2f}s).\n")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] {key.upper()} Critical Failure (Exit Code: {e.returncode})\n")
            return False
        except KeyboardInterrupt:
            print(f"\n[!] Operation Aborted by User.\n")
            return False

    def _find_file(self, root_dir, pattern_list):
        for pattern in pattern_list:
            candidates = list(Path(root_dir).rglob(pattern))
            if candidates:
                return str(candidates[0])
        return None

    def full_auto_scan(self, kape_dir, out_dir, case_name):
        """
        [Coin Slayer Mode]
        Pipeline: Chaos -> Chronos -> AION -> Pandora -> Plutos -> Sphinx -> Hekate
        """
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        case_dir = Path(out_dir) / f"{case_name}_{timestamp}"
        case_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n[*] === INITIATING FULL AUTO SCAN: {case_name} ===")
        print(f"[*] Artifact Source: {kape_dir}")
        print(f"[*] Evidence Output: {case_dir}")

        # --- Phase 1: ChaosGrasp (The Timeline) ---
        print("\n[Phase 1] Timeline Construction")
        chaos_out = case_dir / "Master_Timeline.csv"
        if not self.run_module("chaos", ["-d", kape_dir, "-o", str(chaos_out)]):
            print("[!] Aborting Pipeline: Timeline generation failed.")
            return

        # --- Phase 1.5: ChronosSift (Time Verification) ---
        print("\n[Phase 1.5] Time Verification")
        chronos_out = case_dir / "Time_Verification.csv"
        # [Fix] Chronos needs RAW MFT, not the timeline!
        mft_raw = self._find_file(kape_dir, ["*$MFT_Output.csv", "*MFT*.csv"])
        if mft_raw:
            print(f"    -> Feeding Chronos with Raw MFT: {Path(mft_raw).name}")
            self.run_module("chronos", ["-f", mft_raw, "-o", str(chronos_out)])
        else:
            print("    [!] Warning: Raw MFT not found. Chronos cannot verify timestamps.")

        # --- Phase 2: AION Detector (The Persistence) ---
        print("\n[Phase 2] Persistence Hunting")
        aion_out = case_dir / "Persistence_Report.csv"
        self.run_module("aion", ["--dir", kape_dir, "-o", str(aion_out)])

        # --- Phase 3: Pandora's Link (The Ghost) ---
        print("\n[Phase 3] Ghost Detection & Anomaly Scan")
        pandora_out = case_dir / "Ghost_Report.csv"
        pandora_args = [
            "-d", kape_dir,
            "--start", "2020-01-01",
            "--end", "2030-01-01",
            "--chaos", str(chaos_out),
            "--out", str(pandora_out)
        ]
        self.run_module("pandora", pandora_args)

        # --- Phase 4: Plutos Gate (The Exit) ---
        print("\n[Phase 4] Exfiltration Tracking")
        plutos_out = case_dir / "Plutos_Exfil_Report.csv"
        plutos_args = [
            "--dir", kape_dir,
            "--pandora", str(pandora_out),
            "--out", str(plutos_out)
        ]
        self.run_module("plutos", plutos_args)

        # --- Phase 4.5: Sphinx Deciphering (The Riddle) ---
        print("\n[Phase 4.5] Obfuscation Decoding")
        sphinx_out = case_dir / "Sphinx_Decoded.csv"
        
        # [Fix] Broadened search for Event Logs (PowerShell often in generic Evtx dump)
        target_log = self._find_file(kape_dir, [
            "*PowerShell*Output.csv", 
            "*EvtxECmd*.csv", 
            "*EventLogs*.csv"
        ])
        
        if target_log:
            print(f"    -> Auto-Targeting for Sphinx: {Path(target_log).name}")
            self.run_module("sphinx", ["-f", target_log, "-o", str(sphinx_out)])
        else:
            print("    [-] No target logs (PowerShell/Evtx) found for Sphinx.")

        # --- Phase 5: Hekate Weaver (The Narrative) ---
        print("\n[Phase 5] Weaving the Grimoire")
        final_report = case_dir / "Final_Grimoire.md"
        
        hekate_args = [
            "-i", str(chaos_out), 
            "-o", str(final_report)
        ]
        
        if aion_out.exists(): hekate_args.extend(["--aion", str(aion_out)])
        if pandora_out.exists(): hekate_args.extend(["--pandora", str(pandora_out)])
        if plutos_out.exists(): hekate_args.extend(["--plutos", str(plutos_out)])
        if sphinx_out.exists(): hekate_args.extend(["--sphinx", str(sphinx_out)])
        if chronos_out.exists(): hekate_args.extend(["--chronos", str(chronos_out)])
        
        self.run_module("hekate", hekate_args)

        print(f"\n[*] === MISSION COMPLETE ===")
        print(f"    Report: {final_report}")

def main_menu():
    commander = HeliosCommander()
    default_out = "Helios_Output"

    while True:
        print_logo()
        print("  [1] ChaosGrasp (Timeline)    [4] Pandora (Ghosts)")
        print("  [2] AION (Persistence)       [5] Hekate (Report)")
        print("  [3] Chronos (Verification)   [6] Plutos (Exfil)")
        print("-" * 50)
        print("  [9] FULL AUTO SCAN (Coin Slayer Mode)")
        print("  [0] Exit")
        
        choice = input("\nSelect Module > ").strip()
        
        if choice == "0": break
        elif choice == "1":
            d = input("KAPE Directory: ").strip()
            commander.run_module("chaos", ["-d", d, "-o", "manual_timeline.csv"])
        elif choice == "2":
            d = input("KAPE/Autoruns Directory: ").strip()
            commander.run_module("aion", ["--dir", d, "-o", "manual_persistence.csv"])
        elif choice == "3":
            f = input("MFT CSV: ").strip()
            commander.run_module("chronos", ["-f", f, "-o", "manual_time_verify.csv"])
        elif choice == "4":
            d = input("KAPE Directory (MFT/USN): ").strip()
            commander.run_module("pandora", ["-d", d, "--start", "2020-01-01", "--end", "2030-01-01", "--out", "manual_ghosts.csv"])
        elif choice == "5":
            f = input("Timeline CSV: ").strip()
            commander.run_module("hekate", ["-i", f, "-o", "manual_report.md"])
        elif choice == "6":
            d = input("KAPE Directory: ").strip()
            commander.run_module("plutos", ["--dir", d, "-o", "manual_exfil.csv"])
        elif choice == "9":
            d = input("KAPE Source Directory: ").strip()
            if os.path.isdir(d):
                case = input("Case Name: ").strip() or "AutoCase"
                out_path = input(f"Output Directory [Default: {default_out}]: ").strip() or default_out
                commander.full_auto_scan(d, out_path, case)
                input("\nPress Enter to continue...")
            else:
                print("[!] Invalid directory.")
        else:
            print("[!] Invalid selection.")

if __name__ == "__main__":
    main_menu()
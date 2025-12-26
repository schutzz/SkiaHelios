import sys
import os
from pathlib import Path
import time
import importlib

# ============================================================
#  SH_HeliosConsole v3.7 [Dual Path Fix]
#  Mission: Coordinate Raw Artifacts & Parsed CSVs.
#  Updated: Explicitly handles 'Raw' (for History) and 'CSV' (for Timeline) paths.
#  "Two eyes see depth better than one."
# ============================================================

def print_logo():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(r"""
          , - ~ ~ ~ - ,
      , '   _ _ _ _   ' ,
    ,      |_______|      ,
   ,        _______        ,  < SKIA HELIOS >
  ,        |_______|        ,  v3.7 - Dual Path System
  ,        _______          ,
   ,       |_______|       ,
    ,                     ,
      , _ _ _ _ _ _ _ _ ,
          ' - _ _ - '
    "Illuminating Identity, Authority, and Intent."
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
            return None

    def _load_modules(self):
        tool_map = {
            "clio":     ("SH_ClioGet", "SH_ClioGet"),
            "chaos":    ("SH_ChaosGrasp", "SH_ChaosGrasp"),
            "hercules": ("SH_HerculesReferee", "SH_HerculesReferee"),
            "pandora":  ("SH_PandorasLink", "SH_PandorasLink"),
            "chronos":  ("SH_ChronosSift", "SH_ChronosSift"),
            "aion":     ("SH_AIONDetector", "SH_AIONDetector"),
            "plutos":   ("SH_PlutosGate", "SH_PlutosGate"),
            "hekate":   ("SH_HekateWeaver", "SH_HekateWeaver"),
            "sphinx":   ("SH_SphinxDeciphering", "SH_SphinxDeciphering")
        }
        for key, (folder, script) in tool_map.items():
            func = self._import_dynamic(folder, script)
            self.modules[key] = func if func else None

    def run_module(self, key, args):
        func = self.modules.get(key)
        if not func:
            if key in ["hercules", "clio"]:
                 print(f"[!] Module '{key}' is missing. Skipping...")
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

    def full_auto_scan(self, csv_dir, raw_dir, out_dir, case_name, start_date=None, end_date=None):
        print_logo()
        print(f"[*] --- INITIATING FULL AUTO SCAN: {case_name} ---")
        print(f"[*] Raw Artifacts (Source): {raw_dir}")
        print(f"[*] Parsed CSVs (Source)  : {csv_dir}")
        
        if start_date or end_date:
            print(f"[*] Time Clipping Active: {start_date or '...'} to {end_date or '...'}")
        time.sleep(1.5)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        case_dir = Path(out_dir) / f"{case_name}_{timestamp}"
        case_dir.mkdir(parents=True, exist_ok=True)
        
        time_args = []
        if start_date: time_args.extend(["--start", start_date])
        if end_date:   time_args.extend(["--end", end_date])

        # 0. ClioGet (Browser History Hunting)
        # RawフォルダからHistoryを探し、CSVフォルダ内のサブフォルダに出力する
        # これにより、後続のChaosGraspが再帰探索で拾えるようになる
        browser_out = Path(csv_dir) / "Browser_Artifacts"
        browser_out.mkdir(exist_ok=True)
        print(f"[*] Invoking ClioGet: Raw -> {browser_out}")
        self.run_module("clio", ["-d", raw_dir, "-o", str(browser_out)])

        # 1. Chaos (Master Timeline Construction)
        # CSVフォルダ (Browser_Artifacts含む) をスキャン
        chaos_out = case_dir / "Master_Timeline.csv"
        self.run_module("chaos", ["-d", csv_dir, "-o", str(chaos_out)])

        # 2. Hercules (Authority & Identity Judgment)
        judged_out = case_dir / "Hercules_Judged_Timeline.csv"
        # HerculesもCatalog作成のためにCSVフォルダをスキャンする
        hercules_success = self.run_module("hercules", ["-i", str(chaos_out), "-d", csv_dir, "-o", str(judged_out)])

        # 3. Pipeline Switch
        timeline_target = str(judged_out) if hercules_success and judged_out.exists() else str(chaos_out)
        print(f"[*] Pipeline Target Set: {Path(timeline_target).name}")

        # 4. Chronos (Time Paradox Analysis)
        mft_raw = next(Path(csv_dir).rglob("*$MFT_Output.csv"), None)
        chronos_out = case_dir / "Time_Anomalies.csv"
        if mft_raw:
            self.run_module("chronos", ["-f", str(mft_raw), "-o", str(chronos_out), "--targets-only"] + time_args)

        # 5. AION (Persistence)
        aion_out = case_dir / "Persistence_Report.csv"
        mft_for_aion = str(mft_raw) if mft_raw else timeline_target
        self.run_module("aion", ["--dir", csv_dir, "--mft", mft_for_aion, "-o", str(aion_out)] + time_args)

        # 6. Pandora & Plutos (Exfiltration)
        pandora_out = case_dir / "Ghost_Report.csv"
        p_start = start_date if start_date else "2000-01-01"
        p_end = end_date if end_date else "2099-12-31"
        self.run_module("pandora", ["-d", csv_dir, "--start", p_start, "--end", p_end, "--out", str(pandora_out)])
        
        plutos_out = case_dir / "Exfil_Report.csv"
        plutos_net_out = case_dir / "Exfil_Report_Network.csv"
        self.run_module("plutos", ["--dir", csv_dir, "--pandora", str(pandora_out), "-o", str(plutos_out), "--net-out", str(plutos_net_out)] + time_args)

        # 7. Sphinx (Script Decoding)
        sphinx_out = case_dir / "Sphinx_Decoded.csv"
        evtx_raw = next(Path(csv_dir).rglob("*EvtxECmd_Output.csv"), None)
        if evtx_raw:
            self.run_module("sphinx", ["-f", str(evtx_raw), "-o", str(sphinx_out)] + time_args)

        # 8. Hekate (Final Grimoire Weaving)
        for lang in ["en", "jp"]:
            report_path = case_dir / f"Grimoire_{case_name}_{lang}.md"
            self.run_module("hekate", [
                "-i", timeline_target, 
                "-o", str(report_path), 
                "--lang", lang,
                "--aion", str(aion_out), 
                "--plutos", str(plutos_out),
                "--plutos-net", str(plutos_net_out),
                "--sphinx", str(sphinx_out), 
                "--chronos", str(chronos_out),
                "--pandora", str(pandora_out)
            ] + time_args)

        print(f"\n[*] ALL SYSTEMS GO. Grimoire woven at: {case_dir}")

def main():
    commander = HeliosCommander()
    try:
        # [Fix] 2つのパスを聞くように変更
        print("Please provide the paths for analysis:")
        csv_dir = input("1. Parsed CSV Directory (KAPE 'Module' Output): ").strip().strip('"').strip("'")
        raw_dir = input("2. Raw Artifact Directory (KAPE 'Target' Output): ").strip().strip('"').strip("'")
        
        case = input("Case Name: ").strip() or "Standard_Investigation"
        
        print("\n[Optional] Specify Time Range for Incident (YYYY-MM-DD HH:MM:SS)")
        start_date = input("Start Date [Enter to skip]: ").strip()
        end_date   = input("End Date   [Enter to skip]: ").strip()
        
        if os.path.exists(csv_dir) and os.path.isdir(csv_dir) and os.path.exists(raw_dir) and os.path.isdir(raw_dir):
            commander.full_auto_scan(csv_dir, raw_dir, "Helios_Output", case, start_date, end_date)
        else:
            print("[!] One or both paths are invalid.")
            input("Press Enter to exit...")
    except KeyboardInterrupt:
        print("\n[!] Aborted.")

if __name__ == "__main__":
    main()
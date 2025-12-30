import sys
import os
import argparse
from pathlib import Path
import time
import importlib

# ============================================================
#  SH_HeliosConsole v4.0 [Timekeeper Edition]
#  Mission: Coordinate all modules & enable Sniper Intel flow.
#  Updates:
#    - Implemented argparse for CLI support (start/end fixed).
#    - Selective time-filter distribution (prevent AION/Hekate crash).
# ============================================================

def print_logo():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(r"""
          , - ~ ~ ~ - ,
      , '   _ _ _ _   ' ,
     ,     |_______|      ,
    ,       _______        ,  < SKIA HELIOS >
   ,       |_______|        ,  v4.0 - Timekeeper
   ,       _______          ,
    ,      |_______|       ,
     ,                    ,
      , _ _ _ _ _ _ _ _ ,
          ' - _ _ - '
    "Illuminating Identity, Authority, and Intent."
    """)

class HeliosCommander:
    def __init__(self):
        self.modules = {}
        self._load_modules()

    def _import_dynamic(self, script_name):
        search_paths = [script_name, f"tools.{script_name}"]
        for path in search_paths:
            try:
                mod = importlib.import_module(path)
                if hasattr(mod, 'main'):
                    return mod.main
            except (ImportError, ModuleNotFoundError):
                continue
        return None

    def _load_modules(self):
        tool_map = {
            "clio": "SH_ClioGet",
            "chaos": "SH_ChaosGrasp",
            "hercules": "SH_HerculesReferee",
            "pandora": "SH_PandorasLink",
            "chronos": "SH_ChronosSift",
            "aion": "SH_AIONDetector",
            "plutos": "SH_PlutosGate",
            "hekate": "SH_HekateWeaver",
            "plutos": "SH_PlutosGate",
            "hekate": "SH_HekateWeaver",
            "sphinx": "SH_SphinxDeciphering",
            "siren": "SH_Sirenhunt" # [NEW]
        }
        for key, script in tool_map.items():
            self.modules[key] = self._import_dynamic(script)

    def run_module(self, key, args):
        func = self.modules.get(key)
        if not func:
            print(f"[!] Module '{key}' not found. Skipping Stage...")
            return False
        
        print(f"\n>>> [EXECUTING] {key.upper()} Stage...")
        try:
            func(args)
            return True
        except Exception as e:
            print(f"[!] {key.upper()} Stage Failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def full_auto_scan(self, csv_dir, raw_dir, out_dir, case_name, start_date=None, end_date=None, mount_point=None):
        print_logo()
        print(f"[*] --- INITIATING CERBERUS PIPELINE: {case_name} ---")
        if start_date: print(f"[*] Time Filter: {start_date} -> {end_date}")
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        case_dir = Path(out_dir) / f"{case_name}_{timestamp}"
        case_dir.mkdir(parents=True, exist_ok=True)
        
        # Time args for modules that support them
        time_args = []
        if start_date: time_args.extend(["--start", start_date])
        if end_date:   time_args.extend(["--end", end_date])

        # 1. ClioGet (Browser History)
        browser_out = Path(csv_dir) / "Browser_Artifacts"
        browser_out.mkdir(exist_ok=True)
        self.run_module("clio", ["-d", raw_dir, "-o", str(browser_out)])

        # 2. ChaosGrasp (Timeline Construction)
        chaos_out = case_dir / "Master_Timeline.csv"
        self.run_module("chaos", ["-d", csv_dir, "-o", str(chaos_out)])

        # 3. Pandora (Target Intel) - Supports Time
        pandora_out = case_dir / "Ghost_Report.csv"
        p_start = start_date if start_date else "2000-01-01"
        p_end = end_date if end_date else "2099-12-31"
        self.run_module("pandora", ["-d", csv_dir, "--start", p_start, "--end", p_end, "--out", str(pandora_out)])

        # 4. Hercules (Sniper Execution)
        judged_out = case_dir / "Hercules_Judged_Timeline.csv"
        hercules_success = self.run_module("hercules", [
            "--timeline", str(chaos_out), 
            "--kape", csv_dir, 
            "--out", str(judged_out), 
            "--ghosts", str(pandora_out)
        ])
        timeline_target = str(judged_out) if (hercules_success and judged_out.exists()) else str(chaos_out)

        # 5. Deep Forensics
        mft_raw = next(Path(csv_dir).rglob("*$MFT_Output.csv"), None)
        chronos_out = case_dir / "Time_Anomalies.csv"
        if mft_raw:
            # Chronos supports Time
            self.run_module("chronos", ["-f", str(mft_raw), "-o", str(chronos_out), "--targets-only"] + time_args)
        
        aion_out = case_dir / "Persistence_Report.csv"
        aion_args = ["--dir", csv_dir, "--mft", str(mft_raw if mft_raw else timeline_target), "-o", str(aion_out)]
        if mount_point: aion_args.extend(["--mount", mount_point])
        # AION DOES NOT support time_args (Persistence is timeless)
        self.run_module("aion", aion_args)

        plutos_out = case_dir / "Exfil_Report.csv"
        plutos_net_out = case_dir / "Exfil_Report_Network.csv"
        # Plutos supports Time
        self.run_module("plutos", ["--dir", csv_dir, "--pandora", str(pandora_out), "-o", str(plutos_out), "--net-out", str(plutos_net_out)] + time_args)

        sphinx_out = case_dir / "Sphinx_Decoded.csv"
        evtx_raw = next(Path(csv_dir).rglob("*EvtxECmd_Output.csv"), None)
        if evtx_raw:
            # Sphinx supports Time
            # Sphinx supports Time
            self.run_module("sphinx", ["-f", str(evtx_raw), "-o", str(sphinx_out)] + time_args)

        # 5.5. Sirenhunt (The Validator) - [NEW STAGE]
        # Find Prefetch/Amcache for Siren
        prefetch_raw = next(Path(csv_dir).rglob("*PECmd_Output.csv"), None)
        amcache_raw = next(Path(csv_dir).rglob("*Amcache_UnassociatedFileEntries.csv"), None) # Typical AmcacheParser output
        
        siren_json = case_dir / "Sirenhunt_Results.json"
        siren_cmd = [
            "--chronos", str(chronos_out),
            "--pandora", str(pandora_out),
            "-o", str(siren_json)
        ]
        if prefetch_raw: siren_cmd.extend(["--prefetch", str(prefetch_raw)])
        if amcache_raw: siren_cmd.extend(["--amcache", str(amcache_raw)])
        
        # We need to add 'siren' to _load_modules tool_map first, or just run it via run_module if we add it there.
        # But wait, SH_HeliosConsole.py's _load_modules is hardcoded. I should verify if I need to add 'siren' there too.
        # Yes, I do. Let's do that in a separate chunk.
        self.run_module("siren", siren_cmd)

        # 6. Hekate (The Final Weaver)
        # Hekate usually consumes all events. Filtering is done at ingestion or report time if needed.
        # DO NOT pass time_args to Hekate CLI unless v15.33 main() supports it (it currently doesn't).
        for lang in ["jp", "en"]:
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
                "--sphinx", str(sphinx_out), 
                "--chronos", str(chronos_out),
                "--pandora", str(pandora_out),
                "--siren", str(siren_json) # [NEW] Pass Siren JSON
            ])

        print(f"\n[*] SUCCESS: Pipeline finished. Case dir: {case_dir}")

def main():
    parser = argparse.ArgumentParser(description="SH_HeliosConsole v4.0")
    parser.add_argument("--dir", required=True, help="Parsed CSV Directory (KAPE Modules)")
    parser.add_argument("--raw", help="Raw Artifact Directory (Optional)")
    parser.add_argument("--mft", help="MFT Path (Optional, auto-detected if in dir)")
    parser.add_argument("--mount", help="Mount Point (e.g. E:\\) for AION hashing")
    parser.add_argument("--start", help="Start Date (YYYY-MM-DD)")
    parser.add_argument("--end", help="End Date (YYYY-MM-DD)")
    parser.add_argument("--case", default="Investigation", help="Case Name")
    parser.add_argument("-o", "--out", default="Helios_Output", help="Output Directory")
    
    # Check if arguments are passed, otherwise fallback to interactive
    if len(sys.argv) > 1:
        args = parser.parse_args()
        commander = HeliosCommander()
        raw_target = args.raw if args.raw else args.dir # Fallback
        commander.full_auto_scan(args.dir, raw_target, args.out, args.case, args.start, args.end, args.mount)
    else:
        # Interactive Mode
        print_logo()
        commander = HeliosCommander()
        try:
            csv_dir = input("1. Parsed CSV Directory (KAPE Modules): ").strip().strip('"').strip("'")
            raw_dir = input("2. Raw Artifact Directory (KAPE Targets) [Enter for same]: ").strip().strip('"').strip("'")
            if not raw_dir: raw_dir = csv_dir
            mount_point = input("3. Mount Point (Optional) [e.g. E:\]: ").strip().strip('"').strip("'")
            case = input("Case Name [Default: Investigation]: ").strip() or "Investigation"
            print("\n[Optional] Time Range (YYYY-MM-DD)")
            start_date = input("Start Date: ").strip()
            end_date = input("End Date: ").strip()
            
            if os.path.exists(csv_dir):
                commander.full_auto_scan(csv_dir, raw_dir, "Helios_Output", case, start_date, end_date, mount_point)
            else:
                print("[!] Error: CSV Directory not found.")
        except KeyboardInterrupt:
            print("\n[!] Aborted.")

if __name__ == "__main__":
    main()
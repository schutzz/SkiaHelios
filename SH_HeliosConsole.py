import sys
import os
import argparse
from pathlib import Path
import time
import importlib
import json
from datetime import datetime

# ============================================================
#  SH_HeliosConsole v4.5 [Legacy & Interactive Merged]
#  Mission: Coordinate all modules & Measure Performance.
#  Updates:
#    - Merged v4.1 Benchmarking logic.
#    - Added v4.4 Interactive Legacy Mode prompt.
#    - Added '--legacy' flag support for Chronos v17.1.
# ============================================================

def print_logo():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(r"""
          , - ~ ~ ~ - ,
      , '   _ _ _ _   ' ,
     ,     |_______|      ,
    ,       _______        ,  < SKIA HELIOS >
   ,       |_______|        ,  v4.5 - Legacy Ready
   ,       _______          ,
    ,      |_______|       ,
     ,                    ,
      , _ _ _ _ _ _ _ _ ,
          ' - _ _ - '
    "Illuminating Identity, Authority, Intent, and Velocity."
    """)

class BenchmarkTimer:
    """
    [Cronus: The Time Keeper]
    実行時間を計測し、統計データに記録するコンテキストマネージャ。
    """
    def __init__(self, name, stats_dict):
        self.name = name
        self.stats = stats_dict
        self.start_time = None

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.perf_counter() - self.start_time
        self.stats[self.name] = round(elapsed, 4)

class HeliosCommander:
    def __init__(self):
        self.modules = {}
        # 統計情報用コンテナ
        self.stats = {
            "Total_Execution_Time": 0,
            "Timestamp": datetime.now().isoformat(),
            "Modules": {}
        }
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
        # 重複を削除して整理
        tool_map = {
            "clio": "SH_ClioGet",
            "chaos": "SH_ChaosGrasp",
            "hercules": "SH_HerculesReferee",
            "pandora": "SH_PandorasLink",
            "chronos": "SH_ChronosSift",
            "aion": "SH_AIONDetector",
            "plutos": "SH_PlutosGate",
            "hekate": "SH_HekateWeaver",
            "sphinx": "SH_SphinxDeciphering",
            "siren": "SH_Sirenhunt" 
        }
        for key, script in tool_map.items():
            self.modules[key] = self._import_dynamic(script)

    def run_module(self, key, args):
        func = self.modules.get(key)
        if not func:
            print(f"[!] Module '{key}' not found. Skipping Stage...")
            return False
        
        print(f"\n>>> [EXECUTING] {key.upper()} Stage...")
        
        # タイマー起動 (自動計測)
        start_t = time.perf_counter()
        success = False
        
        try:
            # モジュールの main() が引数を取るかチェックして呼び分け
            import inspect
            sig = inspect.signature(func)
            if len(sig.parameters) > 0:
                func(args)
            else:
                func() # 引数なしの main() に対応
            
            success = True
        except Exception as e:
            print(f"[!] {key.upper()} Stage Failed: {e}")
            import traceback
            traceback.print_exc()
            success = False
        finally:
            elapsed = time.perf_counter() - start_t
            self.stats["Modules"][key] = round(elapsed, 4)
            status_str = "DONE" if success else "FAILED"
            print(f">>> [{status_str}] {key.upper()} finished in {elapsed:.4f}s")
        
        return success

    # [UPDATE] legacy_mode 引数を追加
    def full_auto_scan(self, csv_dir, raw_dir, out_dir, case_name, start_date=None, end_date=None, mount_point=None, legacy_mode=False):
        print_logo()
        print(f"[*] --- INITIATING CERBERUS PIPELINE: {case_name} ---")
        
        # [UPDATE] モード表示
        if legacy_mode:
            print("[*] MODE: LEGACY OS DETECTED (Aggressive Noise Filtering ON)")
        else:
            print("[*] MODE: STANDARD (Modern OS Optimized)")

        if start_date: print(f"[*] Time Filter: {start_date} -> {end_date}")
        
        pipeline_start = time.perf_counter()
        
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
            # [UPDATE] Legacy Mode Flag Passing
            chronos_args = ["-f", str(mft_raw), "-o", str(chronos_out), "--targets-only"] + time_args
            if legacy_mode:
                chronos_args.append("--legacy")
            
            self.run_module("chronos", chronos_args)
        
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
            self.run_module("sphinx", ["-f", str(evtx_raw), "-o", str(sphinx_out)] + time_args)

        # 5.5. Sirenhunt (The Validator)
        prefetch_raw = next(Path(csv_dir).rglob("*PECmd_Output.csv"), None)
        amcache_raw = next(Path(csv_dir).rglob("*Amcache_UnassociatedFileEntries.csv"), None)
        
        siren_json = case_dir / "Sirenhunt_Results.json"
        siren_cmd = [
            "--chronos", str(chronos_out),
            "--pandora", str(pandora_out),
            "-o", str(siren_json)
        ]
        if prefetch_raw: siren_cmd.extend(["--prefetch", str(prefetch_raw)])
        if amcache_raw: siren_cmd.extend(["--amcache", str(amcache_raw)])
        
        self.run_module("siren", siren_cmd)

        # 6. Hekate (The Final Weaver)
        # v1.9ではここが Clotho/Atropos/Lachesis を内包するラッパーとして機能
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
                "--pandora", str(pandora_out),
                "--siren", str(siren_json),
                "--case", case_name # [FIX] Case引数を追加 (レポートタイトル用)
            ])

        # Finalize Pipeline Stats
        total_elapsed = time.perf_counter() - pipeline_start
        self.stats["Total_Execution_Time"] = round(total_elapsed, 4)
        self._export_stats(case_dir)
        
        print(f"\n[*] SUCCESS: Pipeline finished. Case dir: {case_dir}")
        print(f"[*] Total Time: {total_elapsed:.2f}s")

    def _export_stats(self, out_dir):
        """ベンチマーク結果をJSONファイルに出力"""
        try:
            stats_path = Path(out_dir) / "execution_stats.json"
            with open(stats_path, "w") as f:
                json.dump(self.stats, f, indent=4)
            print(f"[+] Benchmark stats saved to '{stats_path.name}'")
        except Exception as e:
            print(f"[!] Failed to save stats: {e}")

def main():
    # 引数が渡されているかチェック
    if len(sys.argv) > 1:
        # Command Line Mode
        parser = argparse.ArgumentParser(description="SH_HeliosConsole v4.5 [Legacy Ready]")
        parser.add_argument("--dir", required=True, help="Parsed CSV Directory (KAPE Modules)")
        parser.add_argument("--raw", help="Raw Artifact Directory (Optional)")
        parser.add_argument("--mft", help="MFT Path (Optional, auto-detected if in dir)")
        parser.add_argument("--mount", help="Mount Point (e.g. E:\\) for AION hashing")
        parser.add_argument("--start", help="Start Date (YYYY-MM-DD)")
        parser.add_argument("--end", help="End Date (YYYY-MM-DD)")
        parser.add_argument("--case", default="Investigation", help="Case Name")
        parser.add_argument("-o", "--out", default="Helios_Output", help="Output Directory")
        # [UPDATE] Legacy Arg
        parser.add_argument("--legacy", action="store_true", help="Enable Legacy Mode (Aggressive Filter for Old OS)")
        
        args = parser.parse_args()
        commander = HeliosCommander()
        raw_target = args.raw if args.raw else args.dir
        commander.full_auto_scan(args.dir, raw_target, args.out, args.case, args.start, args.end, args.mount, args.legacy)
    else:
        # Interactive Mode
        print_logo()
        commander = HeliosCommander()
        try:
            print("[*] Entering Interactive Mode...")
            csv_dir = input("1. Parsed CSV Directory (KAPE Modules): ").strip().strip('"').strip("'")
            if not csv_dir:
                print("[!] Error: CSV Directory required.")
                return

            raw_dir = input("2. Raw Artifact Directory (KAPE Targets) [Enter for same]: ").strip().strip('"').strip("'")
            if not raw_dir: raw_dir = csv_dir
            
            mount_point = input("3. Mount Point (Optional) [e.g. E:\]: ").strip().strip('"').strip("'")
            case_name = input("Case Name [Default: Investigation]: ").strip() or "Investigation"
            
            # [UPDATE] Interactive Legacy Prompt
            legacy_input = input("4. Enable Legacy Mode (Older OS / High Noise)? [y/N]: ").strip().lower()
            legacy_mode = legacy_input in ['y', 'yes']
            
            print("\n[Optional] Time Range (YYYY-MM-DD)")
            start_date = input("Start Date: ").strip()
            end_date = input("End Date: ").strip()
            
            if os.path.exists(csv_dir):
                commander.full_auto_scan(csv_dir, raw_dir, "Helios_Output", case_name, start_date, end_date, mount_point, legacy_mode)
            else:
                print("[!] Error: CSV Directory not found.")
        except KeyboardInterrupt:
            print("\n[!] Aborted.")

if __name__ == "__main__":
    main()
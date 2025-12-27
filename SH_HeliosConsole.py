import sys
import os
from pathlib import Path
import time
import importlib

# ============================================================
#  SH_HeliosConsole v3.9 [Cerberus Orchestrator]
#  Mission: Coordinate all modules & enable Sniper Intel flow.
#  Updates:
#    - Added Mount Point input for AION Hashing.
#    - Updated Hercules arguments to match v3.1 API.
# ============================================================

def print_logo():
    # 画面をクリアしてロゴを表示（Windows/Linux両対応）
    os.system('cls' if os.name == 'nt' else 'clear')
    print(r"""
          , - ~ ~ ~ - ,
      , '   _ _ _ _   ' ,
    ,      |_______|      ,
   ,        _______        ,  < SKIA HELIOS >
  ,        |_______|        ,  v3.9 - Sniper Orchestrator
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

    def _import_dynamic(self, script_name):
        """
        カレントディレクトリまたは tools フォルダから動的に main 関数をロードするっス
        """
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
        # 内部キー名とスクリプト名のマッピング
        tool_map = {
            "clio": "SH_ClioGet",
            "chaos": "SH_ChaosGrasp",
            "hercules": "SH_HerculesReferee",
            "pandora": "SH_PandorasLink",
            "chronos": "SH_ChronosSift",
            "aion": "SH_AIONDetector",
            "plutos": "SH_PlutosGate",
            "hekate": "SH_HekateWeaver",
            "sphinx": "SH_SphinxDeciphering"
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
            # 各スクリプトの main(args) を呼び出す
            func(args)
            return True
        except Exception as e:
            print(f"[!] {key.upper()} Stage Failed: {e}")
            return False

    def full_auto_scan(self, csv_dir, raw_dir, out_dir, case_name, start_date=None, end_date=None, mount_point=None):
        print_logo()
        print(f"[*] --- INITIATING CERBERUS PIPELINE: {case_name} ---")
        
        # セッションディレクトリの作成
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        case_dir = Path(out_dir) / f"{case_name}_{timestamp}"
        case_dir.mkdir(parents=True, exist_ok=True)
        
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

        # 3. Pandora (Target Intel Generation)
        # [VITAL] 先にGhost(削除ファイル)を見つけないとHerculesが狙撃できないっス！
        pandora_out = case_dir / "Ghost_Report.csv"
        p_start = start_date if start_date else "2000-01-01"
        p_end = end_date if end_date else "2099-12-31"
        self.run_module("pandora", ["-d", csv_dir, "--start", p_start, "--end", p_end, "--out", str(pandora_out)])

        # 4. Hercules (Sniper Execution)
        # [UPDATE] v3.1 API: -i -> --timeline, -d -> --kape, --pandora -> --ghosts
        judged_out = case_dir / "Hercules_Judged_Timeline.csv"
        hercules_success = self.run_module("hercules", [
            "--timeline", str(chaos_out), 
            "--kape", csv_dir, 
            "--out", str(judged_out), 
            "--ghosts", str(pandora_out)
        ])

        timeline_target = str(judged_out) if (hercules_success and judged_out.exists()) else str(chaos_out)

        # 5. Deep Forensics (Chronos, AION, Plutos, Sphinx)
        mft_raw = next(Path(csv_dir).rglob("*$MFT_Output.csv"), None)
        chronos_out = case_dir / "Time_Anomalies.csv"
        if mft_raw:
            self.run_module("chronos", ["-f", str(mft_raw), "-o", str(chronos_out), "--targets-only"] + time_args)
        
        aion_out = case_dir / "Persistence_Report.csv"
        aion_args = ["--dir", csv_dir, "--mft", str(mft_raw if mft_raw else timeline_target), "-o", str(aion_out)] + time_args
        if mount_point:
            aion_args.extend(["--mount", mount_point])
        self.run_module("aion", aion_args)

        plutos_out = case_dir / "Exfil_Report.csv"
        plutos_net_out = case_dir / "Exfil_Report_Network.csv"
        self.run_module("plutos", ["--dir", csv_dir, "--pandora", str(pandora_out), "-o", str(plutos_out), "--net-out", str(plutos_net_out)] + time_args)

        sphinx_out = case_dir / "Sphinx_Decoded.csv"
        evtx_raw = next(Path(csv_dir).rglob("*EvtxECmd_Output.csv"), None)
        if evtx_raw:
            self.run_module("sphinx", ["-f", str(evtx_raw), "-o", str(sphinx_out)] + time_args)

        # 6. Hekate (The Final Weaver)
        # 最後に全てのCSVをまとめてレポート化するっス
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
                "--pandora", str(pandora_out)
            ] + time_args)

        print(f"\n[*] SUCCESS: Pipeline finished. Case dir: {case_dir}")

def main():
    commander = HeliosCommander()
    try:
        print("Please provide the paths for SkiaHelios analysis:")
        csv_dir = input("1. Parsed CSV Directory (KAPE Modules): ").strip().strip('"').strip("'")
        raw_dir = input("2. Raw Artifact Directory (KAPE Targets): ").strip().strip('"').strip("'")
        mount_point = input("3. Mount Point (Optional, for Hashing) [e.g. E:\]: ").strip().strip('"').strip("'")
        
        case = input("Case Name [Default: Investigation]: ").strip() or "Investigation"
        
        print("\n[Optional] Specify Time Range (YYYY-MM-DD)")
        start_date = input("Start Date: ").strip()
        end_date   = input("End Date  : ").strip()
        
        if os.path.exists(csv_dir) and os.path.exists(raw_dir):
            commander.full_auto_scan(csv_dir, raw_dir, "Helios_Output", case, start_date, end_date, mount_point)
        else:
            print("[!] Error: One or both paths do not exist. Check your input.")
            input("Press Enter to exit...")
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")

if __name__ == "__main__":
    main()
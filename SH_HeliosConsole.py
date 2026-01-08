import argparse
import subprocess
import sys
import os
from pathlib import Path
import time
import json
from datetime import datetime, timedelta

# ============================================================
#  SH_HeliosConsole v2.4 [Dual-Core Edition]
#  Mission: Orchestrate Standard, Triage, and Deep Dive modes.
#  Update: Pass BOTH Raw and CSV dirs to Hekate/Clotho.
# ============================================================

BANNER = r"""
   _____ __    _       _    _      _ _
  / ____| |   (_)     | |  | |    | (_)
 | (___ | | _  _  __ _| |__| | ___| |_  ___  ___
  \___ \| |/ /| |/ _` |  __  |/ _ \ | |/ _ \/ __|
  ____) |   < | | (_| | |  | |  __/ | | (_) \__ \
 |_____/|_|\_\|_|\__,_|_|  |_|\___|_|_|\___/|___/ v2.4
"""

def run_stage(cmd, stage_name):
    print(f"\n>>> [EXECUTING] {stage_name} Stage...")
    start = time.time()
    try:
        result = subprocess.run(cmd, check=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] {stage_name} Failed: {e}")
        sys.exit(1)
    end = time.time()
    print(f">>> [DONE] {stage_name} finished in {end - start:.4f}s")

def main():
    pipeline_start = time.time()  # Start timing
    print(BANNER)
    parser = argparse.ArgumentParser(description="SkiaHelios Orchestrator")
    parser.add_argument("--dir", required=False, help="Path to KAPE Module Output (CSV)")
    parser.add_argument("--raw", required=False, help="Path to KAPE Target Output (Raw Files)")
    
    parser.add_argument("--case", required=False, help="Case Name")
    parser.add_argument("--legacy", action="store_true", help="Enable Legacy OS adjustments")
    parser.add_argument("--os", default=None, help="Target OS Version Name")
    
    # Modes
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--triage", action="store_true", help="[Mode] Triage: High speed, aggressive filtering.")
    group.add_argument("--deep", type=str, help="[Mode] Deep Dive: Path to Pivot_Config.json")
    
    parser.add_argument("--docx", action="store_true", help="Generate Docx Report")
    parser.add_argument("--lang", default=None, choices=["jp", "en"], help="Report Language (jp/en)")
    parser.add_argument("--enable-yara-webshell", action="store_true", help="[v5.5] Enable YARA WebShell scanning (optional)")
    args = parser.parse_args()

    # --- Interactive Mode ---
    if not args.dir:
        print("\n[?] Input KAPE Output Directory (CSV/Module Output):")
        args.dir = input("    > ").strip().strip('"')
    
    if not args.case:
        print("\n[?] Input Case Name (e.g. Case1_WebSrv):")
        args.case = input("    > ").strip()
    
    # --- Language Selection (Default: Japanese) ---
    if not hasattr(args, 'lang') or not args.lang:
        print("\n[?] Report Language? (jp=日本語 / en=English) [Default: jp]:")
        lang_input = input("    > ").strip().lower()
        args.lang = "en" if lang_input == "en" else "jp"
        print(f"    [+] Language set to: {args.lang.upper()}")

    kape_csv_dir = Path(args.dir)
    if not kape_csv_dir.exists():
        print(f"[!] Error: CSV Directory not found: {kape_csv_dir}")
        sys.exit(1)

    # Rawデータディレクトリの自動検出
    kape_raw_dir = Path(args.raw) if args.raw else None
    
    if not kape_raw_dir:
        print("[*] Raw Artifacts path not specified. Attempting auto-detection...")
        sibling_kape = kape_csv_dir.parent / "kape"
        sibling_source = kape_csv_dir.parent / "source"
        
        if sibling_kape.exists():
            kape_raw_dir = sibling_kape
            print(f"    [+] Auto-detected Raw Dir: {kape_raw_dir}")
        elif sibling_source.exists():
            kape_raw_dir = sibling_source
            print(f"    [+] Auto-detected Raw Dir: {kape_raw_dir}")
        else:
            print("    [!] Could not auto-detect Raw dir. Falling back to CSV dir (History/Registry detection may fail).")
            kape_raw_dir = kape_csv_dir

    # Mode Selection
    if not args.triage and not args.deep:
        print("\n[?] Select Operation Mode:")
        print("    1. Standard (Full Scan)")
        print("    2. Triage (Fast, High Confidence Only)")
        print("    3. Deep Dive (Scope based on Pivot Config)")
        mode_in = input("    > [1]: ").strip()
        if mode_in == "2": args.triage = True
        elif mode_in == "3":
            print("\n[?] Input Path to Pivot_Config.json:")
            args.deep = input("    > ").strip().strip('"')

    out_dir = Path("Helios_Output") / f"{args.case}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Strategy Config
    mode_name = "STANDARD"
    use_silencer = False
    use_junk_killer = False 
    scan_start = "2000-01-01"
    scan_end = "2030-01-01"
    
    if args.triage:
        mode_name = "TRIAGE"
        use_silencer = True
        use_junk_killer = True
    elif args.deep:
        mode_name = "DEEP DIVE"
        use_silencer = False
        use_junk_killer = False
        if os.path.exists(args.deep):
            try:
                with open(args.deep, 'r') as f:
                    pivot_data = json.load(f)
                timestamps = []
                for target in pivot_data.get("Deep_Dive_Targets", []):
                    ts_str = target.get("Timestamp_Hint", "")
                    if ts_str and "T" in ts_str:
                        try:
                            dt = datetime.fromisoformat(ts_str.replace("Z", ""))
                            timestamps.append(dt)
                        except: pass
                if timestamps:
                    min_ts = min(timestamps) - timedelta(minutes=30)
                    max_ts = max(timestamps) + timedelta(minutes=30)
                    scan_start = min_ts.strftime("%Y-%m-%d %H:%M:%S")
                    scan_end = max_ts.strftime("%Y-%m-%d %H:%M:%S")
                    print(f"[*] DEEP DIVE SCOPE: {scan_start} <-> {scan_end}")
            except: pass
        else:
            sys.exit(1)
    
    print(f"[*] --- INITIATING CERBERUS PIPELINE: {args.case} ---")
    
    # Paths
    master_timeline = out_dir / "Master_Timeline.csv"
    time_anomalies = out_dir / "Time_Anomalies.csv"
    ghost_report = out_dir / "Ghost_Report.csv"
    judged_timeline = out_dir / "Hercules_Judged_Timeline.csv"
    aion_out = out_dir / "AION_Persistence.csv"

    # [1] Clio (Browser History) -> Raw Dir を渡す！
    clio_cmd = [
        "python", "-m", "tools.SH_ClioGet",
        "--dir", str(kape_raw_dir), 
        "--out", str(out_dir)
    ]
    run_stage(clio_cmd, "CLIO (Browser History)")

    # [2] Chaos (Timeline) -> CSV Dir
    run_stage(["python", "-m", "tools.SH_ChaosGrasp", "--dir", str(kape_csv_dir), "--out", str(master_timeline)], "CHAOS")

    # [3] Chronos (Icarus Paradox 統合版)
    # Master_Timeline.csv をメインの比較対象(MFT相当)として使用
    chronos_cmd = [
        "python", "-m", "tools.SH_ChronosSift", 
        "-f", str(master_timeline), 
        "-o", str(time_anomalies)
    ]

    # Icarus用のアーティファクトをKAPE CSVディレクトリから自動探索
    # ShimCache (AppCompatCache) - ExclusionListを除外
    shim_files = list(kape_csv_dir.glob("**/*AppCompatCache.csv"))
    shim_files = [f for f in shim_files if "Exclusion" not in f.name]  # ExclusionListを除外
    if shim_files:
        chronos_cmd.extend(["--shimcache", str(shim_files[0])])
        print(f"    [+] Icarus: ShimCache detected -> {shim_files[0].name}")

    # Prefetch
    pf_files = list(kape_csv_dir.glob("**/*Prefetch.csv"))
    if pf_files:
        chronos_cmd.extend(["--prefetch", str(pf_files[0])])
        print(f"    [+] Icarus: Prefetch detected -> {pf_files[0].name}")

    # USN Journal (通常 $J として出力されるもの)
    usn_files = list(kape_csv_dir.glob("**/*$J*.csv"))
    if usn_files:
        chronos_cmd.extend(["--usnj", str(usn_files[0])])
        print(f"    [+] Icarus: USN Journal detected -> {usn_files[0].name}")

    if args.legacy: 
        chronos_cmd.append("--legacy")

    run_stage(chronos_cmd, "CHRONOS (with ICARUS Paradox)")

    # [4] Pandora Pass 1
    pandora_cmd_1 = [
        "python", "-m", "tools.SH_PandorasLink", 
        "-d", str(kape_csv_dir), 
        "--out", str(ghost_report), 
        "--start", scan_start, "--end", scan_end,
        "--chronos", str(time_anomalies)
    ]
    if use_junk_killer: pandora_cmd_1.append("--triage")
    run_stage(pandora_cmd_1, f"PANDORA (Pass 1)")

    # [5] Hercules
    hercules_cmd = [
        "python", "-m", "tools.SH_HerculesReferee",
        "--timeline", str(master_timeline),
        "--ghosts", str(ghost_report),
        "--dir", str(kape_csv_dir),
        "--out", str(judged_timeline)
    ]
    if use_silencer: hercules_cmd.append("--triage")
    run_stage(hercules_cmd, f"HERCULES")

    # [6] Pandora Pass 2
    pandora_cmd_2 = pandora_cmd_1 + ["--hercules", str(judged_timeline)]
    run_stage(pandora_cmd_2, "PANDORA (Pass 2)")

    # [7] AION
    run_stage([
        "python", "-m", "tools.SH_AIONDetector", 
        "--dir", str(kape_csv_dir),
        "--out", str(aion_out),
        "--raw", str(kape_raw_dir) # [v5.6] ChainScavenger
    ], "AION")
    
    # ==========================================
    # [7.5] PLUTOS GATE (Network & Exfil) -> NEW
    # ==========================================
    plutos_out = out_dir / "Plutos_Report.csv"
    plutos_net_out = out_dir / "Plutos_Network_Details.csv"
    
    plutos_cmd = [
        "python", "-m", "tools.SH_PlutosGate",
        "--dir", str(kape_csv_dir),
        "--pandora", str(ghost_report),
        "--out", str(plutos_out),
        "--net-out", str(plutos_net_out)
    ]
    
    # Deep Diveモードなら期間指定も渡して範囲を絞る
    if args.deep and scan_start and scan_end:
         plutos_cmd.extend(["--start", scan_start, "--end", scan_end])

    run_stage(plutos_cmd, "PLUTOS (Network & Lateral)")
    
    # [7.6] YARA WebShell Scanner (Optional) [v5.5]
    if getattr(args, 'enable_yara_webshell', False):
        yara_out = out_dir / "YARA_WebShell_Results.csv"
        yara_cmd = [
            "python", "-m", "tools.SH_YaraScanner",
            "--raw", str(kape_raw_dir) if kape_raw_dir else "",
            "--ghost", str(ghost_report),
            "--out", str(yara_out)
        ]
        run_stage(yara_cmd, "YARA (WebShell Hunter)")
    
    # [8] Hekate -> Raw と CSV の両方を渡す！
    hekate_cmd = [
        "python", "SH_HekateTriad.py",
        "--case", args.case,
        "--os", args.os if args.os else "Windows (Auto-Detected)",
        "--outdir", str(out_dir),
        "--timeline", str(master_timeline),
        "--pandora", str(ghost_report),
        "--hercules", str(judged_timeline),
        "--chronos", str(time_anomalies),
        "--aion", str(aion_out),
        "--kape", str(kape_raw_dir), # Raw (History用)
        "--csv", str(kape_csv_dir),   # CSV (Registry/EventLog用)
        "--lang", args.lang           # Language
    ]
    if args.docx: hekate_cmd.append("--docx")
    
    run_stage(hekate_cmd, "HEKATE")

    # Calculate elapsed time
    elapsed = time.time() - pipeline_start
    mins, secs = divmod(int(elapsed), 60)
    print(f"\n[*] SUCCESS: Pipeline finished in {mins}m {secs}s. Case dir: {out_dir}")

if __name__ == "__main__":
    main()
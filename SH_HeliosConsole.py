import argparse
import subprocess
import sys
import os
from pathlib import Path
import time
import json
from datetime import datetime, timedelta

# ============================================================
#  SH_HeliosConsole v2.1 [Tri-Mode Commander]
#  Mission: Orchestrate Standard, Triage, and Deep Dive modes.
#  Update: Implemented 3-way strategy with Deep Dive Scoping.
# ============================================================

BANNER = r"""
   _____ __    _       _    _      _ _
  / ____| |   (_)     | |  | |    | (_)
 | (___ | | _  _  __ _| |__| | ___| |_  ___  ___
  \___ \| |/ /| |/ _` |  __  |/ _ \ | |/ _ \/ __|
  ____) |   < | | (_| | |  | |  __/ | | (_) \__ \
 |_____/|_|\_\|_|\__,_|_|  |_|\___|_|_|\___/|___/ v4.43
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
    print(BANNER)
    parser = argparse.ArgumentParser(description="SkiaHelios Orchestrator")
    parser.add_argument("--dir", required=False, help="Path to KAPE output folder")
    parser.add_argument("--case", required=False, help="Case Name")
    parser.add_argument("--legacy", action="store_true", help="Enable Legacy OS adjustments")
    parser.add_argument("--os", default=None, help="Target OS Version Name (e.g. 'Windows 10 Pro')")
    
    # Modes
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--triage", action="store_true", help="[Mode] Triage: High speed, aggressive filtering.")
    group.add_argument("--deep", type=str, help="[Mode] Deep Dive: Path to Pivot_Config.json")
    
    parser.add_argument("--docx", action="store_true", help="Generate Docx Report")
    args = parser.parse_args()

    # --- Interactive Mode ---
    if not args.dir:
        print("\n[?] Input KAPE Output Directory:")
        args.dir = input("    > ").strip().strip('"')
    
    if not args.case:
        print("\n[?] Input Case Name (e.g. Case1_WebSrv):")
        args.case = input("    > ").strip()

    kape_dir = Path(args.dir)
    if not kape_dir.exists():
        print(f"[!] Error: Directory not found: {kape_dir}")
        sys.exit(1)

    # Mode Selection (Interactive)
    if not args.triage and not args.deep:
        # Check if user wants to select mode interactively if not passed via CLI
        # But if CLI was used partially (e.g. just --dir), we assume Standard unless prompted?
        # Let's prompt if no mode flags were given
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
    
    # --- Strategy Decision ---
    mode_name = "STANDARD"
    use_silencer = False  # for Hercules (System Ignore)
    use_junk_killer = False # for Pandora (Log/DB Ignore)
    
    # Default Timeline (Wide Range)
    scan_start = "2000-01-01"
    scan_end = "2030-01-01"
    
    if args.triage:
        mode_name = "TRIAGE"
        use_silencer = True
        use_junk_killer = True
    elif args.deep:
        mode_name = "DEEP DIVE"
        use_silencer = False # System logs enabled for deep analysis
        use_junk_killer = False # Show everything
        
        # [NEW] Deep Dive Scope Logic
        # Interactive input might have set args.deep to string path
        if os.path.exists(args.deep):
            try:
                with open(args.deep, 'r') as f:
                    pivot_data = json.load(f)
                
                # ターゲットの中で最も古い/新しい日時を見つけて範囲を設定
                timestamps = []
                for target in pivot_data.get("Deep_Dive_Targets", []):
                    ts_str = target.get("Timestamp_Hint", "")
                    if ts_str and "T" in ts_str: # 簡易チェック
                        try:
                            # Parse ISO format (adjust as needed)
                            dt = datetime.fromisoformat(ts_str.replace("Z", ""))
                            timestamps.append(dt)
                        except: pass
                
                if timestamps:
                    min_ts = min(timestamps) - timedelta(minutes=30)
                    max_ts = max(timestamps) + timedelta(minutes=30)
                    scan_start = min_ts.strftime("%Y-%m-%d %H:%M:%S")
                    scan_end = max_ts.strftime("%Y-%m-%d %H:%M:%S")
                    print(f"[*] DEEP DIVE SCOPE NARROWED: {scan_start} <-> {scan_end}")
                    print(f"    (Focusing on {len(timestamps)} pivot points)")
                else:
                    print("[!] No valid timestamps in Pivot Config. Falling back to full scan.")
            except Exception as e:
                print(f"[!] Pivot Config Parse Error: {e}. Falling back to full scan.")
        else:
            print(f"[!] Pivot Config not found: {args.deep}")
            sys.exit(1)
    
    print(f"[*] --- INITIATING CERBERUS PIPELINE: {args.case} ---")
    print(f"[*] OPERATION MODE: {mode_name}")
    if args.legacy: print("[*] LEGACY OS ADJUSTMENTS: ON")

    # Paths
    master_timeline = out_dir / "Master_Timeline.csv"
    time_anomalies = out_dir / "Time_Anomalies.csv"
    ghost_report = out_dir / "Ghost_Report.csv"
    judged_timeline = out_dir / "Hercules_Judged_Timeline.csv"
    
    # 1. Chaos (Timeline)
    run_stage(["python", "-m", "tools.SH_ChaosGrasp", "--dir", str(kape_dir), "--out", str(master_timeline)], "CHAOS")

    # 2. Chronos (Time Sift)
    chronos_cmd = ["python", "-m", "tools.SH_ChronosSift", "-f", str(master_timeline), "-o", str(time_anomalies)]
    if args.legacy: chronos_cmd.append("--legacy")
    run_stage(chronos_cmd, "CHRONOS")

    # 3. Pandora (Pass 1)
    pandora_cmd_1 = [
        "python", "-m", "tools.SH_PandorasLink", 
        "-d", str(kape_dir), 
        "--out", str(ghost_report), 
        "--start", scan_start, "--end", scan_end, # [UPDATED] Dynamic scope
        "--chronos", str(time_anomalies)
    ]
    if use_junk_killer: pandora_cmd_1.append("--triage")
    run_stage(pandora_cmd_1, f"PANDORA (Pass 1) [{mode_name}]")

    # 4. Hercules (Event Log)
    hercules_cmd = [
        "python", "-m", "tools.SH_HerculesReferee",
        "--timeline", str(master_timeline),
        "--ghosts", str(ghost_report),
        "--dir", str(kape_dir),
        "--out", str(judged_timeline)
    ]
    if use_silencer: hercules_cmd.append("--triage")
    run_stage(hercules_cmd, f"HERCULES [{mode_name}]")

    # 5. Pandora (Pass 2 - Feedback)
    pandora_cmd_2 = pandora_cmd_1 + ["--hercules", str(judged_timeline)]
    run_stage(pandora_cmd_2, "PANDORA (Pass 2)")

    # 6. AION (Persistence)
    # [UPDATED] Pass explicit output path to avoid file-path dependency
    aion_out = out_dir / "AION_Persistence.csv"
    run_stage([
        "python", "-m", "tools.SH_AIONDetector", 
        "--dir", str(kape_dir),  # Fixed: AION uses --dir, not --kape
        "--out", str(aion_out)   # Fixed: Explicit output path
    ], "AION")
    
    # (File rename block removed as we now output directly)

    # 7. Hekate (Final Report)
    hekate_cmd = [
        "python", "SH_HekateTriad.py",
        "--case", args.case,
        "--host", "4ORENSICS", # Placeholder, ideally detected inside Hekate
        "--user", "Hunter",    
        "--os", args.os if args.os else "Windows (Auto-Detected)",
        "--outdir", str(out_dir),
        "--timeline", str(master_timeline),
        "--pandora", str(ghost_report),
        "--hercules", str(judged_timeline),
        "--chronos", str(time_anomalies),
        # Pass AION file if moved, or KAPE dir if AION needs re-parsing
        "--aion", str(out_dir / "AION_Persistence.csv"),
        # [NEW] Pass KAPE Source for USN & History Discovery
        "--kape", str(kape_dir) 
    ]
    if args.docx: hekate_cmd.append("--docx")
    
    run_stage(hekate_cmd, "HEKATE")

    print(f"\n[*] SUCCESS: Pipeline finished. Case dir: {out_dir}")
    if mode_name == "TRIAGE":
        pivot_conf = out_dir / "Pivot_Config.json"
        print(f"[*] NEXT STEP: To investigate deeper, run:")
        print(f"    python SH_HeliosConsole.py ... --deep \"{pivot_conf}\"")

if __name__ == "__main__":
    main()
import argparse
import subprocess
import sys
import os
import re  # [NEW] 正規表現用
from pathlib import Path
import time
import json
from datetime import datetime, timedelta

# [NEW] メモリ監視用に psutil をインポート
try:
    import psutil
except ImportError:
    print("[!] 'psutil' module not found. Please run: pip install psutil")
    sys.exit(1)

# ============================================================
#  SH_HeliosConsole v2.5 [Sanitized Edition]
#  Mission: Orchestrate Standard, Triage, and Deep Dive modes.
#  Update: Auto-sanitize Case Name inputs to prevent path errors.
# ============================================================

BANNER = r"""
   _____ __    _       _    _      _ _
  / ____| |   (_)     | |  | |    | (_)
 | (___ | | _  _  __ _| |__| | ___| |_  ___  ___
  \___ \| |/ /| |/ _` |  __  |/ _ \ | |/ _ \/ __|
  ____) |   < | | (_| | |  | |  __/ | | (_) \__ \
 |_____/|_|\_\|_|\__,_|_|  |_|\___|_|_|\___/|___/ v6.3
"""

# ベンチマーク結果を保存するリスト
BENCHMARK_RESULTS = []

def run_stage(cmd, stage_name):
    # (省略: 変更なし)
    print(f"\n>>> [EXECUTING] {stage_name} Stage...")
    
    start_time = time.time()
    peak_memory_mb = 0.0
    
    try:
        process = subprocess.Popen(
            cmd, 
            stdout=sys.stdout, 
            stderr=sys.stderr,
            text=True
        )
        
        ps_proc = psutil.Process(process.pid)
        
        while process.poll() is None:
            try:
                mem_info = ps_proc.memory_info()
                current_mb = mem_info.rss / (1024 * 1024)
                if current_mb > peak_memory_mb:
                    peak_memory_mb = current_mb
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass 
            
            time.sleep(0.1)
            
        if process.returncode != 0:
            print(f"[!] {stage_name} Failed with return code {process.returncode}")
            sys.exit(1)
            
    except Exception as e:
        print(f"[!] {stage_name} Execution Error: {e}")
        sys.exit(1)

    end_time = time.time()
    duration = end_time - start_time
    
    print(f">>> [DONE] {stage_name} finished in {duration:.4f}s | Peak Mem: {peak_memory_mb:.2f} MB")
    
    BENCHMARK_RESULTS.append({
        "Stage": stage_name,
        "Duration_Sec": round(duration, 4),
        "Peak_Memory_MB": round(peak_memory_mb, 2),
        "Command": " ".join(cmd[:2]) + "..." 
    })

def generate_benchmark_report(out_dir):
    # (省略: 変更なし)
    report_path = out_dir / "Benchmark_Report.md"
    json_path = out_dir / "Benchmark_Stats.json"
    
    total_time = sum(r['Duration_Sec'] for r in BENCHMARK_RESULTS)
    max_mem = max(r['Peak_Memory_MB'] for r in BENCHMARK_RESULTS) if BENCHMARK_RESULTS else 0
    
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({
            "Total_Time": total_time,
            "Max_Memory_Peak": max_mem,
            "Details": BENCHMARK_RESULTS
        }, f, indent=4)
        
    md_content = f"""# 🚀 SkiaHelios Performance Benchmark

**Case:** {out_dir.name}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Execution Time:** {total_time:.2f} sec
**Max Memory Consumption:** {max_mem:.2f} MB

| Stage Name | Duration (s) | Peak Memory (MB) | Status |
| :--- | :---: | :---: | :---: |
"""
    
    for res in BENCHMARK_RESULTS:
        mem_icon = "🟢"
        if res['Peak_Memory_MB'] > 1000: mem_icon = "🔴"
        elif res['Peak_Memory_MB'] > 500: mem_icon = "🟡"
        
        md_content += f"| **{res['Stage']}** | {res['Duration_Sec']:.2f}s | {mem_icon} {res['Peak_Memory_MB']:.2f} MB | ✅ Done |\n"

    md_content += "\n> *Measured by SH_HeliosConsole Benchmark Engine*\n"
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(md_content)
    
    print(f"\n[+] Benchmark Report Generated: {report_path}")

def sanitize_case_name(raw_name):
    """
    [FIX] Input Sanitizer
    Full path input -> Extract folder name
    Invalid chars -> Replace with underscore
    """
    if not raw_name: return "Unnamed_Case"
    
    # 1. Remove quotes
    clean = raw_name.strip('"').strip("'")
    
    # 2. Extract basename if path separators exist
    if "\\" in clean or "/" in clean:
        clean = Path(clean).name
        
    # 3. Replace invalid chars for filenames (Windows specific mostly)
    clean = re.sub(r'[\\/*?:"<>|]', '_', clean)
    
    return clean

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
        raw_case_input = input("    > ").strip()
        args.case = sanitize_case_name(raw_case_input) # Apply Sanitization
    else:
        # CLI引数で渡された場合もサニタイズ
        args.case = sanitize_case_name(args.case)

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
        
        # [v2.6] Enhanced Auto-Detection Logic
        # Pattern 1: CSV dir is "out", Raw is "kape" (sibling folders)
        # e.g., dfir-case1/out (CSV) -> dfir-case1/kape (Raw)
        parent_dir = kape_csv_dir.parent
        sibling_kape = parent_dir / "kape"
        sibling_source = parent_dir / "source"
        sibling_raw = parent_dir / "raw"
        
        # Pattern 2: CSV dir contains "out" in name, check for "kape" in parent
        # e.g., C:\Temp\dfir-case1\out -> C:\Temp\dfir-case1\kape
        
        detected = None
        if sibling_kape.exists():
            detected = sibling_kape
        elif sibling_source.exists():
            detected = sibling_source
        elif sibling_raw.exists():
            detected = sibling_raw
        
        if detected:
            kape_raw_dir = detected
            print(f"    [+] Auto-detected Raw Dir: {kape_raw_dir}")
        else:
            # Auto-detection failed, prompt user
            print("    [!] Could not auto-detect Raw directory.")
            print("\n[?] Please input the path to Raw Artifacts (KAPE Target Output):")
            print("    (This is typically the 'kape' folder containing D\\, E\\, or VSS* subfolders)")
            print("    (Press Enter to skip and use CSV dir as fallback)")
            raw_input = input("    > ").strip().strip('"')
            
            if raw_input and Path(raw_input).exists():
                kape_raw_dir = Path(raw_input)
                print(f"    [+] Raw Dir set to: {kape_raw_dir}")
            else:
                print("    [!] Falling back to CSV dir (History/Registry detection may fail).")
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

    # --- [v2.5] Docx Generation Prompt ---
    if not args.docx:
        print("\n[?] Generate Docx Report? (Requires Pandoc) [y/N]:")
        docx_in = input("    > ").strip().lower()
        if docx_in == 'y' or docx_in == 'yes':
            args.docx = True
            print("    [+] Docx Generation ENABLED")

    # [FIX] Output Directory Construction
    # args.case is now sanitized, so this path will be relative and valid
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

    # [1] Clio (Browser History)
    clio_cmd = [
        "python", "-m", "tools.SH_ClioGet",
        "--dir", str(kape_raw_dir), 
        "--out", str(out_dir)
    ]
    run_stage(clio_cmd, "CLIO (Browser History)")

    # [2] Chaos (Timeline)
    run_stage(["python", "-m", "tools.SH_ChaosGrasp", "--dir", str(kape_csv_dir), "--out", str(master_timeline)], "CHAOS")

    # [3] Chronos (Icarus Paradox)
    chronos_cmd = [
        "python", "-m", "tools.SH_ChronosSift", 
        "-f", str(master_timeline), 
        "-o", str(time_anomalies)
    ]

    shim_files = list(kape_csv_dir.glob("**/*AppCompatCache.csv"))
    shim_files = [f for f in shim_files if "Exclusion" not in f.name]
    if shim_files:
        chronos_cmd.extend(["--shimcache", str(shim_files[0])])
        print(f"    [+] Icarus: ShimCache detected -> {shim_files[0].name}")

    pf_files = list(kape_csv_dir.glob("**/*Prefetch.csv"))
    if pf_files:
        chronos_cmd.extend(["--prefetch", str(pf_files[0])])
        print(f"    [+] Icarus: Prefetch detected -> {pf_files[0].name}")

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
        "--out", str(judged_timeline),
        "--chronos", str(time_anomalies),
        "--raw", str(kape_raw_dir)  # [FIX] Pass Raw directory for ConsoleHost_history.txt
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
        "--raw", str(kape_raw_dir)
    ], "AION")
    
    # [7.5] PLUTOS GATE
    plutos_out = out_dir / "Plutos_Report.csv"
    plutos_net_out = out_dir / "Plutos_Network_Details.csv"
    
    plutos_cmd = [
        "python", "-m", "tools.SH_PlutosGate",
        "--dir", str(kape_csv_dir),
        "--pandora", str(ghost_report),
        "--out", str(plutos_out),
        "--net-out", str(plutos_net_out)
    ]
    
    if args.deep and scan_start and scan_end:
         plutos_cmd.extend(["--start", scan_start, "--end", scan_end])

    run_stage(plutos_cmd, "PLUTOS (Network & Lateral)")
    
    if getattr(args, 'enable_yara_webshell', False):
        yara_out = out_dir / "YARA_WebShell_Results.csv"
        yara_cmd = [
            "python", "-m", "tools.SH_YaraScanner",
            "--raw", str(kape_raw_dir) if kape_raw_dir else "",
            "--ghost", str(ghost_report),
            "--out", str(yara_out)
        ]
        run_stage(yara_cmd, "YARA (WebShell Hunter)")
    
    # [8] Hekate
    # args.case is already sanitized here
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
        "--kape", str(kape_raw_dir),
        "--csv", str(kape_csv_dir),
        "--lang", args.lang
    ]
    if args.docx: hekate_cmd.append("--docx")
    
    run_stage(hekate_cmd, "HEKATE")

    elapsed = time.time() - pipeline_start
    mins, secs = divmod(int(elapsed), 60)
    print(f"\n[*] SUCCESS: Pipeline finished in {mins}m {secs}s. Case dir: {out_dir}")
    
    generate_benchmark_report(out_dir)

if __name__ == "__main__":
    main()
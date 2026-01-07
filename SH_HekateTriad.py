import argparse
import polars as pl
import os
import sys
import json
from pathlib import Path

# ============================================================
# [CRITICAL FIX] 1. インポートを旧Writerから新Coreへ変更
# ============================================================
from tools.lachesis.core import LachesisCore
from tools.SH_ThemisLoader import ThemisLoader

# ============================================================
#  SH_HekateTriad v1.9 [Refactored Edition]
#  Mission: Aggregate, Filter, Narrate, and pass Intel.
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True)
    parser.add_argument("--host", default="Unknown")
    parser.add_argument("--user", default="Unknown")
    parser.add_argument("--outdir", required=True)
    parser.add_argument("--os", default="Windows (Auto-Detected)", help="Operating System Version")
    
    # Artifact Inputs
    parser.add_argument("--timeline", help="Master Timeline CSV")
    parser.add_argument("--ghosts", help="Pandora Ghost Report CSV")
    parser.add_argument("--pandora", dest="ghosts", help="Alias for --ghosts") 
    
    parser.add_argument("--hercules", help="Hercules Judged Timeline CSV")
    parser.add_argument("--chronos", help="Chronos Anomalies CSV")
    parser.add_argument("--aion", help="KAPE dir for AION (or AION result file)")
    parser.add_argument("--kape", help="KAPE Output Directory (History Discovery)")
    
    parser.add_argument("--docx", action="store_true")
    args = parser.parse_args()

    print("[*] Hekate v1.9: Analyzing narrative with Refactored Lachesis...")
    
    # 1. Load Dataframes
    def load_pl(path):
        if path and os.path.exists(path):
            try: return pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
            except: return None
        return None

    dfs = {}
    dfs['Timeline'] = load_pl(args.timeline)
    dfs['Pandora'] = load_pl(args.ghosts)
    
    # Auto-Detect Browser History
    history_csv = None
    for root, dirs, files in os.walk(args.outdir):
        for f in files:
            if "Browser_History" in f and f.endswith(".csv"):
                history_csv = os.path.join(root, f)
                print(f"    [+] Found Browser History: {f}")
                break
        if history_csv: break

    dfs['Hercules'] = load_pl(args.hercules)
    dfs['Chronos'] = load_pl(args.chronos)
    
    aion_path = args.aion
    if aion_path and os.path.isdir(aion_path):
        aion_path = str(Path(args.outdir) / "AION_Persistence.csv")
    if aion_path and os.path.exists(aion_path):
        dfs['AION'] = load_pl(aion_path)

    # USN Journal Injection
    usn_csv = None
    search_roots = [Path(args.outdir)]
    if args.kape: search_roots.append(Path(args.kape))
    search_roots.append(Path(".")) 

    print("    [*] Scanning for USN Journal ($J) to detect Time Paradox...")
    for root_path in search_roots:
        if not root_path.exists(): continue
        for f in root_path.rglob("*$J*Output.csv"):
            if "MFTECmd" in f.name:
                usn_csv = str(f)
                print(f"    [+] Found USN Journal: {usn_csv}")
                break
        if usn_csv: break

    if usn_csv:
        try:
            print("    [!] Injecting USN Journal into Chronos Engine...")
            from tools.SH_ChronosSift import ChronosEngine
            engine = ChronosEngine()
            lf_usn = pl.scan_csv(usn_csv, ignore_errors=True, infer_schema_length=0)
            lf_usn = engine._ensure_columns(lf_usn)
            lf_usn = engine._detect_usn_rollback(lf_usn)
            rollback_hits = lf_usn.filter(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK").collect()
            rollback_hits = rollback_hits.select([pl.col(c).cast(pl.Utf8) for c in rollback_hits.columns])
            
            if rollback_hits.height > 0:
                print(f"      [ALERT] SYSTEM ROLLBACK DETECTED: {rollback_hits.height} events found!")
                if "Chronos_Score" not in rollback_hits.columns and "Threat_Score" in rollback_hits.columns:
                     rollback_hits = rollback_hits.with_columns(pl.col("Threat_Score").alias("Chronos_Score"))
                if dfs['Chronos'] is None:
                    dfs['Chronos'] = rollback_hits
                else:
                    dfs['Chronos'] = pl.concat([dfs['Chronos'], rollback_hits], how="diagonal")
        except Exception as e:
            print(f"    [!] USN Injection Failed: {e}")

    # 2. Build Analysis Result
    events = []
    flow_steps = []
    verdict_flags = set()
    
    if dfs['Hercules'] is not None:
        df_herc = dfs['Hercules']
        if "Timestamp_UTC" in df_herc.columns:
            df_herc = df_herc.sort("Timestamp_UTC")
        for row in df_herc.iter_rows(named=True):
            score = 0
            try: score = int(float(row.get('Threat_Score', 0)))
            except: pass
            tag = str(row.get('Tag', '')).upper()
            verdict = str(row.get('Judge_Verdict', '')).upper()
            is_critical = score >= 60 or "CRITICAL" in verdict or "SNIPER" in verdict
            if is_critical:
                ev = {
                    "Time": row.get('Timestamp_UTC'),
                    "Category": "EXEC", 
                    "Summary": row.get('Action', '') or row.get('Description', ''),
                    "Source": row.get('Artifact_Type', 'Log'),
                    "Criticality": score,
                    "Tag": tag,
                    "Keywords": [row.get('Target_Path')] if row.get('Target_Path') else []
                }
                if "LATERAL" in tag: ev['Category'] = "LATERAL"
                elif "PERSISTENCE" in tag: ev['Category'] = "PERSIST"
                elif "ANTI_FORENSICS" in tag:
                     ev['Category'] = "ANTI"
                     verdict_flags.add("ANTI-FORENSICS")
                events.append(ev)

    analysis_result = {
        "events": events,
        "verdict_flags": verdict_flags,
        "lateral_summary": "Confirmed" if "LATERAL" in verdict_flags else "",
    }

    # [NEW] Load Metadata override
    os_info = args.os
    meta_path = Path(args.outdir) / "Case_Metadata.json"
    if meta_path.exists():
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)
                if meta.get("OS_Info") and "Unknown" not in meta["OS_Info"]:
                    os_info = meta["OS_Info"]
        except: pass

    # ============================================================
    # [CRITICAL FIX] 2. クラス名を LachesisCore に変更
    # ============================================================
    output_md = Path(args.outdir) / f"Grimoire_{args.case}_jp.md"
    lachesis = LachesisCore(lang="jp", hostname=args.host, case_name=args.case)
    
    lachesis.weave_report(
        analysis_result=analysis_result,
        output_path=str(output_md),
        dfs_for_ioc=dfs,
        hostname=args.host,
        os_info=os_info,
        primary_user=args.user,
        history_csv=history_csv,
        history_search_path=args.kape if args.kape else (str(Path(args.timeline).parent) if args.timeline else args.outdir)
    )

    if args.docx:
        try:
            import subprocess
            subprocess.run(["python", "tools/SH_MidasTouch.py", "-f", str(output_md)], check=False)
        except: pass

if __name__ == "__main__":
    main()
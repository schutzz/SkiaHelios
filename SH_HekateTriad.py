import argparse
import polars as pl
import os
import sys
from pathlib import Path
from tools.SH_LachesisWriter import LachesisWriter
from tools.SH_ThemisLoader import ThemisLoader

# ============================================================
#  SH_HekateTriad v1.7 [The Broker]
#  Mission: Aggregate, Filter, Narrate, and pass Intel.
#  Update: Pass KAPE dir to Lachesis for history discovery.
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
    
    # [FIX] Accept BOTH --ghosts and --pandora to prevent crashes
    parser.add_argument("--ghosts", help="Pandora Ghost Report CSV")
    parser.add_argument("--pandora", dest="ghosts", help="Alias for --ghosts") 
    
    parser.add_argument("--hercules", help="Hercules Judged Timeline CSV")
    parser.add_argument("--chronos", help="Chronos Anomalies CSV")
    parser.add_argument("--aion", help="KAPE dir for AION (or AION result file)")
    parser.add_argument("--kape", help="KAPE Output Directory (History Discovery)")
    
    parser.add_argument("--docx", action="store_true")
    args = parser.parse_args()

    print("[*] Hekate v1.3: Analyzing narrative...")
    
    # 1. Load Dataframes
    loader = ThemisLoader([])
    def load_pl(path):
        if path and os.path.exists(path):
            try: return pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
            except: return None
        return None

    dfs = {}
    dfs['Timeline'] = load_pl(args.timeline)
    dfs['Pandora'] = load_pl(args.ghosts)
    
    # [v1.6] Auto-Detect Browser History
    history_csv = None
    for root, dirs, files in os.walk(args.outdir):
        for f in files:
            if "Browser_History" in f and f.endswith(".csv"):
                history_csv = os.path.join(root, f)
                print(f"    [+] Found Browser History: {f}")
                break
        if history_csv: break

    # 2. Analyze Timeline & Extract Facts.ghosts
    dfs['Hercules'] = load_pl(args.hercules)
    dfs['Chronos'] = load_pl(args.chronos)
    
    # AION Handling
    aion_path = args.aion
    # If aion path is a directory (KAPE dir), guess the file
    if aion_path and os.path.isdir(aion_path):
        aion_path = str(Path(args.outdir) / "AION_Persistence.csv")
    
    if aion_path and os.path.exists(aion_path):
        dfs['AION'] = load_pl(aion_path)
    
    # [NEW] Load Metadata from Hercules (OS Info)
    os_info = "Windows (Auto-Detected)"
    meta_path = Path(args.outdir) / "Case_Metadata.json"
    if meta_path.exists():
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)
                if meta.get("OS_Info") and meta["OS_Info"] != "Windows (Unknown Version)":
                    os_info = meta["OS_Info"]
                    print(f"    [+] Loaded OS Info from Metadata: {os_info}")
        except: pass
    
    # 2. Build Analysis Result (Storyteller Logic)
    events = []
    flow_steps = []
    verdict_flags = set()
    
    # --- Hercules Processing (Filter & Flow) ---
    if dfs['Hercules'] is not None:
        df_herc = dfs['Hercules']
        if "Timestamp_UTC" in df_herc.columns:
            df_herc = df_herc.sort("Timestamp_UTC")
        
        for row in df_herc.iter_rows(named=True):
            score = 0
            try: score = int(float(row.get('Threat_Score', 0)))
            except: pass
            
            # [Display Threshold] Markdown only gets High Confidence (>60) OR Critical Tags
            tag = str(row.get('Tag', '')).upper()
            verdict = str(row.get('Judge_Verdict', '')).upper()
            
            is_critical = score >= 60 or "CRITICAL" in verdict or "SNIPER" in verdict
            
            # Story Building
            if is_critical:
                summary = row.get('Action', '') or row.get('Description', '')
                clean_sum = summary.replace("Exec: ", "").replace("Folder Accessed:", "Access:").strip()[:80]
                
                if "PERSISTENCE" in tag: 
                    flow_steps.append(f"Persistence: {clean_sum}")
                    verdict_flags.add("PERSISTENCE")
                elif "EXECUTION" in tag or "CMD_EXEC" in tag:
                    flow_steps.append(f"Execution: {clean_sum}")
                    verdict_flags.add("EXECUTION")
                elif "TIMESTOMP" in tag or "FALSIFIED" in tag:
                    flow_steps.append(f"Timestomp: {clean_sum}")
                    verdict_flags.add("ANTI-FORENSICS")
                elif "CRITICAL" in verdict:
                    flow_steps.append(f"Critical Event: {clean_sum}")

            # Add to Events List (Filtered)
            if is_critical:
                ev = {
                    "Time": row.get('Timestamp_UTC'),
                    "Category": "EXEC", 
                    "Summary": row.get('Action', '') or row.get('Description', ''),
                    "Source": row.get('Artifact_Type', 'Log'),
                    "Criticality": score,
                    "Keywords": [row.get('Target_Path')] if row.get('Target_Path') else []
                }
                if "LATERAL" in tag: ev['Category'] = "LATERAL"
                elif "PERSISTENCE" in tag: ev['Category'] = "PERSIST"
                elif "EXECUTION" in tag: ev['Category'] = "EXEC"
                elif "CREATION" in tag or "DROP" in tag: ev['Category'] = "DROP"
                
                events.append(ev)

    # --- Chronos Processing (Add to Flow) ---
    if dfs['Chronos'] is not None:
        df_chronos = dfs['Chronos']
        # If Score col exists
        score_col = "Chronos_Score" if "Chronos_Score" in df_chronos.columns else "Threat_Score"
        if score_col in df_chronos.columns:
            high_chronos = df_chronos.filter(pl.col(score_col).cast(pl.Int64, strict=False) >= 50)
            for row in high_chronos.iter_rows(named=True):
                fname = row.get("FileName", "Unknown")
                anomaly = row.get("Anomaly_Time", "Anomaly")
                flow_steps.append(f"Timestomp ({anomaly}): {fname}")
                verdict_flags.add("TIMESTOMP")

    # --- AION Processing (Add to Flow) ---
    if dfs.get('AION') is not None:
        df_aion = dfs['AION']
        if "AION_Score" in df_aion.columns:
            high_aion = df_aion.filter(pl.col("AION_Score").cast(pl.Int64, strict=False) >= 50)
            for row in high_aion.iter_rows(named=True):
                tname = row.get("Target_FileName", "Unknown")
                flow_steps.append(f"Persistence Found: {tname}")
                verdict_flags.add("PERSISTENCE")

    # De-duplicate flow steps
    unique_flow = []
    seen = set()
    for f in flow_steps:
        if f not in seen:
            unique_flow.append(f)
            seen.add(f)
    
    # Limit flow steps in summary
    if len(unique_flow) > 15:
        unique_flow = unique_flow[:15] + ["... (See Timeline for more)"]

    phases = [events] if events else []
    
    # 3. Construct Narrative Bundle
    analysis_result = {
        "events": events,
        "phases": phases,
        "origin_stories": [], 
        "verdict_flags": verdict_flags,
        "lateral_summary": "Confirmed" if "LATERAL" in verdict_flags else "",
        "flow_steps": unique_flow
    }

    # [NEW] Load Metadata override
    os_info = args.os # Default from args
    meta_path = Path(args.outdir) / "Case_Metadata.json"
    if meta_path.exists():
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)
                if meta.get("OS_Info") and "Unknown" not in meta["OS_Info"]:
                    os_info = meta["OS_Info"]
                    print(f"    [+] Loaded OS Info from Metadata: {os_info}")
        except: pass

    # 4. Summon Lachesis
    output_md = Path(args.outdir) / f"Grimoire_{args.case}_jp.md"
    lachesis = LachesisWriter(lang="jp", hostname=args.host, case_name=args.case)
    
    lachesis.weave_report(
        analysis_result=analysis_result,
        output_path=str(output_md),
        dfs_for_ioc=dfs,
        hostname=args.host,
        os_info=args.os,
        primary_user=args.user,
        history_csv=history_csv,
        history_search_path=args.kape if args.kape else (str(Path(args.timeline).parent) if args.timeline else args.outdir)
    )

    if args.docx:
        try:
            import subprocess # Added this import for subprocess.run
            subprocess.run(["python", "tools/SH_MidasTouch.py", "-f", str(output_md)], check=False)
        except: pass

if __name__ == "__main__":
    main()
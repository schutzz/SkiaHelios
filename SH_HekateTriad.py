import argparse
import polars as pl
import os
import sys
import json
from pathlib import Path
from datetime import datetime, timedelta

# ============================================================
# [CRITICAL] Case 7 Refactored Imports
# ============================================================
from tools.lachesis.core import LachesisCore
from tools.SH_ThemisLoader import ThemisLoader
from tools.SH_ClothoReader import ClothoReader

# ============================================================
#  SH_HekateTriad v2.7 [Hybrid Edition]
#  Mission: Aggregate, Filter, Narrate using Clotho's Brain.
#  Status: Case 7 Structure + Case 2 Logic (Restored)
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True)
    parser.add_argument("--host", default="Unknown")
    parser.add_argument("--user", default="Unknown")
    parser.add_argument("--outdir", required=True)
    parser.add_argument("--os", default="Windows (Auto-Detected)")
    
    # Artifact Inputs
    parser.add_argument("--timeline", help="Master Timeline CSV")
    parser.add_argument("--ghosts", help="Pandora Ghost Report CSV")
    parser.add_argument("--pandora", dest="ghosts", help="Alias for --ghosts") 
    parser.add_argument("--hercules", help="Hercules Judged Timeline CSV")
    parser.add_argument("--chronos", help="Chronos Anomalies CSV")
    parser.add_argument("--aion", help="AION Persistence CSV")
    
    # Source Dirs
    parser.add_argument("--kape", help="KAPE Raw Directory")
    parser.add_argument("--csv", help="KAPE CSV Directory")
    
    parser.add_argument("--docx", action="store_true")
    parser.add_argument("--lang", default="jp", choices=["jp", "en"], help="Report Language")
    parser.add_argument("--input", dest="timeline_input", help="Alias for timeline to satisfy Clotho")

    args = parser.parse_args()

    # Ensure output directory exists
    if not os.path.exists(args.outdir):
        os.makedirs(args.outdir)

    # Priority: Hercules > Timeline
    if args.hercules:
        args.input = args.hercules
    elif args.timeline:
        args.input = args.timeline
    else:
        args.input = None

    print("[*] Hekate v2.7: Identifying Host & User via ClothoReader...")

    clotho = ClothoReader(args)
    dfs, _, detected_host, detected_os, detected_user = clotho.spin_thread()

    final_host = detected_host if detected_host != "Unknown_Host" else args.host
    final_user = detected_user if detected_user != "Unknown_User" else args.user
    final_os = detected_os if detected_os != "Unknown OS" else args.os

    print(f"    [+] Identity Resolved: {final_host} / {final_user} ({final_os})")

    # History CSV Detection
    history_csv = None
    for root, dirs, files in os.walk(args.outdir):
        for f in files:
            if "Browser_History" in f and f.endswith(".csv"):
                history_csv = os.path.join(root, f)
                print(f"    [+] Found Browser History: {f}")
                break
        if history_csv: break

    # AION Load
    aion_path = args.aion
    if aion_path and os.path.isdir(aion_path):
        aion_path = str(Path(args.outdir) / "AION_Persistence.csv")
    if aion_path and os.path.exists(aion_path):
        dfs['AION'] = pl.read_csv(aion_path, ignore_errors=True, infer_schema_length=0)

    # Plutos Recon Load
    recon_path = str(Path(args.outdir) / "Plutos_Report_recon.csv")
    if os.path.exists(recon_path):
        print(f"    [+] Loading Plutos Recon Report: {recon_path}")
        dfs['Recon'] = pl.read_csv(recon_path, ignore_errors=True, infer_schema_length=0)
    else:
        # Fallback search
        for root, dirs, files in os.walk(args.outdir):
            for f in files:
                if f.endswith("_recon.csv") and "Plutos" in f:
                    print(f"    [+] Loading Plutos Recon Report: {f}")
                    dfs['Recon'] = pl.read_csv(os.path.join(root, f), ignore_errors=True, infer_schema_length=0)
                    break
            if 'Recon' in dfs: break

    # USN Journal Injection
    usn_csv = None
    search_roots = [Path(args.outdir)]
    if args.kape: search_roots.append(Path(args.kape))
    search_roots.append(Path(".")) 

    for root_path in search_roots:
        if not root_path.exists(): continue
        for f in root_path.rglob("*$J*Output.csv"):
            if "MFTECmd" in f.name:
                usn_csv = str(f)
                break
        if usn_csv: break

    if usn_csv:
        try:
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
                
                if dfs.get('Chronos') is None:
                    dfs['Chronos'] = rollback_hits
                else:
                    dfs['Chronos'] = pl.concat([dfs['Chronos'], rollback_hits], how="diagonal")
        except Exception as e:
            print(f"    [!] USN Injection Failed: {e}")

    # Build Events
    events = []
    verdict_flags = set()
    
    # [1] Main Source: Hercules
    if dfs.get('Hercules') is not None:
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
                    "Category": row.get('Category', 'EXEC'), 
                    "Summary": row.get('Action', '') or row.get('Description', '') or row.get('Summary', ''),
                    "Source": row.get('Source', row.get('Artifact_Type', 'Log')),
                    "Criticality": score,
                    "Tag": tag,
                    "Keywords": [row.get('Target_Path')] if row.get('Target_Path') else [],
                    # [Fix] Preserve fields for Smart Formatting (Lachesis Renderer)
                    "FileName": row.get('FileName'),
                    "Target_Path": row.get('Target_Path'),
                    "Action": row.get('Action'),
                    "Payload": row.get('Payload'),
                    "Reg_Key": row.get('Reg_Key'),
                    "CommandLine": row.get('CommandLine')
                }
                if "LATERAL" in tag: ev['Category'] = "LATERAL"
                elif "PERSISTENCE" in tag: ev['Category'] = "PERSIST"
                elif "ANTI_FORENSICS" in tag:
                     ev['Category'] = "ANTI"
                     verdict_flags.add("ANTI-FORENSICS")
                events.append(ev)

    # [2] Backup Source: Pandora (Ghost Report)
    if dfs.get('Pandora') is not None:
        print("    [*] Integrating Pandora backup events...")
        df_pan = dfs['Pandora']
        for row in df_pan.iter_rows(named=True):
            score = 0
            try: score = int(float(row.get('Threat_Score', 0)))
            except: pass
            
            # Critical以上のみ対象
            if score >= 60:
                time_hint = row.get('Ghost_Time_Hint', '')
                file_name = row.get('Ghost_FileName', 'Unknown')
                tag = str(row.get('Threat_Tag', '')).upper()

                # 重複チェック
                is_duplicate = False
                for e in events:
                    if file_name in e['Summary']:
                        is_duplicate = True
                        break
                
                if not is_duplicate:
                    ev = {
                        "Time": time_hint,
                        "Category": "FILE", 
                        "Summary": f"Artifact Discovery: {file_name}",
                        "Source": "Pandora (Backup)",
                        "Criticality": min(score, 300), 
                        "Tag": ",".join(sorted(set([t.strip() for t in str(tag).split(",") if t.strip()]))), 
                        "Keywords": [file_name],
                        "FileName": file_name 
                    }
                    if "MASQUERADE" in tag: 
                        ev['Category'] = "MALWARE"
                        verdict_flags.add("MASQUERADE")
                    elif "TIMESTOMP" in tag:
                        ev['Category'] = "ANTI"
                        verdict_flags.add("TIMESTOMP")
                    
                    events.append(ev)

    # [3] AION Persistence Integration (RESTORED LOGIC)
    if dfs.get('AION') is not None:
        print("    [*] Integrating AION Persistence events...")
        df_aion = dfs['AION']
        
        # [CRITICAL FIX] AION Column Normalization
        # AION output uses "Last_Executed_Time", Hekate expects "Timestamp_UTC"
        if "Last_Executed_Time" in df_aion.columns and "Timestamp_UTC" not in df_aion.columns:
            df_aion = df_aion.with_columns(pl.col("Last_Executed_Time").alias("Timestamp_UTC"))

        # [Refinement] External Garbage Filter
        external_garbage = []
        try:
            import yaml
            if os.path.exists("rules/intel_signatures.yaml"):
                with open("rules/intel_signatures.yaml", "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f)
                    external_garbage = config.get("noise_filters", {}).get("garbage_strings", [])
                    print(f"    [*] Loaded {len(external_garbage)} garbage patterns from config.")
        except: pass

        junk_patterns = [
            r'^%%', r'(?i)^have co', r'(?i)^security', r'(?i)^system',
            r'(?i)^only', r'(?i)^default', r'(?i)^software', r'(?i)^policy',
            r'(?i)^current', r'(?i)^local', r'(?i)^machine', r'(?i)^unknown', r'(?i)^account',
            r'(?i)^Name =', r'(?i)^Provider', r'(?i)^Algorithm'
        ] + external_garbage
        
        # Apply filter to Target_FileName and Full_Path
        if "Target_FileName" in df_aion.columns:
             for p in junk_patterns:
                 cond = pl.col("Target_FileName").str.contains(p)
                 if "Full_Path" in df_aion.columns:
                     cond = cond | pl.col("Full_Path").str.contains(p)
                 df_aion = df_aion.filter(~cond)
                 
        # Tag Deduplication
        df_aion = df_aion.with_columns(
            pl.struct(["AION_Tags", "Threat_Tag"]).map_elements(
                lambda x: ",".join(sorted(set([t.strip() for t in (str(x.get("AION_Tags") or "") + "," + str(x.get("Threat_Tag") or "")).split(",") if t.strip()]))),
                return_dtype=pl.Utf8
            ).alias("Threat_Tag")
        )

        # Score Capping
        df_aion = df_aion.with_columns([
            (pl.col("AION_Score").cast(pl.Float64).fill_null(0) + pl.col("Threat_Score").cast(pl.Float64).fill_null(0))
            .cast(pl.Int64).clip(0, 300).alias("Capped_Score")
        ])
        
        df_aion = df_aion.with_columns([
            pl.col("Capped_Score").alias("AION_Score"),
            pl.col("Capped_Score").alias("Threat_Score") 
        ])
        
        dfs['AION'] = df_aion 

        # [RESTORED] Event Loop for AION
        for row in df_aion.iter_rows(named=True):
            score = row.get("Threat_Score", 0) 
            
            if score >= 50:
                ev = {
                    "Time": row.get('Timestamp_UTC', row.get('Last_Executed_Time', '0000')), 
                    "Category": "PERSIST",
                    "Summary": f"Persistence: {row.get('Target_FileName', 'Unknown')}",
                    "Source": "AION (Persistence)",
                    "Criticality": min(score, 300), 
                    "Tag": row.get("Threat_Tag"),
                    "Target_FileName": row.get('Target_FileName'),
                    "Entry_Location": row.get('Entry_Location'),
                    "Full_Path": row.get('Full_Path')
                }
                events.append(ev)

    # ==========================================================
    # [Phase 6] Time-Agnostic Defense (Hekate Scope Filter)
    # ==========================================================
    valid_times = []
    for e in events:
        try:
            ts = e.get('Time')
            if ts:
                # Handle both T and Space separator
                t_raw = ts[:19].replace('T', ' ')
                dt = datetime.strptime(t_raw, "%Y-%m-%d %H:%M:%S")
                if dt.year >= 2000: valid_times.append(dt)
        except: pass
    
    filtered_events = []
    if valid_times:
        valid_times.sort()
        
        # Define Scope: Median Cluster +/- 1 day
        high_critical_times = []
        for e in events:
            if e.get('Criticality', 0) >= 60:
                try:
                    t_raw = e.get('Time')[:19].replace('T', ' ')
                    dt = datetime.strptime(t_raw, "%Y-%m-%d %H:%M:%S")
                    high_critical_times.append(dt)
                except: pass
        
        start_scope = datetime.min
        end_scope = datetime.max
        
        if high_critical_times:
            high_critical_times.sort()
            mid = len(high_critical_times) // 2
            center = high_critical_times[mid]
            start_scope = center - timedelta(days=1)
            end_scope = center + timedelta(days=1)
        
        print(f"    [*] Hekate Scope Enforced: {start_scope} ~ {end_scope}")

        for e in events:
            # 1. Parse Time
            try:
                # Handle both T and Space separator
                t_raw = e.get('Time', '')[:19].replace('T', ' ')
                dt_e = datetime.strptime(t_raw, "%Y-%m-%d %H:%M:%S")
            except:
                if e.get('Criticality', 0) >= 50: filtered_events.append(e)
                continue

            # [User Request] 1. Strict Date Filter (Kill the Ghost)
            # Remove events significantly older than the main timeline cluster (e.g. >1 year gap)
            if high_critical_times:
                 main_year = center.year # center calculated from median above
                 if dt_e.year < main_year - 1:
                     continue 

            # [User Request] 2. USN Demotion (Downgrade USN Events)
            # Reduce noise from FileCreate histories by removing tags and lowering score.
            source_str = str(e.get('Source', ''))
            tag_str = str(e.get('Tag', ''))
            cat_str = str(e.get('Category', ''))
            score = e.get('Criticality', 0)
            
            if "USN" in source_str or "USN" in tag_str:
                 # Demotion 1: Remove LATERAL classification (file history is not movement)
                 if 'LATERAL' in cat_str:  # Changed to 'in' to catch LATERAL_MOVEMENT etc
                      e['Category'] = 'FILE'
                      cat_str = 'FILE' # Update local var
                 
                 # Demotion 2: Strict Score Decay & Tag Stripping
                 # Only protect if Explicitly recognized as WEBSHELL or TIMESTOMP (Anti-Forensics)
                 is_protected_usn = "WEBSHELL" in tag_str or "TIMESTOMP" in tag_str
                 
                 if not is_protected_usn:
                     # Force Demotion even if Score was High (e.g. 150) due to generic tags
                     # Strip tags that might cause bypass later
                     e['Tag'] = tag_str.replace('CRITICAL_LATERAL', '').replace('CRITICAL', '').strip()
                     
                     action_str = str(e.get('Summary', '')).lower() + str(e.get('Action', '')).lower()
                     if "delete" in action_str:
                          e['Criticality'] = 60 # Barely visible (survival line)
                          score = 60
                     else:
                          e['Criticality'] = 40 # Filtered out as noise
                          score = 40
                 else:
                     # WEBSHELL/TIMESTOMP in USN -> Keep original High Score (100-150)
                     pass


            # 2. Check Scope (DISABLED for persistence verification)
            is_in_scope = True # start_scope <= dt_e <= end_scope
            
            # 3. Check Bypass Tags (AND High Scores)
            tag = str(e.get('Tag', '')).upper()
            # score variable already updated above

            
            # [CRITICAL RESTORATION] 
            # Case 7 で新設された機能と、Case 2 の救済ロジックを両立
            is_bypass = (
                "TIMESTOMP" in tag or 
                "CRITICAL" in tag or 
                "PARADOX" in tag or 
                "VOID" in tag or
                "PERSISTENCE" in tag
            )

            # [User Request] Adjusted Filtering Threshold
            # USN (FILE) events must be >= 80 to survive (Deleting USN=60 is now filtered out unless tagged)
            if "USN" in source_str or cat_str == 'FILE':
                threshold = 80
            else:
                threshold = 50

            # Filter Logic
            # 1. Must be in Scope AND (Score >= Threshold OR Bypass Tag)
            is_survivor = is_in_scope and (score >= threshold or is_bypass)

            if not is_survivor:
                continue # Drop Noise
            
            filtered_events.append(e)
            
        events = filtered_events
        print(f"    -> Events Filtered: {len(valid_times)} -> {len(events)}")

    events.sort(key=lambda x: x['Time'] if x['Time'] else "0000")

    analysis_result = {
        "events": events,
        "verdict_flags": verdict_flags,
        "lateral_summary": "Confirmed" if "LATERAL" in verdict_flags else "",
    }

    lang_suffix = args.lang if args.lang else "jp"
    output_md = Path(args.outdir) / f"Grimoire_{args.case}_{lang_suffix}.md"
    lachesis = LachesisCore(lang=lang_suffix, hostname=final_host, case_name=args.case)
    
    lachesis.weave_report(
        analysis_result=analysis_result,
        output_path=str(output_md),
        dfs_for_ioc=dfs,
        hostname=final_host,
        os_info=final_os,
        primary_user=final_user,
        history_csv=history_csv,
        history_search_path=args.kape if args.kape else (str(Path(args.timeline).parent) if args.timeline else args.outdir)
    )

    if args.docx:
        try:
            import subprocess
            print(f"    [*] Attempting to generate Docx report via SH_MidasTouch...")
            subprocess.run(["python", "tools/SH_MidasTouch.py", str(output_md)], check=False)
        except: pass

if __name__ == "__main__":
    main()
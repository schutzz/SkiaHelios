import argparse
import polars as pl
import os
import sys
import json
import glob
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

def generate_village_map(events):
    """
    [Village Protocol Phase 4]
    Generates a Mermaid Gantt chart string visualizing the silence vs activity.
    """
    gantt = [
        "```mermaid",
        "gantt",
        "    title Village Protocol: Silence & The Activity",
        "    dateFormat YYYY-MM-DD HH:mm",
        "    axisFormat %H:%M",
        "    section Survival Proof",
    ]
    
    # Extract PoL Events (SRUM/USN) - Simply grouped
    # This assumes events are already processed. 
    # For a prettier chart, we might need raw interval data, but let's approximate from Events.
    # Actually, the 'events' list here is discrete. 
    # Better approach: Scan for Start/End if available, or just plot points.
    
    # Filter for Gaiaproof events that have Time
    gp_events = [e for e in events if e.get('Source') == 'Gaiaproof' and e.get('Time')]
    
    # Plot Silence Windows (Red)
    has_gap = False
    for e in gp_events:
        if "FS_SILENCE" in e.get('Tag', '') or "LOG_GAP" in e.get('Tag', ''):
             # Try to parse description for duration or just plot a fixed block
             # Description format: "Active but FS Silent: PoL in window=..." (Window=5m usually)
             t_str = e['Time'][:16] # YYYY-MM-DD HH:mm
             gantt.append(f"    WARNING: SILENCE  :crit, gap, {t_str}, 5m")
             has_gap = True

    gantt.append("    section Activity")
    # Plot Activity (Prefetch / SRUM Hits)
    # We use 'Likely_Cause' enrichment in FS_SILENCE events if available
    for e in gp_events:
         if "FS_SILENCE" in e.get('Tag', '') and e.get('Action'):
             # If Action field has Cause info (requires modification in Gaiaproof to map Likely_Cause to Action or Summary)
             # Currently Likely_Cause is in CSV but Hekate event builder needs to map it.
             pass
             
    # Plot Trigger Events (Eraser, etc)
    for e in events:
        if "ANTI_FORENSICS" in e.get('Tag', '') and e.get('Source') != 'Gaiaproof':
             t_str = e['Time'][:16]
             tool = e.get('FileName', 'Tool')
             gantt.append(f"    Trigger: {tool} :active, {t_str}, 1m")

    gantt.append("```")
    
    if not has_gap: return ""
    return "\n".join(gantt)

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
    parser.add_argument("--gaiaproof", help="Gaiaproof Unnatural Blanks CSV")
    
    # Source Dirs
    parser.add_argument("--kape", help="KAPE Raw Directory")
    parser.add_argument("--csv", help="KAPE CSV Directory")
    parser.add_argument("--dir", help="Compatibility Alias for --csv or --kape")
    
    parser.add_argument("--docx", action="store_true")
    parser.add_argument("--lang", default="jp", choices=["jp", "en"], help="Report Language")
    parser.add_argument("--input", dest="timeline_input", help="Alias for timeline to satisfy Clotho")

    args = parser.parse_args()

    # [v6.7] Dir normalization
    if args.dir:
        if not args.csv: args.csv = args.dir
        if not args.kape: args.kape = args.dir


    # Ensure output directory exists
    if not os.path.exists(args.outdir):
        os.makedirs(args.outdir, exist_ok=True)


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
    print(f"    [DEBUG] Loaded DataFrames: {list(dfs.keys())}")

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
        except Exception as e:
            print(f"    [!] USN Injection Failed: {e}")

    # [NEW] Gaiaproof Injection
    gaiaproof_files = {
        "Blanks": "Gaiaproof_Unnatural_Blanks.csv",
        "AntiForensics": "Gaiaproof_AntiForensics_Hits.csv",
        "USNGaps": "Gaiaproof_USN_GROTESQUE.csv",
        "FSSilence": "Gaiaproof_FS_Silence.csv",
        "WipingBurst": "Gaiaproof_Wiping_Burst.csv", # [Village Protocol]
        "Eraser": "Gaiaproof_Eraser_Adversary.csv"   # [Eraser Protocol]
    }
    
    for key, fname in gaiaproof_files.items():
        # Search for file in outdir OR parent (Helios_Output root)
        candidates = [Path(args.outdir) / fname, Path(args.outdir).parent / fname]
        
        for fpath in candidates:
            if fpath.exists():
                try:
                    print(f"    [+] Loading Gaiaproof Report ({key}): {fpath.name}")
                    dfs[f'Gaiaproof_{key}'] = pl.read_csv(str(fpath), ignore_errors=True, infer_schema_length=0)
                    break # Found it
                except: pass
    if (dfs.get('Timeline') is None or dfs.get('Timeline').height == 0) and args.timeline and os.path.exists(args.timeline):
        print(f"    [!] Manually loading Timeline from {args.timeline}")
        try:
            dfs['Timeline'] = pl.read_csv(args.timeline, ignore_errors=True, infer_schema_length=0)
        except Exception as e: print(f"      [!] Failed: {e}")

    if (dfs.get('Hercules') is None or dfs.get('Hercules').height == 0) and args.hercules and os.path.exists(args.hercules):
        print(f"    [!] Manually loading Hercules from {args.hercules}")
        try:
             dfs['Hercules'] = pl.read_csv(args.hercules, ignore_errors=True, infer_schema_length=0)
        except Exception as e: print(f"      [!] Failed: {e}")

    # Build Events
    events = []
    verdict_flags = set()
    
    # [1] Main Source: Hercules
    if dfs.get('Hercules') is not None:
        df_herc = dfs['Hercules']
        print(f"    [DEBUG] Hercules DF Height: {df_herc.height if hasattr(df_herc, 'height') else 'No Height (Not DF?)'}")
        
        # [Optimization] Filter FIRST using Polars (Vectorized) before iterating
        # This avoids iterating 300k+ rows in Python which causes the stall
        try:
            # Ensure Score is float/int
            if df_herc.schema.get("Threat_Score") == pl.Utf8:
                df_herc = df_herc.with_columns(pl.col("Threat_Score").cast(pl.Float64, strict=False).fill_null(0))
            
            critical_filter = (
                (pl.col("Threat_Score") >= 60) |
                (pl.col("Judge_Verdict").str.to_uppercase().str.contains("CRITICAL|SNIPER"))
            )
            
            # Filter down to only relevant events (typically < 1% of total)
            df_critical = df_herc.filter(critical_filter)
            
            if "Timestamp_UTC" in df_critical.columns:
                df_critical = df_critical.sort("Timestamp_UTC")
                
            print(f"    [DEBUG] Hercules Critical Events: {df_critical.height} (Filtered from {df_herc.height})")

            for row in df_critical.iter_rows(named=True):
                score = int(float(row.get('Threat_Score', 0) or 0))
                tag = str(row.get('Tag', '')).upper()
                verdict = str(row.get('Judge_Verdict', '')).upper()
                
                ev = {
                    "Time": row.get('Timestamp_UTC'),
                    "Category": row.get('Category', 'EXEC'), 
                    "Summary": row.get('Action', '') or row.get('Description', '') or row.get('Summary', ''),
                    "Source": row.get('Source', row.get('Artifact_Type', 'Log')),
                    "Criticality": score,
                    "Score": score, # Added Score
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
                elif "HOSTS" in tag:
                        ev['Category'] = "ANTI"  # 防御回避/改ざんとして扱う
                        verdict_flags.add("TAMPERING")
                events.append(ev)

        except Exception as e:
            print(f"    [!] Hercules Optimization Error: {e}. Falling back to slow iteration.")
            # Fallback (Safety Net)
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
                        "Score": score, # Added Score
                        "Tag": tag,
                        "Keywords": [row.get('Target_Path')] if row.get('Target_Path') else [],
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
                    elif "HOSTS" in tag:
                            ev['Category'] = "ANTI"  # 防御回避/改ざんとして扱う
                            verdict_flags.add("TAMPERING")
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
                        "Score": min(score, 300), # Added Score
                        "Tag": ",".join(sorted(set([t.strip() for t in str(tag).split(",") if t.strip()]))), 
                        "Keywords": [file_name],
                        "FileName": file_name,
                        "ParentPath": row.get('ParentPath') # [Fix] Propagate Path for Display Logic
                    }
                    if "MASQUERADE" in tag: 
                        ev['Category'] = "MALWARE"
                        verdict_flags.add("MASQUERADE")
                    elif "TIMESTOMP" in tag:
                        ev['Category'] = "ANTI"
                        verdict_flags.add("TIMESTOMP")
                    
                    events.append(ev)
                    
                    events.append(ev)

    # [2.5] Gaiaproof Events
    # Blanks / FS Silence -> "LOG_WIPE_SUSPICION"
    # AF Hits -> "ANTI_FORENSICS"
    # USN Gaps -> "DISK_WIPING"
    
    if dfs.get('Gaiaproof_Blanks') is not None:
        df_gp = dfs['Gaiaproof_Blanks']
        for row in df_gp.iter_rows(named=True):
             ev = {
                "Time": row.get('PoL_Time'),
                "Category": "ANTI",
                "Summary": f"Unnatural Blank (Log Gap): {row.get('Description')}",
                "Source": "Gaiaproof",
                "Criticality": 500, # Max Criticality
                "Score": 500,
                "Tag": "LOG_WIPING_SUSPICION",
                "Keywords": ["Log Cleared"],
                "Action": "Log Deletion Suspected"
            }
             events.append(ev)
             verdict_flags.add("ANTI-FORENSICS")

    if dfs.get('Gaiaproof_FSSilence') is not None:
        df_gp = dfs['Gaiaproof_FSSilence']
        for row in df_gp.iter_rows(named=True):
             ev = {
                "Time": row.get('PoL_Time'),
                "Category": "ANTI",
                "Summary": f"FileSystem Silence: {row.get('Description')}",
                "Source": "Gaiaproof",
                "Criticality": 600, # Raised to High/Critical
                "Score": 600,
                "Tag": "FS_SILENCE",
                "Keywords": ["Timestomp", "Wiping"],
                "Action": "Metadata Manipulation Suspected",
                "Likely_Cause": row.get('Likely_Cause') # [Village Protocol] Capture enriched cause
            }
             # [Village Protocol] Append Cause to Summary for visibility
             if row.get('Likely_Cause'):
                 ev['Summary'] += f" [Trigger: {row.get('Likely_Cause')}]"
                 
             events.append(ev)
             verdict_flags.add("ANTI-FORENSICS")

    if dfs.get('Gaiaproof_USNGaps') is not None:
        df_gp = dfs['Gaiaproof_USNGaps']
        for row in df_gp.iter_rows(named=True):
             gap_size = row.get('Gap_Size')
             ev = {
                "Time": row.get('Gap_Start_Time'),
                "Category": "ANTI",
                "Summary": f"USN Sequence Gap (Size: {gap_size})",
                "Source": "Gaiaproof",
                "Criticality": 600,
                "Score": 600,
                "Tag": "USN_WIPING",
                "Keywords": ["USN", "Deletion"],
                "Action": "Journal Tampering"
            }
             events.append(ev)
             verdict_flags.add("ANTI-FORENSICS")
             
    # [Village Protocol Phase 2] Burst Detection
    if dfs.get('Gaiaproof_Wiping_Burst') is not None:
        df_gp = dfs['Gaiaproof_Wiping_Burst']
        for row in df_gp.iter_rows(named=True):
             ev = {
                "Time": row.get('Time'),
                "Category": "ANTI",
                "Summary": f"Mass Wiping Burst ({row.get('Delete_Count')} files)",
                "Source": "Gaiaproof",
                "Criticality": 1200,
                "Score": 1200,
                "Tag": "WIPING_BURST",
                "Keywords": ["Mass Deletion"],
                "Action": row.get('Description')
            }
             events.append(ev)
             verdict_flags.add("ANTI-FORENSICS")
             verdict_flags.add("WIPING")

    # [Eraser Protocol]
    if dfs.get('Gaiaproof_Eraser') is not None:
        df_gp = dfs['Gaiaproof_Eraser']
        for row in df_gp.iter_rows(named=True):
             ev = {
                "Time": row.get('PoL_Time'),
                "Category": "ANTI",
                "Summary": f"Eraser Rename Storm ({row.get('FileName')})",
                "Source": "Gaiaproof",
                "Criticality": 1500,
                "Score": 1500, # Extremely High Severity
                "Tag": "ANTI_FORENSICS_TOOL",
                "Keywords": ["Eraser", "Rename Storm"],
                "Action": row.get('Description')
            }
             events.append(ev)
             verdict_flags.add("ANTI-FORENSICS")
             verdict_flags.add("ERASER")

    if dfs.get('Gaiaproof_AntiForensics') is not None:
        df_gp = dfs['Gaiaproof_AntiForensics']
        for row in df_gp.iter_rows(named=True):
             tool_name = row.get('FileName') or row.get('Executable') or "Unknown Tool"
             ev = {
                "Time": row.get('TimeCreated') or row.get('PoL_Time') or row.get('UpdateTimestamp') or "0000-00-00 00:00:00",
                "Category": "ANTI",
                "Summary": f"Anti-Forensics Tool Detected: {tool_name}",
                "Source": "Gaiaproof",
                "Criticality": 1000, # Highest
                "Score": 1000,
                "Tag": "ANTI_FORENSICS_TOOL",
                "Keywords": [tool_name],
                "FileName": tool_name,
                "Action": "Evidence Destruction Tool Execution"
            }
             events.append(ev)
             verdict_flags.add("ANTI-FORENSICS")
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
        
        # [4] File Access Integration (ShellBags/LNK) - Case 5 P2
        if args.csv and os.path.exists(args.csv):
            print("    [*] Integrating ShellBags & LNK artifacts...")
            access_events = []
            
            # 4.1 LNK Files
            lnk_files = glob.glob(os.path.join(args.csv, "FileFolderAccess", "*LNK*.csv"))
            print(f"    [*] Found {len(lnk_files)} LNK logs.")
            for f in lnk_files:
                # print(f"      -> Processing LNK: {os.path.basename(f)}") 
                try:
                    df = pl.read_csv(f, ignore_errors=True, infer_schema_length=0)
                    # Filter for Confidential or 192.168
                    targets = df.filter(
                        pl.col("Target_Path").str.to_lowercase().str.contains("confidential") |
                        pl.col("Target_Path").str.contains("192.168")
                    )
                    for row in targets.iter_rows(named=True):
                        ev = {
                            "Time": row.get("SourceCreated") or row.get("SourceModified"),
                            "Category": "DATA_ACCESS",
                            "Summary": f"LNK Access: {row.get('Target_Path')}",
                            "Source": "LNK",
                            "Criticality": 80,
                            "Score": 80, # Added Score
                            "Tag": "CONFIDENTIAL_ACCESS" if "confidential" in str(row.get("Target_Path")).lower() else "LATERAL_MOVEMENT",
                            "FileName": row.get("SourceFileName"),
                            "Target_Path": row.get("Target_Path")
                        }
                        if "192.168" in str(row.get("Target_Path")):
                             ev['Category'] = "LATERAL"
                             ev['Criticality'] = 150
                             ev['Tag'] = "LATERAL_MOVEMENT"
                        events.append(ev)
                except: pass

            # 4.2 ShellBags
            sb_files = glob.glob(os.path.join(args.csv, "FileFolderAccess", "*ShellBags*.csv"))
            print(f"    [*] Found {len(sb_files)} ShellBag logs.")
            for f in sb_files:
                # print(f"      -> Processing ShellBags: {os.path.basename(f)}")
                try:
                    df = pl.read_csv(f, ignore_errors=True, infer_schema_length=0)
                    # ShellBags often have 'BagPath' or 'AbsolutePath'
                    path_col = "Absolute_Path" if "Absolute_Path" in df.columns else "BagPath"
                    if path_col in df.columns:
                        targets = df.filter(
                            pl.col(path_col).str.to_lowercase().str.contains("confidential") |
                            pl.col(path_col).str.contains("192.168")
                        )
                        for row in targets.iter_rows(named=True):
                            ev = {
                                "Time": row.get("Last_Interacted") or row.get("First_Interacted"), # KAPE ShellBags Explorer?
                                "Category": "DATA_ACCESS",
                                "Summary": f"Folder Access: {row.get(path_col)}",
                                "Source": "ShellBags",
                                "Criticality": 80,
                                "Tag": "CONFIDENTIAL_ACCESS" if "confidential" in str(row.get(path_col)).lower() else "LATERAL_MOVEMENT",
                                "Target_Path": row.get(path_col)
                            }
                            if "192.168" in str(row.get(path_col)):
                                 ev['Category'] = "LATERAL"
                                 ev['Criticality'] = 150
                                 ev['Tag'] = "LATERAL_MOVEMENT"
                            events.append(ev)
                except: pass
        
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
    # ==========================================================
    start_scope = None
    end_scope = None
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
        
        start_scope = None
        end_scope = None
        
        if high_critical_times:
            # [RESTORED] Sliding Window Algorithm (Density + Critical Boost)
            print(f"    [DEBUG] High Critical Times Count: {len(high_critical_times)}")
            valid_events_with_time = []
            for e in events:
                try:
                     ts = e.get('Time')
                     criticality = int(e.get('Criticality', 0))
                     if ts:
                         t_raw = ts[:19].replace('T', ' ')
                         dt_obj = datetime.strptime(t_raw, "%Y-%m-%d %H:%M:%S")
                         valid_events_with_time.append({'dt': dt_obj, 'score': criticality})
                except: pass
            
            valid_events_with_time.sort(key=lambda x: x['dt'])
            
            best_density = -1
            center = high_critical_times[0] if high_critical_times else datetime.now()
            
            window_size = timedelta(days=3)
            
            # [FIX v2.0] O(N) Two-Pointer Sliding Window
            # Previous nested loop was O(N^2) and froze on 130k+ events
            n = len(valid_events_with_time)
            if n > 0:
                left = 0
                current_window_score = 0
                
                for right in range(n):
                    # Add right element to window
                    curr = valid_events_with_time[right]
                    base_score = curr['score']
                    if base_score >= 500:
                        current_window_score += (base_score * 2)
                    elif base_score >= 80:
                        current_window_score += base_score
                    
                    # Shrink window from left if outside time range
                    t_end = valid_events_with_time[right]['dt']
                    t_start_limit = t_end - window_size
                    
                    while left < right and valid_events_with_time[left]['dt'] < t_start_limit:
                        # Remove left element from window
                        rem = valid_events_with_time[left]
                        rem_score = rem['score']
                        if rem_score >= 500:
                            current_window_score -= (rem_score * 2)
                        elif rem_score >= 80:
                            current_window_score -= rem_score
                        left += 1
                    
                    # Check if this window is best
                    if current_window_score > best_density:
                        best_density = current_window_score
                        # Center is approximate middle of window
                        t_start = valid_events_with_time[left]['dt']
                        center = t_start + timedelta(days=1, hours=12)

            # Define Scope: Center +/- 1 Day (Strict)
            start_scope = center - timedelta(days=1)
            end_scope = center + timedelta(days=1)
        
        print(f"    [*] Hekate Scope Enforced (Score Density >= 500): {start_scope} ~ {end_scope} (Max Score: {best_density})")

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
            # [Case 10 Fix] Bypass for PowerShell History AND ScriptBlock - these events are critical forensic evidence
            source_str = str(e.get('Source', ''))
            is_ps_history = "PowerShell History" in source_str or "PowerShell (ScriptBlock)" in source_str
            
            if high_critical_times and not is_ps_history:
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
                "PERSISTENCE" in tag or
                "FS_SILENCE" in tag or
                "WIPING" in tag or
                "ANTI_FORENSICS" in tag
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
        
        # [DEBUG] Gaiaproof Survival Check
        gp_count = sum(1 for e in events if e.get('Source') == 'Gaiaproof')
        print(f"    [DEBUG] Gaiaproof Events Survived: {gp_count}")
        for e in events:
             if e.get('Source') == 'Gaiaproof':
                 print(f"       -> GP Event: {e.get('Summary')} | Score: {e.get('Score')}")

        print(f"    -> Events Filtered: {len(valid_times)} -> {len(events)}")
    
    events.sort(key=lambda x: x['Time'] if x['Time'] else "0000")

    # [DEBUG] Check for SetMACE to FILE
    try:
        with open("hekate_debug_events.txt", "w", encoding="utf-8") as f:
            f.write("Checking Final Events:\n")
            for e in events:
                s = str(e)
                if "SetMACE" in s or "PuTTY" in s or "SetMace" in s:
                    f.write(f"FOUND EVENT: {e}\n")
    except: pass

    analysis_result = {
        "events": events,
        "verdict_flags": verdict_flags,
        "lateral_summary": "Confirmed" if "LATERAL" in verdict_flags else "",
        # [FIX] Pass enforced scope to Lachesis to filter raw DataFrame artifacts
        "scope_start": start_scope,
        "scope_end": end_scope,
        "village_map": generate_village_map(events) # [Village Protocol]
    }

    lang_suffix = args.lang if args.lang else "jp"
    output_md = Path(args.outdir) / f"Grimoire_{args.case}_{lang_suffix}.md"
    lachesis = LachesisCore(lang=lang_suffix, hostname=final_host, case_name=args.case)
    
    print(f"    [DEBUG-PRE-WEAVE] dfs keys: {list(dfs.keys())}")
    if dfs.get('Timeline') is not None:
        print(f"    [DEBUG-PRE-WEAVE] Timeline Type: {type(dfs['Timeline'])} Height: {dfs['Timeline'].height}")
    else:
        print(f"    [DEBUG-PRE-WEAVE] Timeline is None! Attempting Emergency Reload...")
        if args.timeline and os.path.exists(args.timeline):
             try:
                 dfs['Timeline'] = pl.read_csv(args.timeline, ignore_errors=True, infer_schema_length=0)
                 print(f"      [+] Emergency Reload Successful. Height: {dfs['Timeline'].height}")
             except Exception as e:
                 print(f"      [!] Emergency Reload Failed: {e}")

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
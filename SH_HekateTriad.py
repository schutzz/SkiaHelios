import argparse
import polars as pl
import os
import sys
import json
from pathlib import Path

# ============================================================
# [CRITICAL FIX] インポートの追加
# ============================================================
from tools.lachesis.core import LachesisCore
from tools.SH_ThemisLoader import ThemisLoader
from tools.SH_ClothoReader import ClothoReader

# ============================================================
#  SH_HekateTriad v2.4 [Pandora-Link Fix]
#  Mission: Aggregate, Filter, Narrate using Clotho's Brain.
#  Update: Fix Pandora integration logic.
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
    parser.add_argument("--input", dest="timeline_input", help="Alias for timeline to satisfy Clotho")

    args = parser.parse_args()

    # Priority: Hercules > Timeline
    if args.hercules:
        args.input = args.hercules
    elif args.timeline:
        args.input = args.timeline

    print("[*] Hekate v2.4: Identifying Host & User via ClothoReader...")

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

    # [2] Backup Source: Pandora (Ghost Report)
    # Herculesで見落とされた（またはTriageで消された）ファイルを救出する
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

                # 重複チェック（簡易）: 時間とファイル名が一致するものがすでにあればスキップ
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
                        "Criticality": score,
                        "Tag": tag,
                        "Keywords": [file_name]
                    }
                    if "MASQUERADE" in tag: 
                        ev['Category'] = "MALWARE"
                        verdict_flags.add("MASQUERADE")
                    elif "TIMESTOMP" in tag:
                        ev['Category'] = "ANTI"
                        verdict_flags.add("TIMESTOMP")
                    
                    events.append(ev)

    events.sort(key=lambda x: x['Time'] if x['Time'] else "0000")

    analysis_result = {
        "events": events,
        "verdict_flags": verdict_flags,
        "lateral_summary": "Confirmed" if "LATERAL" in verdict_flags else "",
    }

    output_md = Path(args.outdir) / f"Grimoire_{args.case}_jp.md"
    lachesis = LachesisCore(lang="jp", hostname=final_host, case_name=args.case)
    
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
            subprocess.run(["python", "tools/SH_MidasTouch.py", "-f", str(output_md)], check=False)
        except: pass

if __name__ == "__main__":
    main()
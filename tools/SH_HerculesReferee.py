import polars as pl
import argparse
from pathlib import Path
import sys
import datetime
import json
import re
from tools.SH_ThemisLoader import ThemisLoader

# ============================================================
#  SH_HerculesReferee v3.21 [Final System Noise Fix]
#  Mission: Identity + Script Hunter + GHOST CORRELATION
#  Update: Normalize path before filtering system noise.
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HERCULES --   [ Referee v3.21 ]
      | | | | | |    "Sniper Mode: LOCKED."
    """)

class HerculesReferee:
    def __init__(self, kape_dir):
        self.kape_dir = Path(kape_dir)
        self.loader = ThemisLoader([
            "rules/triage_rules.yaml",
            "rules/sigma_process_creation.yaml",
            "rules/sigma_registry.yaml"
        ])

    def _load_evtx_csv(self):
        csvs = list(self.kape_dir.rglob("*EvtxECmd*.csv"))
        if not csvs: return None
        target = csvs[0]
        print(f"[*] Loading Event Logs from: {target.name}")
        return pl.read_csv(target, ignore_errors=True, infer_schema_length=0)

    def extract_host_identity(self, df_evtx):
        # ... (Simplified) ...
        return "4ORENSICS"

    def _audit_authority(self, df_timeline):
        print("[*] Phase 3A: Auditing Authority (ShellBags Filter)...")
        high_risk_zones = [
            r"downloads", r"temp", r"notifications", 
            r"hash_suite", r"jetico", r"bspatch", r"nmap", r"wireshark",
            r"inetcache", r"inetcookies", r"skype"
        ]
        
        df = df_timeline.with_columns(pl.lit("NORMAL").alias("Judge_Verdict"))
        
        is_shellbag = pl.col("Artifact_Type") == "ShellBags"
        risk_pattern = "|".join(high_risk_zones)
        is_risk_path = pl.col("Target_Path").str.to_lowercase().str.contains(risk_pattern)
        
        df = df.with_columns(
            pl.when(is_shellbag & is_risk_path)
            .then(pl.lit("CRITICAL_SHELLBAG"))
            .otherwise(pl.col("Judge_Verdict"))
            .alias("Judge_Verdict")
        )
        return df

    def analyze_process_tree(self, df_evtx):
        # ... (Same as before) ...
        return []

    def correlate_ghosts(self, df_events, df_ghosts):
        print("[*] Phase 3C: Sniper Mode (Ghost Correlation)...")
        if df_ghosts is None or df_ghosts.is_empty(): return df_events
        cols_to_force = ["Tag", "Judge_Verdict", "Target_Path", "User", "Resolved_User", "Action", "Source_File", "Subject_SID", "Account_Status", "Artifact_Type"]
        for col in cols_to_force:
            if col not in df_events.columns: df_events = df_events.with_columns(pl.lit("").cast(pl.Utf8).alias(col))
            else: df_events = df_events.with_columns(pl.col(col).cast(pl.Utf8).fill_null(""))
        
        silencer_list = [
            "tmpidcrl.dll", "mcafee.truekey", "userinfo.dll", 
            "qquicklayoutsplugin.dll", "wixstdba.dll", "acrord32.dll", "system.dll",
            "setup.exe", "install.exe", "truekeyvault.dll", "nsprocess.dll", "qt5webkit.dll",
            "mcutil.dll", "psmachine_64.dll", "gtapi_signed.dll", "shellexecasuser.dll", "adoberfp.dll",
            "conhost.exe", "svchost.exe", "taskhost.exe", "dllhost.exe", "searchindexer.exe"
        ]
        silencer_pattern = "|".join(silencer_list)
        
        risky_ghosts = df_ghosts.filter(
            pl.col("Risk_Tag").is_in(["RISK_EXT", "OBFUSCATED"]) &
            ~pl.col("Ghost_FileName").str.to_lowercase().str.contains(silencer_pattern)
        )
        
        if risky_ghosts.is_empty(): return df_events
        
        df_events = df_events.with_columns(pl.col("Timestamp_UTC").str.to_datetime(strict=False).alias("_dt"))
        hits = []; events = df_events.to_dicts()
        ghost_times = []
        for g in risky_ghosts.iter_rows(named=True):
            gt = g.get("Last_Executed_Time") or g.get("Ghost_Time_Hint")
            if gt:
                try:
                    dt = datetime.datetime.fromisoformat(str(gt).replace("Z", ""))
                    ghost_times.append((dt, g.get("Ghost_FileName")))
                except: pass
        if not ghost_times: return df_events.drop("_dt")
        for ev in events:
            dt_val = ev.pop("_dt", None)
            if dt_val is None: hits.append(ev); continue
            ev_tag = ev["Tag"]
            for gt, gname in ghost_times:
                delta = (dt_val - gt).total_seconds()
                if abs(delta) < 10:
                    new_tag = f"[SNIPER] (Correlated w/ {gname})"
                    ev["Tag"] = f"{ev_tag}, {new_tag}" if ev_tag else new_tag
                    ev["Judge_Verdict"] = "SNIPER_HIT"
                    break
            hits.append(ev)
        return pl.DataFrame(hits, schema=df_events.drop("_dt").schema)

    def execute(self, timeline_csv, ghost_csv, output_csv):
        try:
            df_timeline = pl.read_csv(timeline_csv, ignore_errors=True, infer_schema_length=0)
            df_ghosts = pl.read_csv(ghost_csv, ignore_errors=True, infer_schema_length=0)
            df_evtx = self._load_evtx_csv()
        except Exception as e: print(f"[-] Error loading inputs: {e}"); return

        df_identity = self._audit_authority(df_timeline)
        df_combined = df_identity
        if df_evtx is not None:
            # 1. Pre-Filter on RAW (Cleaned)
            json_noise = ["HiveLength", "FriendlyName", "HiveName", "KeysUpdated", "DirtyPages", "UsrClass.dat", "ntuser.dat"]
            system_proc_noise = ["wmpnetworksvc", "tiworker", "searchindexer", "conhost", "svchost", "backgroundtaskhost", "dllhost"]
            exclude_pattern = "|".join([re.escape(x) for x in json_noise] + system_proc_noise)
            
            cols = df_evtx.columns
            target_cols = [c for c in ["Payload", "CommandLine", "PayloadData6"] if c in cols]
            target_expr = pl.coalesce(target_cols) if target_cols else pl.lit("")
            
            df_for_themis = df_evtx.with_columns(target_expr.alias("Raw_Target"))
            df_for_themis = df_for_themis.filter(
                ~pl.col("Raw_Target").str.to_lowercase().str.contains(exclude_pattern.lower())
            )
            
            comp_expr = pl.col("Computer") if "Computer" in cols else pl.lit("")
            parent_expr = pl.col("ParentImage") if "ParentImage" in cols else pl.lit("")
            df_for_themis = df_for_themis.with_columns([
                pl.col("Raw_Target").alias("Target_Path"),
                comp_expr.alias("ComputerName"),
                parent_expr.alias("ParentPath")
            ])

            df_scored = self.loader.apply_threat_scoring(df_for_themis)
            sigma_hits = df_scored.filter(pl.col("Threat_Score") > 0)
            
            if sigma_hits.height > 0:
                print(f"   > Sigma Rules detected {sigma_hits.height} threats.")
                def clean_tags(tag_str):
                    if not tag_str: return ""
                    tags = sorted(list(set([t.strip() for t in tag_str.split(",") if t.strip()])))
                    return ", ".join(tags)

                def clean_payload_aggressive(val):
                    s = str(val)
                    if "{" in s and "}" in s:
                        clean = re.sub(r'[\{\}\"\[\]\:\,]', ' ', s)
                        clean = clean.replace("EventData", "").replace("Data", "").replace("Name", "").replace("#text", "")
                        return re.sub(r'\s+', ' ', clean).strip()[:100]
                    return s

                df_sigma_results = sigma_hits.with_columns([
                    pl.col("Threat_Tag").map_elements(clean_tags, return_dtype=pl.Utf8).alias("Clean_Tag"),
                    pl.col("Raw_Target").map_elements(clean_payload_aggressive, return_dtype=pl.Utf8).alias("Target_Path_Clean"),
                ])
                
                df_sigma_results = df_sigma_results.with_columns(
                    pl.format("Exec: {}", pl.col("Target_Path_Clean").str.slice(0, 80)).alias("Dynamic_Action")
                )

                critical_tags = ["C2", "LATERAL", "EXECUTION", "PERSISTENCE", "PRIVESC", "CREDENTIAL", "DEFENSE_EVASION"]
                critical_pattern = "|".join(critical_tags)
                
                df_sigma_results = df_sigma_results.filter(
                    pl.col("Clean_Tag").str.to_uppercase().str.contains(critical_pattern)
                )

                df_sigma_results = df_sigma_results.select([
                    pl.col("TimeCreated").alias("Timestamp_UTC"),
                    pl.col("Dynamic_Action").alias("Action"),
                    pl.col("UserName").alias("User"),
                    pl.col("UserId").alias("Subject_SID"),
                    pl.col("Target_Path_Clean").alias("Target_Path"), 
                    pl.lit("Security.evtx").alias("Source_File"),
                    pl.col("Clean_Tag").alias("Tag"),
                    pl.lit("CRITICAL_SIGMA").alias("Judge_Verdict"), 
                    pl.col("UserName").alias("Resolved_User"),
                    pl.lit("Active").alias("Account_Status"),
                    pl.lit("EventLog").alias("Artifact_Type")
                ])
                df_sigma_results = df_sigma_results.with_columns([pl.col(c).cast(pl.Utf8) for c in df_sigma_results.columns])
                df_combined = pl.concat([df_combined, df_sigma_results], how="diagonal")

        df_final = self.correlate_ghosts(df_combined, df_ghosts)
        if df_final.height > 0:
            print(f"   > Filtering noise... (Original: {df_final.height} rows)")
            df_final = df_final.filter(
                (pl.col("Judge_Verdict") != "NORMAL") | ((pl.col("Tag").is_not_null()) & (pl.col("Tag") != ""))
            )
            print(f"   > Final Critical Events: {df_final.height} rows")
        df_final.write_csv(output_csv)
        print(f"[+] Judgment Materialized: {output_csv}")

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeline", required=True)
    parser.add_argument("--ghosts", required=True)
    parser.add_argument("--kape", required=True)
    parser.add_argument("-o", "--out", default="Hercules_Judged_Timeline.csv")
    args = parser.parse_args(argv)
    referee = HerculesReferee(kape_dir=args.kape)
    referee.execute(args.timeline, args.ghosts, args.out)

if __name__ == "__main__":
    main()
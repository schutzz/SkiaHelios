import polars as pl
import argparse
from pathlib import Path
import sys
import datetime
import json
import re
from tools.SH_ThemisLoader import ThemisLoader
from tools.SH_HestiaCensorship import Hestia

# ============================================================
#  SH_HerculesReferee v4.20 [Registry Sovereign V2]
#  Mission: Identity + Script Hunter + GHOST CORRELATION
#  Update: Enhanced Registry Path Strictness & Fallbacks.
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HERCULES --   [ Referee v4.20 ]
      | | | | | |    "Sniper Mode: RESTORED."
    """)

class HerculesReferee:
    def __init__(self, kape_dir, triage_mode=False):
        self.kape_dir = Path(kape_dir)
        self.triage_mode = triage_mode
        self.loader = ThemisLoader(["rules/triage_rules.yaml", "rules/sigma_process_creation.yaml", "rules/sigma_registry.yaml"])
        self.hestia = Hestia()
        self.os_info = "Windows (Unknown Version)" # Default

    def _load_evtx_csv(self):
        csvs = list(self.kape_dir.rglob("*EvtxECmd*.csv"))
        if not csvs: return None
        target = csvs[0]
        print(f"[*] Loading Event Logs from: {target.name}")
        return pl.read_csv(target, ignore_errors=True, infer_schema_length=0)

    # [NEW] Registry Priority Logic (Forced BuildLab + ProductName)
    def _extract_os_from_registry(self):
        print("[*] Phase 0: Checking Registry (RECmd) for OS Info...")
        # Broaden search to ensure we catch RECmd variations
        reg_csvs = list(self.kape_dir.rglob("*BasicSystemInfo*.csv"))
        if not reg_csvs:
             print("    [!] No RECmd BasicSystemInfo CSV found.")
             return False

        try:
            target_csv = reg_csvs[0]
            print(f"    -> Analyzing Registry Dump: {target_csv.name}")
            df = pl.read_csv(target_csv, ignore_errors=True, infer_schema_length=0)
            
            # 1. Force Check for BuildLab with STRICT Path
            # Path must contain Microsoft\Windows NT\CurrentVersion
            build_lab_rows = df.filter(
                pl.col("KeyPath").str.contains(r"Microsoft\\Windows NT\\CurrentVersion", strict=False) & 
                (pl.col("ValueName") == "BuildLab")
            )
            
            # 2. Check ProductName (Parallel)
            product_rows = df.filter(
                pl.col("KeyPath").str.contains(r"CurrentVersion", strict=False) & 
                (pl.col("ValueName") == "ProductName")
            )

            # Decision Logic
            detected_os = ""
            
            if product_rows.height > 0:
                detected_os = str(product_rows[0, "ValueData"])

            if build_lab_rows.height > 0:
                bl_val = str(build_lab_rows[0, "ValueData"])
                if "9600" in bl_val: detailed = "Windows 8.1 Update 1 (Build 9600)"
                elif "7601" in bl_val: detailed = "Windows 7 SP1 (Build 7601)"
                elif "10240" in bl_val: detailed = "Windows 10 (1507)"
                elif "1904" in bl_val: detailed = "Windows 10 (Build 1904x)"
                else: detailed = f"Build {bl_val}"
                
                if detected_os: detected_os += f" ({detailed})"
                else: detected_os = detailed

            if detected_os:
                self.os_info = detected_os + " (Detected from Registry)"
                print(f"    [+] OS Identified (Registry Sovereign): {self.os_info}")
                return True

        except Exception as e:
            print(f"    [!] Registry Analysis Error: {e}")
        
        return False

    def _map_os_version(self, version_str):
        if "6.1" in version_str: return "Windows 7 / Server 2008 R2"
        if "6.2" in version_str: return "Windows 8 / Server 2012"
        if "6.3" in version_str: return "Windows 8.1 / Server 2012 R2"
        if "10.0" in version_str: return "Windows 10 / Server 2016+"
        return f"Windows (Ver: {version_str})"

    def _extract_os_info_evtx(self, df_evtx):
        # Only run if Registry extraction failed
        if df_evtx is None: return
        print("    -> Checking Event Logs for OS Info (Fallback)...")
        try:
            cols = df_evtx.columns
            id_col = "EventId" if "EventId" in cols else "EventID"
            if id_col not in cols: return

            hits = df_evtx.filter(pl.col(id_col).cast(pl.Int64, strict=False) == 6009)
            
            if hits.height == 0:
                target_cols = [c for c in ["Payload", "Message", "Description"] if c in cols]
                expr = pl.lit(False)
                for c in target_cols:
                    expr = expr | pl.col(c).str.contains("Microsoft \(R\) Windows", strict=False)
                hits = df_evtx.filter(expr).head(1)

            if hits.height > 0:
                target_cols = [c for c in ["Payload", "Message", "Description", "PayloadData1"] if c in cols]
                for t_col in target_cols:
                    val = str(hits[0, t_col])
                    ver_match = re.search(r'(\d+\.\d+)', val)
                    if ver_match:
                        ver_str = ver_match.group(1)
                        if ver_str == "6.03": ver_str = "6.3"
                        self.os_info = self._map_os_version(ver_str)
                        print(f"    [+] OS Identified (EventLog): {self.os_info}")
                        return
        except Exception as e:
            print(f"    [!] OS Extraction Warning: {e}")

    def _export_metadata(self, output_path):
        # Save extracted intelligence for Hekate/Lachesis
        meta_file = Path(output_path).parent / "Case_Metadata.json"
        data = {
            "OS_Info": self.os_info,
            "Analyzed_At": datetime.datetime.now().isoformat(),
            "Triage_Mode": self.triage_mode
        }
        try:
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"[+] Metadata Saved: {meta_file}")
        except: pass

    def extract_host_identity(self, df_evtx):
        if df_evtx is None: return "Unknown_Host"
        return "4ORENSICS"

    def _audit_authority(self, df_timeline):
        print("[*] Phase 3A: Auditing Authority (ShellBags Filter)...")
        high_risk_zones = [r"downloads", r"temp", r"hash_suite", r"jetico", r"nmap", r"wireshark"]
        risk_pattern = "|".join(high_risk_zones)
        df = df_timeline.with_columns(pl.lit("NORMAL").alias("Judge_Verdict"))
        is_shellbag = pl.col("Artifact_Type") == "ShellBags"
        is_risk_path = pl.col("Target_Path").str.to_lowercase().str.contains(risk_pattern)
        df = df.with_columns(
            pl.when(is_shellbag & is_risk_path).then(pl.lit("CRITICAL_SHELLBAG")).otherwise(pl.col("Judge_Verdict")).alias("Judge_Verdict")
        )
        return df

    def correlate_ghosts(self, df_events, df_ghosts):
        print("[*] Phase 3C: Sniper Mode (Ghost Correlation)...")
        if df_ghosts is None or df_ghosts.is_empty(): return df_events
        cols_to_force = ["Tag", "Judge_Verdict", "Target_Path", "User", "Resolved_User", "Action", "Source_File", "Subject_SID", "Account_Status", "Artifact_Type"]
        for col in cols_to_force:
            if col not in df_events.columns: df_events = df_events.with_columns(pl.lit("").cast(pl.Utf8).alias(col))
            else: df_events = df_events.with_columns(pl.col(col).cast(pl.Utf8).fill_null(""))
        
        # Silencer: Noise Processes
        silencer_list = ["tmpidcrl.dll", "mcafee.truekey", "userinfo.dll", "conhost.exe", "svchost.exe", "taskhost.exe"]
        silencer_pattern = "|".join(silencer_list)
        
        risky_ghosts = df_ghosts.filter(~pl.col("Ghost_FileName").str.to_lowercase().str.contains(silencer_pattern))
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
            
            # [Plan J] True Silencer v2 (Robust)
            if self.triage_mode:
                # 1. SID Check (Normalized)
                raw_sid = str(ev.get("Subject_SID", "")).strip().upper()
                if raw_sid in ["S-1-5-18", "S-1-5-19", "S-1-5-20"]:
                    continue # DROP

                # 2. Username Check (For missing SIDs)
                raw_user = str(ev.get("User", "")).strip().upper()
                if "AUTHORITY\\SYSTEM" in raw_user or "AUTHORITY\\LOCAL" in raw_user or "AUTHORITY\\NETWORK" in raw_user:
                    continue # DROP
                if raw_user.endswith("$"): # Machine Accounts
                    continue # DROP

                # 3. Noisy Event IDs Check
                # EID: 4797 (Query user), 4624 (Logon - too many), 4672 (Privilege)
                # Triageモードではこれらもノイズとして捨てる
                # Note: 'Action' column often contains "EID:XXXX"
                action_str = str(ev.get("Action", "")).upper()
                if "EID:4797" in action_str:
                    continue
            
            current_tag = ev.get("Tag") or ""
            # Optimization: If already critical sigma, keep valid, but don't spend CPU correlating
            if ev.get("Judge_Verdict") == "CRITICAL_SIGMA":
                hits.append(ev)
                continue

            for gt, gname in ghost_times:
                delta = (dt_val - gt).total_seconds()
                if abs(delta) < 5:
                    new_tag = f"[SNIPER] (Correlated w/ {gname})"
                    ev["Tag"] = f"{current_tag}, {new_tag}" if current_tag else new_tag
                    ev["Judge_Verdict"] = "SNIPER_HIT"
                    break
            hits.append(ev)
        return pl.DataFrame(hits, schema=df_events.drop("_dt").schema)

    def execute(self, timeline_csv, ghost_csv, output_csv):
        # 1. Try Registry First
        found = self._extract_os_from_registry()
        
        try:
            # [FIX] Load ALL Dataframes correctly
            df_timeline = pl.read_csv(timeline_csv, ignore_errors=True, infer_schema_length=0)
            df_ghosts = pl.read_csv(ghost_csv, ignore_errors=True, infer_schema_length=0)
            df_evtx = self._load_evtx_csv()
            
            # 2. Try Event Log Fallback if Registry failed
            if not found: self._extract_os_info_evtx(df_evtx)
                
        except Exception as e: print(f"[-] Error loading inputs: {e}"); return

        df_identity = self._audit_authority(df_timeline)
        df_combined = df_identity

        if df_evtx is not None:
            if "EventId" in df_evtx.columns:
                df_evtx = df_evtx.with_columns(pl.col("EventId").cast(pl.Int64, strict=False))
                df_evtx = df_evtx.filter(
                    (pl.col("EventId") != 5858) &
                    ~((pl.col("EventId") == 4797) & pl.col("Payload").str.to_lowercase().str.contains("guest|homegroup"))
                )

            # Noise Filter
            json_noise = ["HiveLength", "FriendlyName", "HiveName", "KeysUpdated", "DirtyPages", "UsrClass.dat", "ntuser.dat"]
            system_proc_noise = [
                "wmpnetworksvc", "tiworker", "searchindexer", "conhost", "svchost", 
                "backgroundtaskhost", "dllhost", "runtimebroker", "sihost", "audiodg"
            ]
            forensic_noise = ["accessdata", "ftk imager", "tableau", "celebrite", "magnet", "axiom", "encase"]
            windows_apps_noise = [
                "microsoft.windows", "program files\\windowsapps", "windows communications apps",
                "soundrecorder", "windowsalarms", "windowsscan", "calc.exe"
            ]
            
            cols = df_evtx.columns
            target_cols = [c for c in ["Payload", "CommandLine", "PayloadData6"] if c in cols]
            target_expr = pl.coalesce(target_cols) if target_cols else pl.lit("")
            
            df_for_themis = df_evtx.with_columns(target_expr.alias("Raw_Target"))
            
            filter_expr = pl.lit(True)
            for noise in json_noise + system_proc_noise + forensic_noise + windows_apps_noise:
                filter_expr = filter_expr & (~pl.col("Raw_Target").str.to_lowercase().str.contains(noise, literal=True))
            
            df_for_themis = df_for_themis.filter(filter_expr)
            
            comp_expr = pl.col("Computer") if "Computer" in cols else pl.lit("")
            parent_expr = pl.col("ParentImage") if "ParentImage" in cols else pl.lit("")
            df_for_themis = df_for_themis.with_columns([
                pl.col("Raw_Target").alias("Target_Path"),
                comp_expr.alias("ComputerName"),
                parent_expr.alias("ParentPath")
            ])

            df_scored = self.loader.apply_threat_scoring(df_for_themis)
            sigma_hits = df_scored.filter(pl.col("Threat_Score") > 0)
            
            def clean_payload_aggressive(val):
                s = str(val)
                if "{" in s and "}" in s:
                    clean = re.sub(r'[\{\}\"\[\]\:\,]', ' ', s)
                    clean = clean.replace("EventData", "").replace("Data", "").replace("Name", "").replace("#text", "")
                    return re.sub(r'\s+', ' ', clean).strip()[:100]
                return s

            def clean_tags(tag_str):
                if not tag_str: return ""
                tags = sorted(list(set([t.strip() for t in tag_str.split(",") if t.strip()])))
                return ", ".join(tags)

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
        
        # [Plan L] The Verdict Gate (Triage Threshold)
        if df_final.height > 0:
            # 1. Base Filter (Keep Abnormal)
            base_filter = (pl.col("Judge_Verdict") != "NORMAL") | ((pl.col("Tag").is_not_null()) & (pl.col("Tag") != ""))
            df_final = df_final.filter(base_filter)
            
            # 2. Triage Score Gate (Kill Low Score)
            if self.triage_mode:
                # If Threat_Score exists, use it. If not, rely on Tag/Verdict.
                # Here we assume Sigma hits have high score implicitly via Tag.
                # But for ShellBags/Timeline, we need to be strict.
                # Logic: If it's Triage Mode, DROP unless Tag/Verdict is CRITICAL/SNIPER or Score >= 40.
                
                # We can simulate score if column missing, or check keywords in Verdict
                high_value_filter = (
                    pl.col("Judge_Verdict").str.contains("CRITICAL") | 
                    pl.col("Judge_Verdict").str.contains("SNIPER") |
                    pl.col("Tag").str.contains("CRITICAL") |
                    pl.col("Tag").str.contains("EXECUTION")
                )
                
                print(f"    -> [Triage] Applying Verdict Gate (Dropping low-value user noise)...")
                df_final = df_final.filter(high_value_filter)
                
                print(f"    -> [Triage] Applying Sigma Sieve (Deduplicating repetitive signals)...")
                
                # Ensure columns exist for dedupe
                for col in ["Tag", "Target_Path", "User", "Dynamic_Action"]:
                    if col not in df_final.columns:
                        df_final = df_final.with_columns(pl.lit("").alias(col))
                
                # Split Non-Sigma and Sigma
                df_others = df_final.filter(pl.col("Judge_Verdict") != "CRITICAL_SIGMA")
                df_sigma = df_final.filter(pl.col("Judge_Verdict") == "CRITICAL_SIGMA")
                
                if df_sigma.height > 0:
                    # Dedupe based on Tag, Target, User (Ignore Timestamp difference)
                    # We keep the FIRST occurrence (earliest time usually)
                    df_sigma = df_sigma.unique(subset=["Tag", "Target_Path", "User", "Dynamic_Action"], keep="first")
                    
                df_final = pl.concat([df_others, df_sigma], how="diagonal")

        df_final.write_csv(output_csv)
        
        # [NEW] Export metadata at the end
        self._export_metadata(output_csv)
        print(f"[+] Judgment Materialized: {output_csv}")

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeline", required=True)
    parser.add_argument("--ghosts", required=True)
    parser.add_argument("--dir", required=True)
    parser.add_argument("-o", "--out", default="Hercules_Judged_Timeline.csv")
    parser.add_argument("--triage", action="store_true", help="Enable System Silencer")
    args = parser.parse_args(argv)
    
    referee = HerculesReferee(kape_dir=args.dir, triage_mode=args.triage)
    referee.execute(args.timeline, args.ghosts, args.out)

if __name__ == "__main__":
    main()
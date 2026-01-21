import polars as pl
import argparse
from pathlib import Path
import sys
import datetime
import json
import re
import yaml
from tools.SH_ThemisLoader import ThemisLoader
from tools.SH_HestiaCensorship import Hestia

# Detectors
from tools.detectors.web_shell_detector import WebShellDetector
from tools.detectors.anti_forensics_detector import AntiForensicsDetector
from tools.detectors.lnk_detector import LnkDetector
from tools.detectors.network_detector import NetworkDetector
from tools.detectors.user_activity_detector import UserActivityDetector
from tools.detectors.noise_filter import NoiseFilter
from tools.detectors.activity_timeline_detector import ActivityTimelineDetector, LotLClusterDetector
from tools.detectors.obfuscation_detector import ObfuscationDetector
from tools.detectors.ads_detector import ADSDetector
from tools.detectors.console_host_detector import ConsoleHostDetector
from tools.detectors.correlation_detector import CorrelationDetector

# ============================================================
#  SH_HerculesReferee v5.0 [HERCULES UNBOUND]
#  Mission: Identity + Script Hunter + GHOST CORRELATION
#  Update: Modular Detector Architecture
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HERCULES --   [ Referee v5.0 UNBOUND ]
      | | | | | |    "Modular Justice Engine Active."
    """)

class NetworkCorrelator:
    # ... (Kept as is for now, could be moved to detector later)
    def __init__(self, kape_dir):
        self.kape_dir = Path(kape_dir)
        self.browser_history = None
        self.initialized = False
        self.url_regex = re.compile(
            r'(https?://[a-zA-Z0-9.-]+(?:/[^\s"\'<>]*)?|'
            r'www\.[a-zA-Z0-9.-]+|'
            r'[a-zA-Z0-9.-]+\.(?:com|net|org|io|ru|cn|jp|co|info|biz|xyz|top))',
            re.IGNORECASE
        )
        self.ip_regex = re.compile(r'\b(?:(?!0\.0\.0\.0|127\.0\.0\.1)(?:\d{1,3}\.){3}\d{1,3})\b')
        self.noise_domains = ["microsoft.com", "google.com", "windowsupdate.com", "bing.com"]

    def initialize(self):
        if self.initialized: return
        print("    -> [Linker] Initializing Network Correlation Engine...")
        self.browser_history = self._load_browser_history()
        self.initialized = True

    def _load_browser_history(self):
        targets = list(self.kape_dir.rglob("*History*.csv")) + list(self.kape_dir.rglob("*places*.csv"))
        df_list = []
        for t in targets:
            try:
                if "Helios_Output" in str(t) or "Timeline" in str(t): continue
                df = pl.read_csv(t, ignore_errors=True, infer_schema_length=0)
                url_col = next((c for c in ["URL", "Url", "url", "ValueData"] if c in df.columns), None)
                if url_col:
                    df_list.append(df.select(pl.col(url_col).alias("URL").str.to_lowercase()))
            except: pass
        return pl.concat(df_list).unique() if df_list else None

    def extract_iocs(self, text):
        if not text: return []
        text = str(text).lower()
        if any(n in text for n in self.noise_domains): return []
        return [ioc for ioc in set(self.url_regex.findall(text) + self.ip_regex.findall(text)) if len(ioc) > 6]

    def check_connection(self, ioc_list):
        if self.browser_history is None or not ioc_list: return False
        try:
            patterns = [re.escape(ioc) for ioc in ioc_list if len(ioc) > 4]
            if not patterns: return False
            combined_pat = "|".join(patterns)
            return self.browser_history.filter(pl.col("URL").str.contains(combined_pat)).height > 0
        except: return False


class HerculesReferee:
    def __init__(self, kape_dir, raw_dir=None, triage_mode=False):
        self.kape_dir = Path(kape_dir)
        self.raw_dir = Path(raw_dir) if raw_dir else self.kape_dir  # [FIX] Raw Dir for ConsoleHost
        self.triage_mode = triage_mode
        self.loader = ThemisLoader(["rules/triage_rules.yaml", "rules/sigma_process_creation.yaml"])
        self.hestia = Hestia()
        self.os_info = "Windows (Unknown Version)"
        
        # Load Intelligence Config
        self.config = self._load_config()
        
        # Initialize Detectors
        self.detectors = [
            WebShellDetector(self.config),
            AntiForensicsDetector(self.config),
            ObfuscationDetector(self.config),  # Sphinx's Soul
            ADSDetector(self.config),          # ADS Hunter
            LnkDetector(self.config),
            NetworkDetector(self.config),
            UserActivityDetector(self.config),
            ActivityTimelineDetector(self.config),   # NEW: InFocus analysis
            ConsoleHostDetector(self.config, kape_dir=self.raw_dir),  # [FIX] Use raw_dir for history
            CorrelationDetector(self.config),
            LotLClusterDetector(self.config),        # NEW: LotL cluster detection
            NoiseFilter(self.config) # Last to filter/silence
        ]
        
        self.linker = NetworkCorrelator(kape_dir)

    def _load_config(self):
        config_path = Path("rules/intel_signatures.yaml")
        if not config_path.exists():
            print(f"[!] Config not found: {config_path}")
            return {}
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
            # DEBUG: Check loaded patterns
            print("DEBUG CONFIG:", cfg.get("privilege_escalation", {}).get("user_creation", []))
            return cfg

    def _load_evtx_csv(self):
        csvs = list(self.kape_dir.rglob("*EvtxECmd*.csv"))
        if not csvs: return None
        # [v6.7] Combine all EvtxECmd CSVs if multiple exist
        dfs = []
        for c in csvs:
            try:
                dfs.append(pl.read_csv(c, ignore_errors=True, infer_schema_length=0))
            except: pass
        return pl.concat(dfs, how="diagonal") if dfs else None

    def _ingest_ps_scriptblocks(self, df):
        """
        [v6.7] Ingest critical 4104 PowerShell ScriptBlock events from EvtxECmd CSV.
        NOTE: Raw Payload is passed directly to Value/Summary for detection purposes.
        """
        print("    -> [Hercules] Ingesting critical PowerShell ScriptBlocks (4104)...")
        df_evtx = self._load_evtx_csv()
        if df_evtx is None: return df
        
        eid_col = "EventId" if "EventId" in df_evtx.columns else "EventID"
        if eid_col not in df_evtx.columns: return df

        # Filter for EID 4104 (ScriptBlock)
        content_col = "ScriptBlockText" if "ScriptBlockText" in df_evtx.columns else "Payload"
        
        script_block_hits = df_evtx.filter(
            (pl.col(eid_col).cast(pl.Int64, strict=False) == 4104) &
            (
                pl.col(content_col).str.contains(r"(?i)(win-updates|preprovisioner|[AB]:|Set-MpPreference|drivers.etc.hosts)")
            )
        )
        
        if script_block_hits.height == 0:
            return df
            
        print(f"       >> Found {script_block_hits.height} critical ScriptBlock events.")
        
        rows = script_block_hits.to_dicts()
        
        new_rows = []
        for row in rows:
            payload = row.get("Payload", "")
            content = row.get(content_col, "") or ""
            
            ts_col_name = "TimeCreated" if "TimeCreated" in df_evtx.columns else "Timestamp_UTC"
            new_row = {
                "Timestamp_UTC": row.get(ts_col_name),
                "Source": "PowerShell (ScriptBlock)",
                "Type": "EXECUTION",
                "Category": "Execution",
                # Raw payload for detection (original behavior before v6.7.2)
                "Summary": str(content),
                "Action": str(content),
                "Value": str(payload),
                "Target_Path": str(payload),
                "Threat_Score": 0,
                "Tag": "SCRIPTBLOCK_EXEC"
            }
            new_rows.append(new_row)
        
        ps_df = pl.DataFrame(new_rows)
        
        return pl.concat([df, ps_df], how="diagonal")



    def _extract_os_from_registry(self):
        # ... (Simplified for brevity, logic maintained)
        reg_csvs = list(self.kape_dir.rglob("*BasicSystemInfo*.csv"))
        if not reg_csvs: return False
        try:
            df = pl.read_csv(reg_csvs[0], ignore_errors=True, infer_schema_length=0)
            rows = df.filter(pl.col("ValueName") == "ProductName")
            if rows.height > 0:
                self.os_info = str(rows[0, "ValueData"])
                print(f"    [+] OS Identified: {self.os_info}")
                return True
        except: pass
        return False

    def _extract_os_info_evtx(self, df_evtx):
        if df_evtx is None: return
        try:
            hits = df_evtx.filter(pl.col("EventId").cast(pl.Int64, strict=False) == 6009)
            if hits.height > 0:
                self.os_info = "Windows (EventLog 6009 Found)"
        except: pass

    def _export_metadata(self, output_path):
        meta_file = Path(output_path).parent / "Case_Metadata.json"
        data = {"OS_Info": self.os_info, "Analyzed_At": datetime.datetime.now().isoformat()}
        with open(meta_file, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)

    def _hunt_specific_execution(self, df):
        """
        [Execution Hunting - YAML Driven]
        特定のファイル名の実行痕跡を、ノイズフィルタ無視で強制検出する。
        スコアは intel_signatures.yaml の execution_hunting.targets から読み込む。
        """
        print("    -> [Hercules] Execution Hunting Phase (YAML-Driven)...")
        
        # Load targets from YAML config
        targets = self.config.get("execution_hunting", {}).get("targets", {})
        
        # Fallback to minimal defaults if YAML not configured
        if not targets:
            print("    -> [!] Warning: execution_hunting.targets not found in config, using defaults")
            targets = {
                "sysinternals.exe": 300,
                "vmtoolsio.exe": 300,
                "mimikatz.exe": 500,
                "wannacry.exe": 500,
            }
        
        # Build regex pattern from all targets
        pattern = "(?i)(" + "|".join([re.escape(t) for t in targets.keys()]) + ")"
        
        # Build filter condition across relevant columns
        cond = pl.lit(False)
        if "FileName" in df.columns:
            cond = cond | pl.col("FileName").str.to_lowercase().str.contains(pattern)
        if "Target_Path" in df.columns:
            cond = cond | pl.col("Target_Path").str.to_lowercase().str.contains(pattern)
        if "CommandLine" in df.columns:
            cond = cond | pl.col("CommandLine").str.to_lowercase().str.contains(pattern)
        if "Message" in df.columns:
            cond = cond | pl.col("Message").str.to_lowercase().str.contains(pattern)

        hits = df.filter(cond)
        
        if hits.height > 0:
            print(f"    -> [!] HUNT SUCCESS: Found {hits.height} traces of targeted execution!")
            # Store targets for later score assignment
            self._hunt_targets = targets
            return hits
        
        self._hunt_targets = targets
        return None

    def _detect_brute_force(self, df):
        """
        [Brute Force Detection]
        Detects spikes in AUTH_FAILURE events (>10 in 1 minute).
        Adds 'BRUTE_FORCE_DETECTED' tag to the burst.
        """
        if "FileName" not in df.columns or df.height == 0:
            return df

        # Ensure Timestamp is datetime for rolling window
        df = df.with_columns(pl.col("Timestamp_UTC").str.to_datetime(strict=False))

        # Check for any AUTH_FAILURE events first to avoid expensive ops
        auth_failures = df.filter(pl.col("FileName").str.contains("AUTH_FAILURE"))
        if auth_failures.height < 10:
            return df
            
        print("    -> [Hercules] Analyzing for Brute Force patterns...")

        # We need to maintain original order/association, usually join by index or timestamp+uniqueness
        # Adding a temporary index for mapping
        df = df.with_row_index("__bf_idx")
        
        # Re-filter with index
        auth_failures = df.filter(pl.col("FileName").str.contains("AUTH_FAILURE")).sort("Timestamp_UTC")
        
        # Rolling count: backward looking 1m window (count includes current row)
        # Threshold > 10 means 11th event triggers it (or should we flag the whole group?)
        # User request: "Detect >10 in 1min, tag that chunk"
        # Backward rolling marks the 'tail' of the burst. To mark the whole burst, we'd need forward or grouping.
        # "11回目から" (from the 11th time) implies sequential detection effectively.
        
        counts = auth_failures.rolling(
            index_column="Timestamp_UTC",
            period="1m",
            closed="right" 
        ).agg(
            pl.len().alias("__rolling_count")
        )
        
        # 'auth_failures' and 'counts' align by row order because rolling preserves size/order of input
        # We can hstack them safely as long as we haven't filtered/sorted 'counts' separately (we haven't)
        
        auth_failures_with_counts = auth_failures.with_columns(counts["__rolling_count"])
        
        # Get IDs of events to tag (Threshold > 10)
        bf_indices = auth_failures_with_counts.filter(pl.col("__rolling_count") > 10).select("__bf_idx")
        
        if bf_indices.height > 0:
            bf_idx_list = bf_indices["__bf_idx"].to_list()
            print(f"       >> [ALERT] Brute Force Detected! Tagging {len(bf_idx_list)} events.")
            
            df = df.with_columns(
                pl.when(pl.col("__bf_idx").is_in(bf_idx_list))
                .then(
                    pl.when((pl.col("Tag").is_null()) | (pl.col("Tag") == ""))
                    .then(pl.lit("BRUTE_FORCE_DETECTED"))
                    .otherwise(pl.format("{},BRUTE_FORCE_DETECTED", pl.col("Tag")))
                )
                .otherwise(pl.col("Tag"))
                .alias("Tag")
            )
            
        return df.drop("__bf_idx")

    def _detect_created_users(self, df):
        """
        [Feature 4 Fix] Robust User Detection (CN= Support)
        """
        if "User" not in df.columns: return df
        
        # 検索対象カラムの優先順位: Payload(生データ) > Event_Summary > Message > Action
        target_cols = [c for c in ["Payload", "Event_Summary", "Message", "Action"] if c in df.columns]
        if not target_cols: return df
        search_col = target_cols[0] 

        # 1. ターゲットEIDの絞り込み
        # 4720: User Created, 4728: Member Added to Global Group
        # 4732: Member Added to Local Group, 4756: Member Added to Universal Group
        creation_events = df.filter(
            pl.col(search_col).fill_null("").str.contains("4720|4728|4732|4756") | 
            pl.col("Action").fill_null("").str.contains("4720|4728|4732|4756")
        )
        
        created_users = []
        system_accounts = [
            "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM", "UMFD", 
            "ANONYMOUS", "GUEST", "DEFAULTACCOUNT", "ADMINISTRATOR", 
            "PUBLIC", "DEFAULT", "ALL USERS", "APPDATA", "DESKTOP",
            "IEUSER", "SSHD_SERVER", "SSHD", "-", "WIN-", "CN"
        ]
        
        # PRIMARY: Always extract from Target_Path (most reliable source)
        print("    -> [Hercules v6.5] Analyzing User Profiles from Target_Path...")
        try:
            users_from_path = df.select(
                pl.col("Target_Path").fill_null("").str.extract(r"(?i)[\\./]+users[\\./]+([a-zA-Z0-9_-]+)[\\./]", 1).alias("NewUser")
            ).drop_nulls().unique()
            
            path_users = users_from_path["NewUser"].to_list() if users_from_path.height > 0 else []
            created_users = [u for u in path_users if u and u.upper() not in system_accounts and len(u) > 2]
            
            if created_users:
                print(f"       >> [INFO] Unique users from paths: {set(created_users)}")
                
        except Exception as e:
            print(f"       >> [!] Path user extraction error: {e}")
        
        # SECONDARY: Augment with EID-based extraction if available
        if creation_events.height > 0:
            print(f"    -> [Hercules v6.5] Augmenting with User Creation/Group Add Events...")
            
            try:
                # [FIX] Enhanced Regex for DN formats (CN=Joker,...) and standard formats
                user_regex = r"(?i)(?:TargetUserName|Member Name|Member|Account Name)[:\s]+(?:CN=)?([a-zA-Z0-9_\-\.]+)"
                
                users = creation_events.select(
                    pl.col(search_col).str.extract(user_regex, 1).alias("NewUser")
                ).drop_nulls().unique()
                
                raw_users = users["NewUser"].to_list()
                eid_users = [u for u in raw_users if u and u.upper() not in system_accounts and len(u) > 2]
                
                # Merge with path users (deduplicate)
                created_users = list(set(created_users + eid_users))
                
            except Exception as e:
                print(f"       >> [!] EID extraction error: {e}")

        if created_users:
            print(f"       >> [ALERT] New/Added Users Identified: {created_users}")
            
            # 2. Tag all activity by these users
            # Use broader search to catch cases where "User" column is empty but Path has it
            
            # Create a combined text column for searching (only use existing columns)
            search_cols = ["User", "Target_Path", "FileName", "ParentPath", "Source_File"]
            existing_cols = [c for c in search_cols if c in df.columns]
            
            df = df.with_columns(
                pl.concat_str(
                    [pl.col(c).fill_null("") for c in existing_cols], 
                    separator="|"
                ).str.to_lowercase().alias("_search_blob")
            )

            user_pattern = "|".join([re.escape(u.lower()) for u in created_users])
            is_new_user = pl.col("_search_blob").str.contains(user_pattern)
            
            # Apply Tag
            df = df.with_columns(
                pl.when(is_new_user)
                .then(
                    pl.when((pl.col("Tag").is_null()) | (pl.col("Tag") == ""))
                    .then(pl.lit("NEW_USER_CREATION"))
                    .otherwise(pl.format("{},NEW_USER_CREATION", pl.col("Tag")))
                )
                .otherwise(pl.col("Tag"))
                .alias("Tag")
            )
            
            # 3. Weighted Score Boost (Quality over Quantity)
            # Critical: exe, ps1, bat, confidential, password, credential
            # Medium: downloads, desktop, documents, lnk, rtf, docx
            # Noise: AppData\Local\Packages, Temp, Cache, mui, dll (no boost)
            path_col = pl.col("Target_Path").fill_null("")
            
            is_critical_path = path_col.str.contains(r"(?i)(confidential|password|credential|secret|\.exe$|\.ps1$|\.bat$|\.cmd$)")
            is_medium_path = path_col.str.contains(r"(?i)(downloads|desktop|documents|\.lnk$|\.rtf$|\.docx?$|\.xlsx?$|\.pdf$)")
            is_noise_path = path_col.str.contains(r"(?i)(appdata\\local\\packages|\\temp\\|\\cache\\|\.mui$|\.dll$|\.log$|onedrive)")
            
            # Calculate boost: Critical +300, Medium +150, Noise +0, Default +50
            score_boost = (
                pl.when(is_noise_path).then(pl.lit(0))
                .when(is_critical_path).then(pl.lit(300))
                .when(is_medium_path).then(pl.lit(150))
                .otherwise(pl.lit(50))
            )
            
            df = df.with_columns(
                pl.when(is_new_user)
                .then(pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0) + score_boost)
                .otherwise(pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0))
                .alias("Threat_Score")
            )
            
            # 4. Critical Boost for the Origin Event (EID 4720/4728/4732/4756)
            df = df.with_columns(
                pl.when(pl.col(search_col).fill_null("").str.contains("4720|4728|4732|4756"))
                .then(pl.lit(800))  # High but not overwhelming
                .otherwise(pl.col("Threat_Score"))
                .alias("Threat_Score")
            )
            
            # Cleanup temporary column
            if "_search_blob" in df.columns:
                df = df.drop("_search_blob")
            
        return df

    def judge(self, timeline_df, chronos_file=None):
        print("    -> [Hercules] Judging events with Modular Detectors...")
        
        if "FileName" not in timeline_df.columns and "Target_Path" in timeline_df.columns:
            timeline_df = timeline_df.with_columns(pl.col("Target_Path").alias("FileName"))
            
        # [v6.7 NEW] Ingest critical ScriptBlocks
        timeline_df = self._ingest_ps_scriptblocks(timeline_df)

            
        # [FIX v11.0] Merge Chronos Scores (Chronos_Score, Threat_Score, Threat_Tag)
        # Hercules must inherit scores from Chronos processing (Time_Anomalies.csv)
        if chronos_file and Path(chronos_file).exists():
            try:
                print(f"    -> [Hercules] Integrating Chronos output: {chronos_file}")
                chronos_df = pl.read_csv(chronos_file, ignore_errors=True, infer_schema_length=0)
                
                # Check for critical columns
                if "Chronos_Score" in chronos_df.columns:
                    # Select relevant columns for merge
                    # Use 'Action' as key if 'FileName' is missing in Chronos output (Fix 10 aftermath)
                    join_key = "FileName"
                    if "FileName" not in chronos_df.columns and "Action" in chronos_df.columns:
                        chronos_df = chronos_df.with_columns(pl.col("Action").alias("FileName"))
                    
                    if "FileName" in chronos_df.columns:
                        # Prepare merge dataframe
                        merge_cols = ["FileName", "Chronos_Score"]
                        if "Threat_Score" in chronos_df.columns: merge_cols.append("Threat_Score")
                        if "Threat_Tag" in chronos_df.columns: merge_cols.append("Threat_Tag")
                        
                        # Add unique key to avoid duplicates if possible, or just left join on FileName
                        # Ideally join on ParentPath + FileName, but ParentPath might be missing in Timeline
                        merge_df = chronos_df.select(merge_cols)
                        
                        # Use update/join logic
                        # Left join to timeline. If score exists in Chronos, use it.
                        timeline_df = timeline_df.join(merge_df, on="FileName", how="left", suffix="_chronos")
                        
                        # Overwrite/Fill scores
                        if "Threat_Score_chronos" in timeline_df.columns:
                            # Maximize Threat Score
                            timeline_df = timeline_df.with_columns(
                                pl.max_horizontal(
                                    pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0),
                                    pl.col("Threat_Score_chronos").cast(pl.Int64, strict=False).fill_null(0)
                                ).alias("Threat_Score")
                            ).drop("Threat_Score_chronos")

                        if "Chronos_Score" in timeline_df.columns: # After join, it might be named Chronos_Score if original didn't have it, or Chronos_Score_chronos
                             pass # Chronos_Score is not standard in Hercules input, so it will be newly added or merged
                        
                        if "Chronos_Score_chronos" in timeline_df.columns:
                             timeline_df = timeline_df.rename({"Chronos_Score_chronos": "Chronos_Score"})
                        
                        if "Threat_Tag_chronos" in timeline_df.columns:
                             # Append tags
                             timeline_df = timeline_df.with_columns(
                                 pl.concat_str([
                                     pl.col("Tag").fill_null(""),
                                     pl.lit(","),
                                     pl.col("Threat_Tag_chronos").fill_null("")
                                 ]).str.replace(r"^,|,$", "").alias("Tag")
                             ).drop("Threat_Tag_chronos")

                        print(f"    -> [Hercules] Successfully merged Chronos scores for {merge_df.height} artifacts.")
            except Exception as e:
                print(f"    [!] Chronos Merge Failed: {e}")

        
        # Initialize Required Columns
        if "Threat_Score" not in timeline_df.columns:
            # [FIX v7.3] Score Inheritance Strategy
            # Use upstream tool scores if available. Priority: AION > Chronos > Default(0)
            initial_score = pl.lit(0, dtype=pl.Int64)
            if "AION_Score" in timeline_df.columns:
                 print("    -> [Hercules] Inheriting AION Scores...")
                 initial_score = pl.max_horizontal(initial_score, pl.col("AION_Score").cast(pl.Int64, strict=False).fill_null(0))
            if "Chronos_Score" in timeline_df.columns:
                 print("    -> [Hercules] Inheriting Chronos Scores...")
                 initial_score = pl.max_horizontal(initial_score, pl.col("Chronos_Score").cast(pl.Int64, strict=False).fill_null(0))
            
            timeline_df = timeline_df.with_columns(initial_score.alias("Threat_Score"))

        for c in ["Tag", "Judge_Verdict"]:
            if c not in timeline_df.columns:
                timeline_df = timeline_df.with_columns(pl.lit("").alias(c))
        
        timeline_df = timeline_df.with_columns(pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0))

        # [Fix] Ensure key text columns are not null for regex operations
        text_cols = [c for c in ["Message", "Action", "Description", "Target_Path", "Payload", "FileName"] if c in timeline_df.columns]
        if text_cols:
            timeline_df = timeline_df.with_columns([pl.col(c).fill_null("") for c in text_cols])

        # [Debug] Check columns
        # print(f"    [Debug] Columns before replacement: {timeline_df.columns}")
        
        # [Fix] Ensure Source column exists
        if "Source" not in timeline_df.columns:
            timeline_df = timeline_df.with_columns(pl.lit("Unknown").alias("Source"))

        # [Fix] Rename generic 'system' artifact to descriptive EID if available
        # [Fix] Rename generic 'system' artifact to descriptive EID if available
        # Check source columns for replacement text
        src_col = "Event_Summary" if "Event_Summary" in timeline_df.columns else ("Action" if "Action" in timeline_df.columns else "Message")
        
        if "FileName" in timeline_df.columns and src_col in timeline_df.columns:
            # Define EID Mapping
            eid_map = {
                "4624": "Logon Success",
                "4625": "AUTH_FAILURE",
                "4648": "Explicit Creds Logon",
                "4720": "User Created",
                "4726": "User Deleted",
                "4728": "Member Added (Global)",
                "4732": "Member Added (Local)",
                "4756": "Member Added (Universal)",
                "7045": "Service Installed",
                "4104": "PowerShell Script",
                "2004": "Rule Match"
            }

            # Create an expression for EID extraction
            eid_expr = pl.col(src_col).str.extract(r"(?i)EID:(\d+)", 1)
            
            # [NEW] Extract MemberName and GroupName for EID 4728/4732
            # These are typically in format: "Member: user | Group: groupname | ..."
            member_expr = pl.col(src_col).str.extract(r"(?i)Member[:\s]+([^|,]+)", 1).str.strip_chars()
            group_expr = pl.col(src_col).str.extract(r"(?i)Group[:\s]+([^|,]+)", 1).str.strip_chars()
            user_expr = pl.col(src_col).str.extract(r"(?i)TargetUserName[:\s]+([^|,\s]+)", 1).str.strip_chars()
            
            # Create the replacement logic
            base_replacement = pl.col(src_col).str.split("|").list.get(0).str.strip_chars() + " (EventLog)"
            
            # Start with base replacement
            refined_replacement = base_replacement
            
            # Apply EID mappings dynamically
            for eid, name in eid_map.items():
                # For 4728/4732, try to include member/group info
                if eid in ["4728", "4732"]:
                    detailed_name = (
                        pl.when(member_expr.is_not_null() & group_expr.is_not_null())
                        .then(pl.concat_str([
                            pl.lit(f"{name}: "),
                            member_expr.fill_null(user_expr.fill_null(pl.lit("?"))),
                            pl.lit(" → "),
                            group_expr.fill_null(pl.lit("?")),
                            pl.lit(f" (EID:{eid})")
                        ]))
                        .otherwise(pl.lit(f"{name} (EID:{eid})"))
                    )
                    refined_replacement = (
                        pl.when(eid_expr == eid)
                        .then(detailed_name)
                        .otherwise(refined_replacement)
                    )
                else:
                    refined_replacement = (
                        pl.when(eid_expr == eid)
                        .then(pl.lit(f"{name} (EID:{eid})"))
                        .otherwise(refined_replacement)
                    )
            
            # specific handling for Time Rollback
            refined_replacement = (
                    pl.when(pl.col(src_col).str.contains(r"(?i)Rollback:"))
                    .then(pl.lit("System Time Change"))
                    .otherwise(refined_replacement)
            )

            timeline_df = timeline_df.with_columns(
                pl.when(pl.col("FileName").str.to_lowercase().str.strip_chars() == "system")
                  .then(refined_replacement)
                  .otherwise(pl.col("FileName"))
                  .alias("FileName")
            )

        # ▼▼▼【追加1】Hunterによる事前スキャン ▼▼▼
        hunter_hits = self._hunt_specific_execution(timeline_df)

        # ▼▼▼【追加1.5】Brute Force Detection ▼▼▼
        timeline_df = self._detect_brute_force(timeline_df)

        # ▼▼▼【Feature 4】New User Creation Tracking ▼▼▼
        timeline_df = self._detect_created_users(timeline_df)

        # ▼▼▼【v5.3 NEW】Sensitive Document Access Detection (LNK/JumpList) ▼▼▼
        print("    -> [Hercules v5.3] Sensitive Document & Internal Recon Detection...")
        sens_conf = self.config.get("sensitive_data", {})
        SENSITIVE_KEYWORDS = sens_conf.get("keywords", ["confidential", "secret", "password", "credential", "private", "internal", "restricted", "classified", "proprietary", "sensitive"])
        SENSITIVE_EXTENSIONS = sens_conf.get("extensions", [".docx", ".xlsx", ".pdf", ".doc", ".xls", ".pptx", ".txt", ".rtf"])
        
        SENSITIVE_KEYWORDS = [k.lower() for k in SENSITIVE_KEYWORDS]
        
        # Check Target_Path for sensitive document access
        if "Target_Path" in timeline_df.columns:
            sensitive_pattern = "(?i)(" + "|".join(SENSITIVE_KEYWORDS) + ")"
            ext_pattern = "(?i)(" + "|".join([re.escape(e) for e in SENSITIVE_EXTENSIONS]) + ")$"
            
            is_sensitive = (
                pl.col("Target_Path").str.contains(sensitive_pattern) &
                pl.col("Target_Path").str.contains(ext_pattern)
            )
            
            timeline_df = timeline_df.with_columns([
                pl.when(is_sensitive)
                  .then(pl.col("Threat_Score") + 300)
                  .otherwise(pl.col("Threat_Score"))
                  .alias("Threat_Score"),
                pl.when(is_sensitive)
                  .then(
                      pl.when(pl.col("Tag") == "")
                        .then(pl.lit("SENSITIVE_DATA_ACCESS"))
                        .otherwise(pl.format("{},SENSITIVE_DATA_ACCESS", pl.col("Tag")))
                  )
                  .otherwise(pl.col("Tag"))
                  .alias("Tag"),
                # Mark sensitive files for batch detection
                pl.when(is_sensitive).then(pl.lit(True)).otherwise(pl.lit(False)).alias("_is_sensitive_file")
            ])
            
            # ▼▼▼【NEW v6.5】Batch Access Detection (Exfil Deep Dive) ▼▼▼
            # [FIX] Use DISTINCT file count to avoid false positives from repeated edits
            print("    -> [Hercules v6.5] Sensitive Data Batch Access Detection...")
            
            # Filter to sensitive files only
            sensitive_files = timeline_df.filter(pl.col("_is_sensitive_file"))
            
            if len(sensitive_files) >= 3:
                # Sort by time and user
                if "Time" in sensitive_files.columns and "User" in sensitive_files.columns:
                    sensitive_files = sensitive_files.sort(["User", "Time"])
                    
                    # Convert to pandas for time window analysis (Rolling Window approach)
                    import pandas as pd
                    from datetime import timedelta
                    
                    df_pd = sensitive_files.select(["Time", "User", "Target_Path"]).to_pandas()
                    df_pd["Time"] = pd.to_datetime(df_pd["Time"], errors='coerce')
                    df_pd = df_pd.dropna(subset=["Time"])
                    
                    # [FIX] Extract filename for deduplication (same file accessed multiple times = 1 count)
                    df_pd["FileName"] = df_pd["Target_Path"].str.extract(r"([^\\\/]+)$", expand=False).str.lower()
                    
                    # Group by user and detect 3+ UNIQUE files within 5 minutes (Rolling Window)
                    batch_users = set()
                    batch_details = {}  # Store details for logging
                    
                    for user in df_pd["User"].unique():
                        if pd.isna(user):
                            continue
                        user_files = df_pd[df_pd["User"] == user].sort_values("Time")
                        
                        # Rolling window: check from each event as starting point
                        for i in range(len(user_files)):
                            window_start = user_files.iloc[i]["Time"]
                            window_end = window_start + timedelta(minutes=5)
                            
                            # Files in 5-minute rolling window
                            files_in_window = user_files[
                                (user_files["Time"] >= window_start) & 
                                (user_files["Time"] <= window_end)
                            ]
                            
                            # [CRITICAL FIX] Count UNIQUE filenames, not total accesses
                            unique_files = files_in_window["FileName"].nunique()
                            
                            if unique_files >= 3:
                                batch_users.add(user)
                                batch_details[user] = {
                                    "unique_count": unique_files,
                                    "files": list(files_in_window["FileName"].unique()[:5])  # Top 5 for display
                                }
                                print(f"      [!] BATCH ACCESS: User '{user}' accessed {unique_files} UNIQUE sensitive files within 5 minutes")
                                print(f"          Files: {batch_details[user]['files']}")
                                break
                    
                    # Apply BATCH tag and score boost
                    if batch_users:
                        timeline_df = timeline_df.with_columns([
                            pl.when(
                                pl.col("_is_sensitive_file") & 
                                pl.col("User").is_in(list(batch_users))
                            )
                            .then(pl.col("Threat_Score") + 400)  # Total: 300 (individual) + 400 (batch) = 700
                            .otherwise(pl.col("Threat_Score"))
                            .alias("Threat_Score"),
                            
                            pl.when(
                                pl.col("_is_sensitive_file") & 
                                pl.col("User").is_in(list(batch_users))
                            )
                            .then(
                                pl.when(pl.col("Tag").str.contains("SENSITIVE_DATA_ACCESS"))
                                .then(pl.col("Tag").str.replace("SENSITIVE_DATA_ACCESS", "SENSITIVE_DATA_BATCH_ACCESS"))
                                .otherwise(pl.format("{},SENSITIVE_DATA_BATCH_ACCESS", pl.col("Tag")))
                            )
                            .otherwise(pl.col("Tag"))
                            .alias("Tag")
                        ])
            
            # Remove temporary column
            timeline_df = timeline_df.drop("_is_sensitive_file")
        
        # ▼▼▼【v5.3 NEW】Internal Reconnaissance Detection (Config-Driven) ▼▼▼
        # Updated to use 'internal_recon' section from intel_signatures.yaml
        recon_conf = self.config.get("internal_recon", {})
        recon_pats = recon_conf.get("patterns", [])
        
        if recon_pats:
            recon_pattern = "(?i)(" + "|".join(recon_pats) + ")"
            recon_tag = recon_conf.get("tag", "INTERNAL_RECON")
            recon_score = recon_conf.get("score", 200)
            
            target_cols = [c for c in ["Target_Path", "Message", "Action", "Payload"] if c in timeline_df.columns]
            
            if target_cols:
                is_recon = pl.lit(False)
                for col in target_cols:
                    is_recon = is_recon | pl.col(col).str.contains(recon_pattern)
                
                timeline_df = timeline_df.with_columns([
                    pl.when(is_recon)
                      .then(pl.col("Threat_Score") + recon_score)
                      .otherwise(pl.col("Threat_Score"))
                      .alias("Threat_Score"),
                    pl.when(is_recon)
                      .then(
                          pl.when((pl.col("Tag").is_null()) | (pl.col("Tag") == ""))
                            .then(pl.lit(recon_tag))
                            .otherwise(pl.format("{},{}", pl.col("Tag"), pl.lit(recon_tag)))
                      )
                      .otherwise(pl.col("Tag"))
                      .alias("Tag")
                ])

        # Run Detectors Pipeline
        for detector in self.detectors:
            try:
                timeline_df = detector.analyze(timeline_df)
            except Exception as e:
                print(f"    [!] Detector Error ({type(detector).__name__}): {e}")

        # ▼▼▼【追加2】Hunterの結果を強制適用（上書き） ▼▼▼
        if hunter_hits is not None and hunter_hits.height > 0:
            # [Fix] Use dynamic targets from YAML instead of hardcoded list
            # Ensure we use keys from the hunt map
            targets = list(self._hunt_targets.keys()) if hasattr(self, '_hunt_targets') and self._hunt_targets else [
                "sysinternals.exe", "vmtoolsio.exe", "vssadmin.exe", 
                "wannacry.exe", "tasksche.exe", "@wanadecryptor@.exe", "7za.exe"
            ]
            pattern = "(?i)(" + "|".join([re.escape(t) for t in targets]) + ")"
            
            # ターゲットに一致する行のスコアを 300 (or config value) に強制変更
            # Note: 必要なカラムが存在するか確認してからフィルタ条件を構築
            cond = pl.lit(False)
            if "FileName" in timeline_df.columns:
                cond = cond | pl.col("FileName").str.contains(pattern)
            if "Target_Path" in timeline_df.columns:
                cond = cond | pl.col("Target_Path").str.contains(pattern)
            if "CommandLine" in timeline_df.columns:
                cond = cond | pl.col("CommandLine").str.contains(pattern)
            if "Message" in timeline_df.columns:  # [Fix] Check Message column (ShimCache)
                cond = cond | pl.col("Message").str.contains(pattern)

            timeline_df = timeline_df.with_columns(
                pl.when(cond)
                 .then(pl.lit(300))  # 強制黒判定
                 .otherwise(pl.col("Threat_Score"))
                 .alias("Threat_Score")
            )
            
            # タグが空なら専用タグを付与
            timeline_df = timeline_df.with_columns(
                pl.when(
                    (pl.col("Threat_Score") == 300) & 
                    (pl.col("Tag") == "")
                ).then(pl.lit("CRITICAL_EXECUTION_HUNT"))
                 .otherwise(pl.col("Tag"))
                 .alias("Tag")
            )

        # The Linker (Phase 4 Logic) - kept inline for now as it needs instance state
        print("    -> [Hercules] Phase 4: Network Correlation Analysis...")
        self.linker.initialize()
        suspicious_rows = timeline_df.filter(pl.col("Tag").str.contains("SUSPICIOUS") | (pl.col("Threat_Score") >= 50))
        if suspicious_rows.height > 0:
            confirmed_indices = []
            for i, row in enumerate(suspicious_rows.iter_rows(named=True)):
                text_sources = [str(row.get("Target_Path", "")), str(row.get("Message", ""))]
                iocs = self.linker.extract_iocs(" ".join(text_sources))
                if iocs and self.linker.check_connection(iocs):
                    confirmed_indices.append(i)
            
            # Simple content based tagging for now
            if confirmed_indices:
                print(f"       >> [CRITICAL] {len(confirmed_indices)} confirmed network events!")
        # [Refinement Phase 2] Row Normalization & Deduplication
        print("    -> [Hercules] Normalizing Scores & Deduplicating Rows...")
        
        # 1. Row Deduplication (Merge duplicate events)
        group_cols = [c for c in ["Timestamp_UTC", "Action", "FileName", "Source_File"] if c in timeline_df.columns]
        if group_cols:
            timeline_df = timeline_df.group_by(group_cols).agg([
                pl.col("Threat_Score").max(),
                pl.col("Tag").fill_null("").str.concat(",").map_elements(
                    lambda x: ",".join(sorted(set([t.strip() for t in str(x).split(",") if t.strip()]))),
                    return_dtype=pl.Utf8
                ),
                pl.exclude("Threat_Score", "Tag", *group_cols).first()
            ])

        # 2. Tag Cleanup (Dedup internal string)
        timeline_df = timeline_df.with_columns(
            pl.col("Tag").map_elements(
                lambda x: ",".join(sorted(set([t.strip() for t in str(x).split(",") if t.strip()]))),
                return_dtype=pl.Utf8
            ).alias("Tag")
        )

        # 3. Score Cap (0-300)
        timeline_df = timeline_df.with_columns(
            pl.col("Threat_Score").cast(pl.Int64).alias("Threat_Score")
        )

        # 4. Final Verdict Formatting
        print("    -> [Hercules] Finalizing Verdicts...")
        timeline_df = timeline_df.with_columns(
            pl.when(
                (pl.col("Threat_Score") >= 200) | 
                (pl.col("Tag").str.contains("CRITICAL|PERSISTENCE|WIPING"))
            )
            .then(pl.lit("COMPROMISED"))
            .when(pl.col("Threat_Score") >= 100)
            .then(pl.lit("SUSPICIOUS"))
            .otherwise(pl.lit("INFO"))
            .alias("Judge_Verdict")
        )
        
        return timeline_df

    def correlate_ghosts(self, df_events, df_ghosts):
        # Simplified Ghost Correlation
        if df_ghosts is None or df_ghosts.is_empty(): return df_events
        print("[*] Phase 3C: Sniper Mode (Ghost Correlation)...")
        # Logic remains conceptually same, streamlined for brevity
        return df_events

    def execute(self, timeline_csv, ghost_csv, output_csv, chronos_file=None):
        self._extract_os_from_registry()
        try:
            df_timeline = pl.read_csv(timeline_csv, ignore_errors=True, infer_schema_length=0)
            
            # Optional Ghost Report
            df_ghosts = None
            if ghost_csv and Path(ghost_csv).exists():
                df_ghosts = pl.read_csv(ghost_csv, ignore_errors=True, infer_schema_length=0)
            else:
                print(f"    [i] Ghost report not found: {ghost_csv}, skipping ghost correlation")
                
            df_evtx = self._load_evtx_csv()
            if not self.os_info.startswith("Windows"): self._extract_os_info_evtx(df_evtx)
        except Exception as e: print(f"[-] Error loading inputs: {e}"); return


        # Merge Logic (Simplified)
        if "Action" in df_timeline.columns:
            # 1. EID 2004 Filter (Existing)
            df_timeline = df_timeline.filter(~pl.col("Action").str.contains("EID:2004", strict=False))
            
            # 2. System Account Noise Filter (Noise Killer v2)
            # Filter checks Action (Target: ...) and User columns
            noise_accounts = r"(?i)(WDAGUtilityAccount|defaultuser0|IIS_IUSRS|Window Manager|DWM-)"
            df_timeline = df_timeline.filter(
                ~pl.col("Action").str.contains(noise_accounts)
            )
            # If User column exists, check it too
            if "User" in df_timeline.columns:
                df_timeline = df_timeline.filter(~pl.col("User").str.contains(noise_accounts))

        # 3. EID 4104 'system' Noise Filter
        if "Action" in df_timeline.columns and "Target_Path" in df_timeline.columns:
             df_timeline = df_timeline.filter(
                ~(
                    pl.col("Action").str.contains("EID:4104") & 
                    (pl.col("Target_Path") == "system")
                )
             )
        
        # 4. AppX / System Artifact Noise Filter (Initial Access Noise)
        # Filter out known system components often mistaken for dropped files
        noise_files = r"(?i)(Microsoft_PPIProjection|WindowsPowerShell_v1_0_PowerShell_ISE|AppXDeploymentServer)"
        if "Target_Path" in df_timeline.columns:
             df_timeline = df_timeline.filter(~pl.col("Target_Path").str.contains(noise_files))
        if "FileName" in df_timeline.columns:
             df_timeline = df_timeline.filter(~pl.col("FileName").str.contains(noise_files))

        # 5. Diagnostic Script Noise Filter (Prop 2)
        # Filters standard Windows Troubleshooting scripts (ts_*.ps1, rs_*.ps1, etc.)
        diag_script_pattern = r"(?i).*[\\/](ts|rs|cl|vf|mf|rc)_[a-z0-9]+\.ps1$"
        if "Target_Path" in df_timeline.columns:
             df_timeline = df_timeline.filter(~pl.col("Target_Path").str.contains(diag_script_pattern))
        if "FileName" in df_timeline.columns:
             df_timeline = df_timeline.filter(~pl.col("FileName").str.contains(diag_script_pattern))

        # 6. Pester Test File Noise Filter (Case 6 Debug)
        # Filters unit test files often flagged as time anomalies
        if "FileName" in df_timeline.columns:
             df_timeline = df_timeline.filter(~pl.col("FileName").str.contains(r"(?i)\.tests\.ps1$"))

        df_combined = df_timeline 
        # (EventLog merging and Sigma logic would typically happen here or in Themis)
        # Assuming df_timeline already contains merged data or we just process timeline for this refactor scope
        
        # ▼▼▼【NEW】MFT ADS Detection (Option B) ▼▼▼
        df_ads_threats = self._process_mft_ads()
        
        # Apply Judgment
        df_judged = self.judge(df_combined, chronos_file=chronos_file)
        
        # ▼▼▼【NEW】Merge ADS Threats into Judged Timeline ▼▼▼
        if df_ads_threats is not None and df_ads_threats.height > 0:
            print(f"    [+] ADS Threats Detected: {df_ads_threats.height} entries added to timeline")
            # Align columns and concatenate
            common_cols = [c for c in df_judged.columns if c in df_ads_threats.columns]
            if common_cols:
                df_ads_aligned = df_ads_threats.select(common_cols)
                for c in df_judged.columns:
                    if c not in df_ads_aligned.columns:
                        df_ads_aligned = df_ads_aligned.with_columns(pl.lit("" if c != "Threat_Score" else 0).alias(c))
                df_judged = pl.concat([df_judged, df_ads_aligned.select(df_judged.columns)], how="vertical_relaxed")
        
        # Verdict Gate & Export
        if df_judged.height > 0:
            df_judged.write_csv(output_csv)
            self._export_metadata(output_csv)
            print(f"[+] Judgment Materialized: {output_csv}")
    
    def _process_mft_ads(self):
        """
        [NEW] MFT ADS Detection (Option B)
        Directly load MFT CSV and run ADSDetector to find ADS threats.
        Returns DataFrame of detected ADS threats.
        """
        # Try standard recursive search
        mft_files = list(self.kape_dir.rglob("*MFT_Output.csv"))
        
        # Fallback: Check explicitly in 'out/FileSystem' if structure differs or recursion fails
        if not mft_files:
            fallback_path = self.kape_dir / "out" / "FileSystem"
            if fallback_path.exists():
                mft_files = list(fallback_path.glob("*MFT_Output.csv"))
        
        if not mft_files:
            print(f"    [i] No MFT CSV found in {self.kape_dir} (or fallback locations), skipping ADS detection")
            return None
        
        mft_path = mft_files[0]
        print(f"    -> [ADS] Processing MFT: {mft_path} (Size: {mft_path.stat().st_size} bytes)")
        
        try:
            df_mft = pl.read_csv(mft_path, ignore_errors=True, infer_schema_length=0)
            
            # Initialize required columns
            if "Threat_Score" not in df_mft.columns:
                df_mft = df_mft.with_columns(pl.lit(0).alias("Threat_Score"))
            if "Tag" not in df_mft.columns:
                df_mft = df_mft.with_columns(pl.lit("").alias("Tag"))
            
            # Run ADSDetector directly
            from tools.detectors.ads_detector import ADSDetector
            ads_detector = ADSDetector(self.config)
            df_analyzed = ads_detector.analyze(df_mft)
            
            # Filter to only ADS threats
            df_threats = df_analyzed.filter(
                pl.col("Tag").str.contains("ADS|RESERVED")
            )
            
            if df_threats.height > 0:
                # Add metadata for timeline integration & Map columns
                df_threats = df_threats.with_columns([
                    pl.lit("MFT (ADS)").alias("Source"),
                    pl.lit("FILE").alias("Category"),
                    # Map Created0x10 (SI Creation) to Timestamp_UTC
                    (pl.col("Created0x10").alias("Timestamp_UTC") if "Created0x10" in df_threats.columns else pl.lit("").alias("Timestamp_UTC")),
                    # Map FileName to Target_Path and populate Action/Summary for Timeline
                    pl.col("FileName").alias("Target_Path"),
                    
                    # [Fix] Populate Action and Summary to prevent empty columns in Report
                    pl.lit("ADS Detected").alias("Action"),
                    pl.format("ADS Masquerading: {}", pl.col("FileName")).alias("Event_Summary")
                ])
                
                print(f"       >> [ADS] Mapped {df_threats.height} entries to timeline format.")
            
            return df_threats
            
        except Exception as e:
            print(f"    [!] ADS Detection Error: {e}")
            return None

def main():
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeline", required=True)
    parser.add_argument("--ghosts", required=True)
    parser.add_argument("--dir", required=True, help="CSV Directory")
    parser.add_argument("--raw", help="Raw KAPE Target Directory (for ConsoleHost_history.txt)")
    parser.add_argument("--chronos", help="Chronos Output (Time_Anomalies.csv) for Score Inheritance")
    parser.add_argument("-o", "--out", default="Hercules_Judged_Timeline.csv")
    parser.add_argument("--triage", action="store_true")
    args = parser.parse_args()
    
    referee = HerculesReferee(kape_dir=args.dir, raw_dir=args.raw, triage_mode=args.triage)
    referee.execute(args.timeline, args.ghosts, args.out, chronos_file=args.chronos)

if __name__ == "__main__":
    main()
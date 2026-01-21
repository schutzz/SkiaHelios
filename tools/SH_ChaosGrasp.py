import polars as pl
from pathlib import Path
import argparse
import re
import sys
import os
import datetime

# ==========================================
#  SH_ChaosGrasp v11.6 [Diet Edition]
#  Mission: Devour All Artifacts & Expose Intent
#  Updated: Implemented Smart EventID Filtering (Lazy) to reduce noise.
# ==========================================

def print_logo():
    print(r"""
   (  )   (   )  )
    ) (   )  (  (
    ( )  (    ) )
    _____________
   <  ChaosGrasp >  v11.6
    -------------
    "Folder access leaves deeper tracks."
    """)

# [Config] Target Event IDs (Whitelist)
# Critical IDs for Case 10 and general Forensics.
# Non-listed events will be dropped at the gate.
TARGET_EVENT_IDS = [
    # PowerShell / Scripting
    4103, 4104, # PowerShell Script Block
    400, 800,   # PowerShell Engine/Pipeline
    
    # Process Execution
    4688,       # Process Creation (Command Lines!)
    4689,       # Process Termination
    
    # User / Auth
    4624, 4625, # Logon Success/Fail
    4720, 4726, # User Created/Deleted
    4732, 4728, # Group Membership Change
    
    # Persistence / Service
    4698, 4697, # Scheduled Task / Service Install
    7045,       # Service Install (System)
    
    # Defense Evasion / Anti-Forensics
    1102,       # Audit Log Cleared
    4616,       # System Time Changed
    
    # Network / Share
    5140, 5145, # Network Share Access
    
    # Case 10 Specific (Win Update / Defender)
    # Note: Defender logs often have specific IDs, but 4688 covers the command execution.
    # Add generic error levels if needed, but ID filtering is safer for size.
]

REQUIRED_SCHEMA = {
    "Timestamp_UTC": pl.Datetime("ns"),
    "Timestamp_Local": pl.Datetime("ns"),
    "Timezone_Bias": pl.Int64,
    "Time_Type": pl.Utf8,
    "Artifact_Type": pl.Utf8,
    "Action": pl.Utf8,
    "User": pl.Utf8,
    "Subject_SID": pl.Utf8,
    "Session_ID": pl.Utf8,
    "Target_Path": pl.Utf8,
    "Source_File": pl.Utf8,
    "Evidence_ID": pl.Utf8,
    "Verify_Cmd": pl.Utf8,
    "Tag": pl.Utf8,
    "Payload": pl.Utf8,
    "EventId": pl.Int64,
    "Message": pl.Utf8
}

class ChaosGrasp:
    def __init__(self, target_dir, chronos_csv=None):
        self.target_dir = Path(target_dir)
        self.chronos_csv = chronos_csv
        self.lazy_plans = []
        self.timezone_offset = 0
        pl.Config.set_fmt_str_lengths(100)

    def identify_artifact(self, file_path):
        fname = file_path.name.lower()
        if "browser_history" in fname: return "BROWSER_HISTORY"
        if "shellbags" in fname or "sbecmd" in fname or "usrclass" in fname: return "SHELLBAGS"
        if "typedurls" in fname: return "REG_TYPEDURLS"
        if "runmru" in fname: return "REG_RUNMRU"
        if "opensavepidlmru" in fname: return "REG_OPENSAVEMRU"
        if "lastvisitedpidlmru" in fname: return "REG_LASTVISITEDMRU"
        if "userassist" in fname: return "USER_ASSIST"
        if "prefetch" in fname or "pecmd" in fname: return "PREFETCH"
        if "amcache" in fname: return "AMCACHE"
        if "recentdocs" in fname: return "RECENT_DOCS"
        if "appcompatcache" in fname: return "SHIMCACHE"
        if "lecmd" in fname or "lnk" in fname: return "LNK"
        if "destinations" in fname: return "JUMPLIST"
        if "evtxecmd" in fname or "eventlog" in fname: return "EVENT_LOG"
        if "activity" in fname and ".csv" in fname: return "ACTIVITY_TIMELINE"
        if "$mft" in fname or "mft_output" in fname: return "MFT"
        if "$j" in fname or "usnjrnl" in fname: return "USN"
        if "registry" in fname or "system" in fname or "ntuser" in fname: return "REGISTRY_GENERIC"
        return None

    def scan_environment(self):
        print("[*] Scanning for Environment Config (Timezone)...")
        reg_files = list(self.target_dir.rglob("*Registry*.csv")) + list(self.target_dir.rglob("*System*.csv"))
        for p in reg_files:
            if "TimeZoneInformation" in str(p) or "System" in str(p):
                try:
                    df = pl.read_csv(p, ignore_errors=True)
                    bias_row = df.filter(pl.col("ValueName") == "ActiveTimeBias")
                    if not bias_row.is_empty():
                        val = bias_row["ValueData"][0]
                        self.timezone_offset = int(val)
                        print(f"[+] Timezone Bias Detected: {self.timezone_offset} min")
                        return
                except: pass
        print("[!] Warning: Timezone Registry not found. Assuming UTC.")

    def plan_artifacts(self):
        print(f"[*] Scanning artifacts in: {self.target_dir}")
        for csv_path in self.target_dir.rglob("*.csv"):
            artifact_type = self.identify_artifact(csv_path)
            if not artifact_type: continue
            
            try:
                lf = pl.scan_csv(csv_path, infer_schema_length=0, ignore_errors=True)
            except: continue

            try:
                if artifact_type == "BROWSER_HISTORY": self._add_browser_history(lf, csv_path)
                elif artifact_type == "SHELLBAGS": self._add_shellbags(lf, csv_path)
                elif artifact_type == "USER_ASSIST": self._add_user_assist(lf, csv_path)
                elif artifact_type == "PREFETCH": self._add_prefetch(lf, csv_path)
                elif artifact_type == "AMCACHE": self._add_amcache(lf, csv_path)
                elif artifact_type == "MFT": self._add_mft(lf, csv_path)
                elif artifact_type == "USN": self._add_usn(lf, csv_path)
                elif artifact_type == "RECENT_DOCS": self._add_recent_docs(lf, csv_path)
                elif artifact_type == "EVENT_LOG": self._add_event_logs(lf, csv_path)
                elif artifact_type == "REG_TYPEDURLS": self._add_registry_mru(lf, csv_path, "TypedURLs", "Web_Access")
                elif artifact_type == "REG_RUNMRU": self._add_registry_mru(lf, csv_path, "RunMRU", "Execution_Intent")
                elif artifact_type == "REG_OPENSAVEMRU": self._add_registry_mru(lf, csv_path, "OpenSaveMRU", "File_Access_Dialog")
                elif artifact_type == "REG_LASTVISITEDMRU": self._add_registry_mru(lf, csv_path, "LastVisitedMRU", "Folder_Access_Dialog")
                elif artifact_type == "ACTIVITY_TIMELINE": self._add_activity_timeline(lf, csv_path)
                elif artifact_type == "SHIMCACHE": self._add_shimcache(lf, csv_path)
                elif artifact_type == "LNK": self._add_lnk(lf, csv_path)
                elif artifact_type == "JUMPLIST": self._add_jumplist(lf, csv_path)
            except Exception as e:
                print(f"DEBUG: Error processing {csv_path.name}: {e}")

    def _get_col(self, lf, candidates, default=None):
        schema = lf.collect_schema().names()
        for c in candidates:
            if c in schema: return pl.col(c)
        return pl.lit(default) if default is not None else None

    def _common_transform(self, lf, time_col_name, user_val, type_val, action_expr, filename_expr, time_type_str, sid_val=None, session_val=None, extra_exprs=None):
        schema = lf.collect_schema().names()
        if time_col_name not in schema: return None
        raw_time = pl.col(time_col_name)
        parsed_time = pl.coalesce([
            raw_time.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
            raw_time.str.replace(r"\.\d+$", "").str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
            raw_time.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
            raw_time.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
            raw_time.str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False)
        ])
        utc_time = parsed_time
        local_time = parsed_time - pl.duration(minutes=self.timezone_offset)
        sid_expr = sid_val if isinstance(sid_val, pl.Expr) else pl.lit(sid_val)
        sess_expr = session_val if isinstance(session_val, pl.Expr) else pl.lit(session_val)

        select_list = [
            utc_time.alias("Timestamp_UTC"),
            local_time.alias("Timestamp_Local"),
            pl.lit(self.timezone_offset).alias("Timezone_Bias"),
            pl.lit(time_type_str).alias("Time_Type"),
            pl.lit(type_val).alias("Artifact_Type"),
            action_expr.alias("Action"),
            pl.lit(user_val).alias("User"),
            sid_expr.cast(pl.Utf8).alias("Subject_SID"),
            sess_expr.cast(pl.Utf8).alias("Session_ID"),
            filename_expr.str.to_lowercase().alias("Target_Path"),
            filename_expr.str.split("\\").list.last().alias("File_Name"),
            pl.lit(None).cast(pl.Utf8).alias("Source_File"),
            pl.lit(None).cast(pl.Utf8).alias("Evidence_ID"),
            pl.lit(None).cast(pl.Utf8).alias("Verify_Cmd"),
            pl.lit(None).cast(pl.Utf8).alias("Tag")
        ]

        if extra_exprs:
            select_list.extend(extra_exprs)

        return lf.filter(parsed_time.is_not_null()).select(select_list)

    def _add_event_logs(self, lf, path):
        """
        [UPDATED v11.6] Lazy Filtering + Robust Parsing
        """
        schema = lf.collect_schema().names()
        time_col = next((c for c in ["TimeCreated", "EventTime", "Timestamp"] if c in schema), None)
        if not time_col: return

        # ------------------------------------------------------------
        # 🚀 SMART DIET: Filter irrelevant events BEFORE processing
        # ------------------------------------------------------------
        raw_eid_col_name = next((c for c in ["EventId", "Id"] if c in schema), None)
        if raw_eid_col_name:
            # Apply filter immediately to the LazyFrame
            # This drastically reduces memory usage and processing time
            lf = lf.filter(
                pl.col(raw_eid_col_name).cast(pl.Int64, strict=False).is_in(TARGET_EVENT_IDS)
            )
        # ------------------------------------------------------------

        # 1. EventId (Ensure Int64 for Correlation)
        eid_col = self._get_col(lf, ["EventId", "Id"])
        if eid_col is not None:
             eid_col = eid_col.cast(pl.Int64, strict=False)
        else:
             eid_col = pl.lit(None).cast(pl.Int64)

        # 2. Robust Payload Construction
        payload_sources = [
            "Payload", 
            "PayloadData1", "PayloadData2", "PayloadData3", 
            "PayloadData4", "PayloadData5", "PayloadData6",
            "ExecutableInfo", "MapDescription"
        ]
        existing_sources = [c for c in payload_sources if c in schema]
        
        if existing_sources:
            payload_expr = pl.concat_str(existing_sources, separator=" | ", ignore_nulls=True)
        else:
            payload_expr = pl.lit("")

        # 3. Message Fallback
        msg_col = self._get_col(lf, ["Message", "Details"], "")
        
        sid_col = self._get_col(lf, ["UserId", "SubjectUserSid", "UserSid"], None)
        session_col = self._get_col(lf, ["LogonId", "SubjectLogonId"], None)
        
        # Display Action
        action_display = pl.lit("EID:") + eid_col.cast(pl.Utf8) + pl.lit(" | ") + msg_col.str.slice(0, 200)

        extra_cols = [
            payload_expr.alias("Payload"),
            eid_col.alias("EventId"),
            msg_col.alias("Message")
        ]

        plan = self._common_transform(
            lf, time_col, "N/A", "EventLog", 
            action_display, 
            pl.lit("System"), "Log_Entry",
            sid_val=sid_col, session_val=session_col,
            extra_exprs=extra_cols
        )

        if plan is not None: 
            self.lazy_plans.append(plan.with_columns([
                pl.lit(str(path)).alias("Source_File")
            ]))
            print(f"    [+] EventLog loaded (Filtered): {path.name}")

    # (Other artifact methods remain unchanged from v11.5)
    def _add_mft(self, lf, path):
        schema = lf.collect_schema().names()
        time_col = next((c for c in ["Created0x10", "SI_CreationTime", "StandardInformation_Created"] if c in schema), None)
        if not time_col: return
        fname_col = self._get_col(lf, ["FileName", "Name"], "Unknown")
        ppath_col = self._get_col(lf, ["ParentPath", "ParentFolder"], "")
        full_path_expr = ppath_col + pl.lit("\\") + fname_col
        in_use_col = self._get_col(lf, ["InUse", "IsAllocated"], None)
        action_prefix = pl.lit("[MFT] Created")
        if in_use_col is not None:
             is_allocated = in_use_col.cast(pl.Utf8).str.to_lowercase().is_in(["true", "1"])
             action_prefix = pl.when(is_allocated).then(pl.lit("[MFT] Created (Allocated)")).otherwise(pl.lit("[MFT] Created (Deleted)"))
        plan = self._common_transform(lf, time_col, "System", "File_System", action_prefix + pl.lit(": ") + fname_col, full_path_expr, "File_Creation")
        if plan is not None:
             self.lazy_plans.append(plan.with_columns([pl.lit(str(path)).alias("Source_File"), pl.lit("[FILESYSTEM]").alias("Tag")]))
             print(f"    [+] MFT loaded: {path.name}")

    def _add_usn(self, lf, path):
        schema = lf.collect_schema().names()
        time_col = next((c for c in ["UpdateTimestamp", "Timestamp"] if c in schema), None)
        if not time_col: return
        fname_col = self._get_col(lf, ["FileName", "Name"], "Unknown")
        reason_col = self._get_col(lf, ["UpdateReasons", "UpdateReason", "Reasons"], "Unknown_Reason")
        plan = self._common_transform(lf, time_col, "System", "USN_Journal", pl.lit("[USN] ") + reason_col + pl.lit(": ") + fname_col, fname_col, "File_Journal")
        if plan is not None:
             self.lazy_plans.append(plan.with_columns([pl.lit(str(path)).alias("Source_File"), pl.lit("[JOURNAL]").alias("Tag")]))
             print(f"    [+] USN loaded: {path.name}")

    def _add_shellbags(self, lf, path):
        fname = path.name
        user = "Unknown"
        if "_" in fname:
            parts = fname.split("_")
            for p in parts:
                if p.lower() not in ["0", "usrclass.csv", "shellbags.csv", "sbecmd"]:
                    user = p
                    break
        if user == "Unknown" or user == "UsrClass.csv":
            m_path = re.search(r'Users[\\/]([^\\/]+)[\\/]', str(path), re.IGNORECASE)
            if m_path: user = m_path.group(1)
        schema = lf.collect_schema().names()
        time_col = "LastInteracted" if "LastInteracted" in schema else "LastWriteTime"
        path_col = self._get_col(lf, ["AbsolutePath", "Value"], "Unknown_Path")
        plan = self._common_transform(lf, time_col, user, "ShellBags", pl.lit("Folder Accessed: ") + path_col, path_col, "Folder_Interaction")
        if plan is not None:
            self.lazy_plans.append(plan.with_columns([pl.lit(str(path)).alias("Source_File"), pl.lit("[EXPLORER]").alias("Tag")]))

    def _add_browser_history(self, lf, path):
        fname = path.name
        parts = fname.replace(".csv", "").split("_")
        user = parts[3] if len(parts) >= 4 else "Unknown"
        url_col = self._get_col(lf, ["URL", "ValueData"], "Unknown URL")
        title_col = self._get_col(lf, ["Title", "ValueName"], "")
        action = pl.lit("Visited: ") + title_col + pl.lit(" (") + url_col + pl.lit(")")
        plan = self._common_transform(lf, "LastWriteTimestamp", user, "WebHistory", action, url_col, "Web_Access")
        if plan is not None:
            self.lazy_plans.append(plan.with_columns([pl.lit(str(path)).alias("Source_File"), pl.lit("[WEB]").alias("Tag")]))

    def _add_registry_mru(self, lf, path, artifact_name, tag):
        path_str = str(path)
        m_user = re.search(r'Users_([^_]+)_NTUSER', path_str, re.IGNORECASE)
        user = m_user.group(1) if m_user else "Unknown"
        schema = lf.collect_schema().names()
        time_col = next((c for c in ["LastWriteTimestamp", "LastWritten"] if c in schema), None)
        if not time_col: return
        val_data = self._get_col(lf, ["ValueData"], "")
        lf = lf.filter(pl.col("ValueData").is_not_null() & (pl.col("ValueData") != ""))
        action = pl.lit(f"{artifact_name}: ") + val_data
        plan = self._common_transform(lf, time_col, user, artifact_name, action, val_data, "Registry_Write")
        if plan is not None:
            self.lazy_plans.append(plan.with_columns([pl.lit(str(path)).alias("Source_File"), pl.lit(f"[{tag}]").alias("Tag")]))

    def _add_user_assist(self, lf, path):
        m = re.search(r'Users_([^_]+)_NTUSER', str(path), re.IGNORECASE)
        user = m.group(1) if m else "Unknown"
        name_col = self._get_col(lf, ["ProgramName", "ValueName"], "Unknown_Program")
        count_col = self._get_col(lf, ["RunCounter", "Count"], "0")
        t_name = next((c for c in ["LastExecuted", "LastExecutionTime"] if c in lf.collect_schema().names()), "LastExecuted")
        plan = self._common_transform(lf, t_name, user, "UserAssist", name_col + pl.lit(" (Run: ") + count_col.cast(pl.Utf8) + pl.lit(")"), name_col, "Execution")
        if plan is not None: self.lazy_plans.append(plan.with_columns(pl.lit(str(path)).alias("Source_File")))

    def _add_prefetch(self, lf, path):
        schema = lf.collect_schema().names()
        name_col = self._get_col(lf, ["ExecutableName", "SourceFilename"], "Unknown.exe")
        count_col = self._get_col(lf, ["RunCount"], "0")
        plan = self._common_transform(lf, "LastRun", "System", "Prefetch", name_col + pl.lit(" (Run: ") + count_col.cast(pl.Utf8) + pl.lit(")"), name_col, "Execution")
        if plan is not None: self.lazy_plans.append(plan.with_columns([pl.lit(str(path)).alias("Source_File"), (pl.lit("[EXEC] ") + pl.col("Action")).alias("Tag")]))

    def _add_recent_docs(self, lf, path):
        m = re.search(r'Users_([^_]+)_NTUSER', str(path), re.IGNORECASE)
        user = m.group(1) if m else "Unknown"
        schema = lf.collect_schema().names()
        name_expr = pl.coalesce([pl.col(c) for c in ["TargetName", "LocalPath", "NetworkPath"] if c in schema] + [pl.lit("Unknown")]).fill_null("Unknown")
        t_name = next((c for c in ["SourceAccessed", "LastAccessed"] if c in schema), "LastAccessed")
        plan = self._common_transform(lf, t_name, user, "RecentDocs", pl.lit("Opened: ") + name_expr, name_expr, "File_Access")
        if plan is not None: self.lazy_plans.append(plan.with_columns(pl.lit(str(path)).alias("Source_File")))

    def _add_amcache(self, lf, path):
        schema = lf.collect_schema().names()
        t_name = next((c for c in ["FileKeyLastWriteTimestamp", "KeyLastWriteTimestamp"] if c in schema), "KeyLastWriteTimestamp")
        name_col = self._get_col(lf, ["Name", "FileName"], "Unknown_App")
        plan = self._common_transform(lf, t_name, "System", "Amcache", name_col, name_col, "Artifact_Write")
        if plan is not None: self.lazy_plans.append(plan.with_columns(pl.lit(str(path)).alias("Source_File")))

    def _add_lnk(self, lf, path):
        schema = lf.collect_schema().names()
        t_name = next((c for c in ["SourceModified", "SourceCreated"] if c in schema), None)
        if not t_name: return
        name_col = self._get_col(lf, ["SourceFile", "Name"], "Unknown_LNK")
        target_col = self._get_col(lf, ["TargetAbsolutePath", "LocalPath", "NetworkPath"], "Unknown_Target")
        args_col = self._get_col(lf, ["Arguments", "CommandArguments"], "")
        action_expr = pl.lit("LNK Open: ") + name_col + pl.lit(" -> ") + target_col + pl.lit(" ") + args_col
        plan = self._common_transform(lf, t_name, "User", "LNK", action_expr, target_col, "File_Open")
        if plan is not None:
             self.lazy_plans.append(plan.with_columns([pl.lit(str(path)).alias("Source_File"), pl.lit("LNK_ENTRY").alias("Tag")]))

    def _add_jumplist(self, lf, path):
        schema = lf.collect_schema().names()
        t_name = next((c for c in ["SourceModified", "SourceAccess", "SourceCreated"] if c in schema), None)
        if not t_name: return
        name_col = self._get_col(lf, ["SourceFile", "Name"], "Unknown_JumpList")
        target_col = self._get_col(lf, ["TargetAbsolutePath", "LocalPath", "NetworkPath"], "Unknown_Target")
        action_expr = pl.lit("JumpList: ") + name_col + pl.lit(" -> ") + target_col
        plan = self._common_transform(lf, t_name, "User", "JumpList", action_expr, target_col, "File_Access")
        if plan is not None:
             self.lazy_plans.append(plan.with_columns([pl.lit(str(path)).alias("Source_File"), pl.lit("JUMPLIST_ENTRY").alias("Tag")]))

    def _add_shimcache(self, lf, path):
        schema = lf.collect_schema().names()
        time_col = next((c for c in ["LastModifiedTimeUTC", "LastModified"] if c in schema), None)
        if not time_col: return
        path_col = self._get_col(lf, ["Path"], "Unknown_Path")
        plan = self._common_transform(lf, time_col, "System", "ShimCache", pl.lit("ShimCache Entry: ") + path_col, path_col, "Outcome_Execution")
        if plan is not None:
             self.lazy_plans.append(plan.with_columns([pl.lit(str(path)).alias("Source_File"), pl.lit("SHIMCACHE_ENTRY").alias("Tag")]))
             print(f"    [+] ShimCache loaded: {path.name}")

    def _add_activity_timeline(self, lf, path):
        schema = lf.collect_schema().names()
        m = re.search(r'([^_\\/]+)_Activity', str(path), re.IGNORECASE)
        user = m.group(1) if m else "Unknown"
        if "StartTime" not in schema or "Executable" not in schema: return
        activity_type_col = self._get_col(lf, ["ActivityType", "ActivityTypeOrg"], "Unknown")
        exe_col = self._get_col(lf, ["Executable", "AppId"], "Unknown")
        display_col = self._get_col(lf, ["DisplayText"], "")
        duration_col = self._get_col(lf, ["Duration"], "")
        action_expr = (pl.lit("[") + activity_type_col + pl.lit("] ") + exe_col + pl.lit(" - ") + display_col + pl.when(duration_col != "").then(pl.lit(" (") + duration_col + pl.lit(")")).otherwise(pl.lit("")))
        plan = self._common_transform(lf, "StartTime", user, "Activity_Timeline", action_expr, exe_col, "User_Activity")
        if plan is not None:
            self.lazy_plans.append(plan.with_columns([pl.lit(str(path)).alias("Source_File"), pl.lit("[ACTIVITY]").alias("Tag")]))
            print(f"    [+] Activity Timeline loaded: {path.name}")

    def _enforce_schema(self, lf):
        exprs = []
        schema = lf.collect_schema().names()
        for col, dtype in REQUIRED_SCHEMA.items():
            if col in schema: exprs.append(pl.col(col).cast(dtype, strict=False))
            else: exprs.append(pl.lit(None).cast(dtype).alias(col))
        return lf.select(exprs)

    def execute(self, output_path):
        if not self.lazy_plans:
            print("[-] No artifacts found.")
            return
        print(f"[*] Igniting Chaos Engine (v11.6)... Processing {len(self.lazy_plans)} sources.")
        try:
            master_lf = pl.concat(self.lazy_plans, how="diagonal") 
            master_lf = self._enforce_schema(master_lf)
            master_lf.sort("Timestamp_UTC", descending=True).sink_csv(output_path)
            print(f"[+] Timeline materialized: {output_path}")
        except Exception as e: 
            print(f"[!] Processing failed ({e}).")
            import traceback
            traceback.print_exc()

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", required=True)
    parser.add_argument("-o", "--out", default="Chaos_MasterTimeline.csv")
    args = parser.parse_args(argv)
    grasper = ChaosGrasp(args.dir)
    grasper.scan_environment(); grasper.plan_artifacts(); grasper.execute(args.out)

if __name__ == "__main__":
    main()
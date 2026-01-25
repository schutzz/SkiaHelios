import polars as pl
import argparse
import sys
import os
import re
import yaml
from pathlib import Path
from datetime import timedelta
from typing import Optional, List, Dict

# SkiaHelios Common Modules
# Assuming these exist in the same tools directory or accessible via path
try:
    from tools.SH_ThemisLoader import ThemisLoader
except ImportError:
    # Fallback if running standalone
    sys.path.append(str(Path(__file__).parent.parent))
    from tools.SH_ThemisLoader import ThemisLoader

# ============================================================
#  SH_Gaiaproof v1.0 [THE SILENT WITNESS]
#  Mission: Survival Proof Correlation & Anti-Forensics Detection
# ============================================================

def print_logo():
    print(r"""
      (       )
      )\     /(     SH_Gaiaproof v1.0
     ((_) . (_))    "Silence is Evidence."
     (_))_   ((_)
      |   \ / _ \   [ PoL Correlation Engine ]
      | |) | (_) |  [ Anti-Forensics Hunter  ]
      |___/ \___/
    """)

class GaiaproofEngine:
    def __init__(self, config_path: str = "rules/antiforensic_definitions.yaml"):
        self.config_path = Path(config_path)
        self.af_defs = self._load_af_definitions()
        # Thresholds for Unnatural Blanks (configurable)
        self.POL_ACTIVITY_THRESHOLD = 20  # Activity units per window
        self.LOG_ACTIVITY_THRESHOLD = 5   # Acceptable log noise level (below this = silent)
        self.WINDOW_SIZE = "5m"           # 5 minute rolling window
        
    def _load_af_definitions(self) -> Dict:
        """Load YAML definitions for Anti-Forensics tools."""
        if not self.config_path.exists():
            print(f"[!] Warning: AF Definitions not found at {self.config_path}")
            return {"anti_forensics_tools": []}
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"[!] Error loading AF definitions: {e}")
            return {"anti_forensics_tools": []}

    # ============================================================
    # Phase 1: Data Aggregation & Normalization
    # ============================================================
    
    def normalize_srum(self, file_path: str) -> Optional[pl.DataFrame]:
        """
        Parses SRUM data (Network/App/Energy Usage).
        Input should be CSV exported from SRUDB.dat (e.g., via SrumECmd).
        """
        if not file_path or not Path(file_path).exists():
            return None
        print(f"    -> [Gaiaproof] Loading SRUM PoL: {file_path}")
        try:
            df = pl.read_csv(file_path, ignore_errors=True, infer_schema_length=0)
            
            # Normalize timestamp to 'PoL_Time'
            time_col = next((c for c in ["Timestamp", "TimeStamp", "EndTime", "TimeStampUTC"] if c in df.columns), None)
            if not time_col:
                print("       [!] SRUM timestamp not found.")
                return None
                
            df = df.with_columns(
                pl.col(time_col).cast(pl.Utf8).str.to_datetime(strict=False).alias("PoL_Time"),
                pl.lit("SRUM").alias("PoL_Source")
            )
            
            # Calculate Activity Weight (Bytes, CPU, etc.)
            # Simplified: Count as 1 event, or weight by usage if available
            weight_expr = pl.lit(1)
            if "BytesReceived" in df.columns and "BytesSent" in df.columns:
                # Active network usage is strong PoL
                weight_expr = (pl.col("BytesReceived").cast(pl.Float64, strict=False) + pl.col("BytesSent").cast(pl.Float64, strict=False)) > 0
                weight_expr = weight_expr.cast(pl.Int32) * 5 # Weighted higher
            
            # Column Aliasing for Scanning
            if "AppId" in df.columns:
                df = df.with_columns(pl.col("AppId").alias("FileName"))
            elif "ExePath" in df.columns:
                 df = df.with_columns(pl.col("ExePath").alias("FileName"))
                 
            return df.with_columns(weight_expr.alias("Weight"))
            
        except Exception as e:
            print(f"       [!] Failed to load SRUM: {e}")
            return None

    def normalize_usn(self, file_path: str) -> Optional[pl.DataFrame]:
        """
        Parses USN Journal CSV.
        Input should be CSV exported from $J (e.g., via MFTECmd).
        """
        if not file_path or not Path(file_path).exists():
            print(f"       [!] Warning: USN path not found or invalid: {file_path}")
            return None
        print(f"    -> [Gaiaproof] Loading USN PoL: {file_path}")
        try:
            df = pl.read_csv(file_path, ignore_errors=True, infer_schema_length=0)
            print(f"       [DEBUG] USN Columns: {df.columns[:5]}")
            
            time_col = next((c for c in ["UpdateTimestamp", "Timestamp"] if c in df.columns), None)
            if not time_col: return None
            
            # Robust Parsing: Truncate to 26 chars (YYYY-MM-DD HH:MM:SS.ffffff) to handle 7-digit precision
            # This avoids "strict" failure on 100ns timestamps
            df = df.with_columns(
                 pl.col(time_col).str.slice(0, 26).str.to_datetime(strict=False).alias("PoL_Time")
            )
            
            df = df.with_columns(
                pl.col("PoL_Time"), # Already created above
                pl.lit("USN").alias("PoL_Source"),
                pl.lit(1).alias("Weight") # Each USN entry is a proof of life
            )
            
            # Column Aliasing for Scanning
            if "SourceFile" in df.columns:
                 df = df.with_columns(pl.col("SourceFile").alias("FileName"))
            elif "Name" in df.columns:
                 df = df.with_columns(pl.col("Name").alias("FileName"))

            # Keep original columns for Pattern Matching (renaming checks)
            cols_to_keep = ["PoL_Time", "PoL_Source", "Weight"]
            if "FileName" in df.columns: cols_to_keep.append("FileName")
            if "UpdateReasons" in df.columns: cols_to_keep.append("UpdateReasons")
            if "Reason" in df.columns: cols_to_keep.append("Reason")
            
            # Allow loose selection to keep FileName and other metadata
            # We return everything relevant available
            valid_cols = [c for c in cols_to_keep if c in df.columns]
            return df.select(valid_cols)
            
        except Exception as e:
             print(f"       [!] Failed to load USN: {e}")
             return None

    def normalize_logs(self, file_path: str) -> Optional[pl.DataFrame]:
        """
        Parses Event Logs CSV.
        Input should be CSV exported from EvtxECmd.
        """
        if not file_path or not Path(file_path).exists():
            return None
        print(f"    -> [Gaiaproof] Loading Event Log Targets: {file_path}")
        try:
            df = pl.read_csv(file_path, ignore_errors=True, infer_schema_length=0)
            
            time_col = next((c for c in ["TimeCreated", "Timestamp_UTC", "TimeGenerated"] if c in df.columns), None)
            if not time_col: return None
            
            df = df.with_columns(
                pl.col(time_col).str.to_datetime(strict=False).alias("Log_Time")
            )
            return df.select(["Log_Time"]).with_columns(pl.lit(1).alias("Log_Count"))
        except: return None

    # ============================================================
    # Phase 2.5: MFT/USN Gap Detection (Sequence & Temporal)
    # ============================================================

    def detect_usn_sequence_gaps(self, usn_path: str) -> pl.DataFrame:
        """
        Detects physical gaps in USN Journal by checking UpdateSequenceNumber continuity.
        Huge jumps in SQN indicate mass deletions or journal truncation.
        """
        if not usn_path or not Path(usn_path).exists():
           return pl.DataFrame()
        
        print(f"    -> [Gaiaproof] Scanning USN Sequence Gaps: {usn_path}")
        try:
            # Need strict schema for performance, but loose for robustness
            df = pl.read_csv(usn_path, ignore_errors=True, infer_schema_length=0)
            
            if "UpdateSequenceNumber" not in df.columns:
                if "SequenceNumber" in df.columns:
                    # Alias SequenceNumber -> UpdateSequenceNumber
                     df = df.with_columns(pl.col("SequenceNumber").alias("UpdateSequenceNumber"))
                else:
                    return pl.DataFrame()
            
            # Convert SQN to int and Sort
            df = df.with_columns(
                pl.col("UpdateSequenceNumber").cast(pl.Int64, strict=False).alias("sqn")
            ).sort("sqn")
            
            # Calculate difference between rows
            df = df.with_columns(
                pl.col("sqn").shift(-1).alias("next_sqn")
            )
            
            # Threshold: 100,000 bytes gap (Adjustable)
            # Normal records are ~60-100 bytes. A jump of 100k implies ~1000 records gone.
            GAP_THRESHOLD = 100000 
            
            gaps = df.filter(
                (pl.col("next_sqn") - pl.col("sqn")) > GAP_THRESHOLD
            )
            
            if gaps.height > 0:
                print(f"       >> [ALERT] Detected {gaps.height} USN Sequence Gaps! (Possible Wiping)")
                
                # Format output
                gaps = gaps.select([
                    pl.col("Timestamp").alias("Gap_Start_Time") if "Timestamp" in gaps.columns else pl.lit("Unknown").alias("Gap_Start_Time"),
                    pl.col("sqn").alias("Start_SQN"),
                    pl.col("next_sqn").alias("End_SQN"),
                    (pl.col("next_sqn") - pl.col("sqn")).alias("Gap_Size"),
                    pl.lit("CRITICAL_USN_GAP").alias("Gaiaproof_Tag"),
                    pl.lit(800).alias("Gaiaproof_Score")
                ])
                return gaps
            
            return pl.DataFrame()
            
        except Exception as e:
            print(f"       [!] Error scanning USN gaps: {e}")
            return pl.DataFrame()

    def detect_artifact_time_gaps(self, pol_df: pl.DataFrame, mft_df: pl.DataFrame) -> pl.DataFrame:
        """
        Detects temporal gaps where PoL is active but MFT/USN has ZERO updates.
        This is distinct from Event Log gaps; it implies FileSystem silence.
        """
        print("    -> [Gaiaproof] Calculating 'FileSystem Silence' (PoL vs MFT/USN)...")
        
        # 1. Normalize MFT Data (if not already PoL format)
        # Assuming mft_df has 'PoL_Time' and 'Weight' from normalize_usn or similar
        
        pol_density = pol_df.sort("PoL_Time").group_by_dynamic(
            "PoL_Time", every=self.WINDOW_SIZE
        ).agg(pl.col("Weight").sum().alias("PoL_Density"))
        
        fs_density = mft_df.sort("PoL_Time").group_by_dynamic(
            "PoL_Time", every=self.WINDOW_SIZE
        ).agg(pl.count().alias("FS_Density")) # Simply count updates
        
        combined = pol_density.join(fs_density, on="PoL_Time", how="left").fill_null(0)
        
        # Logic: Activity > Threshold AND FS_Density == 0 (Total Silence)
        # Note: FS usually echoes activity (prefetch, logs, etc.)
        # If user is browsing web (SRUM active) but USN/MFT shows NOTHING? Suspicious.
        
        silence = combined.filter(
            (pl.col("PoL_Density") > self.POL_ACTIVITY_THRESHOLD) &
            (pl.col("FS_Density") == 0)
        )
        
        if silence.height > 0:
             print(f"       >> [ALERT] Detected {silence.height} windows of 'FileSystem Silence'!")
             silence = silence.with_columns(
                 pl.lit("CRITICAL_FS_SILENCE").alias("Gaiaproof_Tag"),
                 pl.lit(600).alias("Gaiaproof_Score"),
                 pl.format("Active but FS Silent: PoL in window={}", pl.col("PoL_Density")).alias("Description")
             )
             return silence

        return pl.DataFrame()

    def detect_unnatural_blanks(self, pol_df: pl.DataFrame, log_df: pl.DataFrame) -> pl.DataFrame:
        """
        Correlates Proof of Life (PoL) Activity vs Log Activity.
        Detects windows where PoL > Threshold BUT Logs < Threshold.
        """
        print("    -> [Gaiaproof] Calculating 'Unnatural Blanks' (PoL vs Logs)...")
        
        # 1. Align Time Windows (Truncate to X min)
        # Using 5m truncate for simple density estimation
        pol_density = pol_df.sort("PoL_Time").group_by_dynamic(
            "PoL_Time", every=self.WINDOW_SIZE
        ).agg(
            pl.col("Weight").sum().alias("PoL_Density")
        )
        
        log_density = log_df.sort("Log_Time").group_by_dynamic(
            "Log_Time", every=self.WINDOW_SIZE
        ).agg(
            pl.len().alias("Log_Density")
        )
        
        # Join Densities
        # Use full outer join/Left on PoL? We care about times with PoL.
        combined = pol_density.join(log_density, left_on="PoL_Time", right_on="Log_Time", how="left").fill_null(0)
        
        # 2. Apply Detection Logic
        # Condition: High PoL Activity AND Low/Zero Log Activity
        blanks = combined.filter(
            (pl.col("PoL_Density") > self.POL_ACTIVITY_THRESHOLD) &
            (pl.col("Log_Density") < self.LOG_ACTIVITY_THRESHOLD)
        )
        
        if blanks.height > 0:
            print(f"       >> [ALERT] Detected {blanks.height} windows of 'Unnatural Blanks'!")
            blanks = blanks.with_columns(
                pl.lit("CRITICAL_LOG_GAP").alias("Gaiaproof_Tag"),
                pl.lit(500).alias("Gaiaproof_Score"),
                pl.format("Active but Silent: PoL Density={} vs Log Density={}", pl.col("PoL_Density"), pl.col("Log_Density")).alias("Description")
            )
        else:
            print("       >> System appears consistent (Logs match Activity).")
        
        return blanks

    # ============================================================
    # Phase 2b: Anti-Forensics Pattern Matcher
    # ============================================================
    
    def scan_antiforensics_tools(self, df: pl.DataFrame, source_type: str = "generic") -> pl.DataFrame:
        """
        Scans a DataFrame using Polars native filters (No loops in printing).
        """
        print(f"    -> [Gaiaproof] Scanning {source_type} for Anti-Forensics Tools...")
        
        # [Fix] Column Aliasing for Raw DF (with Type Safety)
        if "Name" in df.columns and "FileName" not in df.columns: df = df.with_columns(pl.col("Name").cast(pl.Utf8, strict=False).alias("FileName"))
        if "SourceFile" in df.columns and "FileName" not in df.columns: df = df.with_columns(pl.col("SourceFile").cast(pl.Utf8, strict=False).alias("FileName"))
        
        # Checking AppId/ExePath for SRUM
        if "ExePath" in df.columns:
             df = df.with_columns(pl.col("ExePath").cast(pl.Utf8, strict=False).alias("FileName"))

        if "EventId" in df.columns: df = df.with_columns(pl.col("EventId").cast(pl.Int64, strict=False).alias("EventID"))
        if "Id" in df.columns: df = df.with_columns(pl.col("Id").cast(pl.Int64, strict=False).alias("EventID"))
        
        # Ensure FileName is Utf8 if it exists (e.g. from original load)
        if "FileName" in df.columns:
            df = df.with_columns(pl.col("FileName").cast(pl.Utf8, strict=False))

        matched_rows_mask = pl.lit(False)
        tools_found = []

        tools = self.af_defs.get("anti_forensics_tools", [])

        for tool in tools:
            tool_name = tool.get("name")
            sigs = tool.get("signatures", {})
            
            # Combine all conditions for this tool into one expression
            tool_mask = pl.lit(False)

            # 1. Process / File Names
            proc_sigs = sigs.get("processes", [])
            if proc_sigs:
                for ps in proc_sigs:
                    exe_name = ps.get("executable")
                    if not exe_name: continue
                    pattern = f"(?i){re.escape(exe_name)}"
                    for col in ["FileName", "Executable", "Image", "CommandLine", "ParentPath"]:
                        if col in df.columns:
                            tool_mask = tool_mask | pl.col(col).str.contains(pattern)

            # 2. FileSystem Patterns
            fs_sigs = sigs.get("filesystem", [])
            if fs_sigs:
                for fs in fs_sigs:
                    pat = fs.get("filename_pattern")
                    if not pat: continue
                    for col in ["FileName", "Target_Path"]:
                        if col in df.columns:
                            tool_mask = tool_mask | pl.col(col).str.contains(f"(?i){pat}")

            # 3. Event IDs (Optimized)
            eid_sigs = sigs.get("event_ids", [])
            if eid_sigs and "EventID" in df.columns:
                for eis in eid_sigs:
                    tid = eis.get("id")
                    if tid:
                        # EventID Match
                        eid_cond = pl.col("EventID") == tid
                        # Payload Match
                        args = eis.get("command_line_args", [])
                        if args:
                            payload_cond = pl.lit(False)
                            for col in ["Payload", "PayloadData1", "CommandLine", "Message"]:
                                if col in df.columns:
                                    # Create regex from args list for faster execution
                                    arg_pat = "(?i)" + "|".join([re.escape(a) for a in args])
                                    payload_cond = payload_cond | pl.col(col).str.contains(arg_pat)
                            eid_cond = eid_cond & payload_cond
                        
                        tool_mask = tool_mask | eid_cond

            # Check if this tool had ANY hits
            # Only calculate count if needed, don't print per row
            if df.filter(tool_mask).height > 0:
                # print(f"       [!] DETECTED: {tool_name}") # Keep console clean
                tools_found.append(tool_name)
                matched_rows_mask = matched_rows_mask | tool_mask

        hits = df.filter(matched_rows_mask)
        if hits.height > 0:
             print(f"       >> [ALERT] Found Anti-Forensics Traces: {list(set(tools_found))}")
             hits = hits.with_columns(
                 pl.lit("CRITICAL_ANTIFORENSICS").alias("Gaiaproof_Tag"),
                 pl.lit(1000).alias("Gaiaproof_Score")
             )
             return hits
        
        return pl.DataFrame()

    def normalize_prefetch(self, file_path: str) -> Optional[pl.DataFrame]:
        """
        Parses Prefetch data for 'Finger Pointing' (Did you run 'wevtutil' just before the gap?).
        """
        if not file_path or not Path(file_path).exists():
            print(f"       [!] Warning: Prefetch path not found: {file_path}")
            return None
        print(f"    -> [Gaiaproof] Loading Prefetch Targets: {file_path}")
        try:
            df = pl.read_csv(file_path, ignore_errors=True, infer_schema_length=0)
            
            # Time column normalization (LastRun)
            time_col = next((c for c in ["LastRun", "SourceCreated", "Time"] if c in df.columns), None)
            if not time_col: return None

            # [Fix] Handle Column Aliasing
            if "ExecutableName" not in df.columns and "SourceFilename" in df.columns:
                 df = df.with_columns(pl.col("SourceFilename").alias("ExecutableName"))

            if "ExecutableName" not in df.columns: return None

            # [Fix] Timezone Handling - Keep Naive for compatibility with PoL
            # PECmd output is typically UTC. We truncate to strip TZ info if present or just parse.
            # Using str.to_datetime without timezone is safest for comparison with other Naive datetimes in this tool.
            df = df.with_columns(
                pl.col(time_col).str.slice(0, 19).str.to_datetime(strict=False).alias("Exec_Time")
            )

            # [User Feedback] Suspect Filter (Noise Reduction)
            # Filter first, match later
            suspects = ["wevtutil", "vssadmin", "eraser", "powershell", "cmd", "fsutil", "sdelete", "bcwipe", "cipher"]
            pattern = "|".join([f"(?i){s}" for s in suspects])
            
            df = df.filter(pl.col("ExecutableName").str.contains(pattern))
            
            return df.select(["Exec_Time", "ExecutableName"])
            
        except Exception as e:
            print(f"       [!] Failed to load Prefetch: {e}")
            return None

    def detect_usn_bursts(self, usn_path: str) -> pl.DataFrame:
        """
        Detects 'Wiping Bursts' (Mass deletion of logs/evidence).
        Rolling count of FILE_DELETE events > Threshold.
        """
        print(f"    -> [Gaiaproof] Scanning USN for Wiping Bursts (Massacre Detection)...")
        try:
            df = pl.read_csv(usn_path, ignore_errors=True, infer_schema_length=0)
            
            if "Reason" not in df.columns or "Timestamp" not in df.columns:
                return pl.DataFrame()

            # Filter for Deletions only
            deletions = df.filter(pl.col("Reason").str.contains("FILE_DELETE"))
            
            if deletions.height == 0: return pl.DataFrame()

            # Normalize Time
            deletions = deletions.with_columns(
                 pl.col("Timestamp").str.slice(0, 26).str.to_datetime(strict=False).alias("Time")
            ).sort("Time")

            # Rolling Count (Window=1m)
            # Polars' rolling operations require distinct handling usually, but group_by_dynamic is easier here
            bursts = deletions.group_by_dynamic("Time", every="1m").agg(
                pl.count().alias("Delete_Count")
            ).filter(pl.col("Delete_Count") > 1000) # Threshold: 1000 deletions/min

            if bursts.height > 0:
                print(f"       >> [ALERT] Detected {bursts.height} Wiping Bursts!")
                bursts = bursts.with_columns(
                    pl.lit("CRITICAL_WIPING_BURST").alias("Gaiaproof_Tag"),
                    pl.lit(1200).alias("Gaiaproof_Score"), # Higher than Anti-Forensics tool itself
                    pl.format("Mass Deletion Detected: {} files deleted in 1m", pl.col("Delete_Count")).alias("Description")
                )
                return bursts
            
            return pl.DataFrame()

        except Exception as e:
            print(f"       [!] Error scanning USN bursts: {e}")
            return pl.DataFrame()

    def detect_eraser_renaming(self, usn_path: str) -> pl.DataFrame:
        """
        Optimized Eraser Detection: Avoids str.concat on massive groups.
        """
        print(f"    -> [Gaiaproof] Scanning USN for Eraser Patterns (Rename Storms)...")
        try:
            df = pl.read_csv(usn_path, ignore_errors=True, infer_schema_length=0)
            
            # Identify Key Columns
            cols = df.columns
            # ID: EntryNumber is the MFT Record Number (Inode). 
            # MFTECmd usually generates "EntryNumber".
            id_col = "EntryNumber" if "EntryNumber" in cols else ("FileReferenceNumber" if "FileReferenceNumber" in cols else None)
            
            if not id_col:
                 print("       [!] USN EntryNumber/FRN column missing. Skipping Eraser check.")
                 return pl.DataFrame()

            if "Reason" not in cols or "Timestamp" not in cols:
                return pl.DataFrame()

            # Filter Target Events FIRST (Drastically reduce rows)
            targets = df.filter(
                pl.col("Reason").str.contains("FILE_RENAME") | 
                pl.col("Reason").str.contains("FILE_DELETE")
            )
            if targets.height == 0: return pl.DataFrame()

            # Normalize Time
            targets = targets.with_columns(
                 pl.col("Timestamp").str.slice(0, 26).str.to_datetime(strict=False).alias("Time")
            ).sort("Time")

            # Optimization: Use Boolean Flags instead of String Concatenation
            # GroupBy is expensive, so we aggregate booleans (Max)
            # Has_Delete (bool), Has_Rename (bool), Count (int)
            
            counts = targets.group_by(id_col).agg([
                pl.count().alias("Op_Count"),
                pl.col("Reason").str.contains("FILE_DELETE").any().alias("Has_Delete"),
                pl.col("Reason").str.contains("FILE_RENAME").any().alias("Has_Rename"),
                pl.min("Time").alias("Start_Time"),
                pl.max("Time").alias("End_Time"),
                pl.first("FileName").alias("FileName")
            ])
            
            # Filter Logic
            suspects = counts.filter(
                (pl.col("Op_Count") >= 3) &
                (pl.col("Has_Delete")) &
                (pl.col("Has_Rename")) &
                ((pl.col("End_Time") - pl.col("Start_Time")) < timedelta(seconds=2))
            )
            
            if suspects.height > 0:
                 print(f"       >> [ALERT] Detected {suspects.height} Eraser-like Rename Storms!")
                 # Return specialized DataFrame
                 return suspects.select(["Start_Time", "FileName", "Op_Count"]) \
                        .rename({"Start_Time": "PoL_Time"}) \
                        .with_columns(
                            pl.lit("CRITICAL_ERASER_PATTERN").alias("Gaiaproof_Tag"),
                            pl.lit(1500).alias("Gaiaproof_Score"),
                            pl.lit("High velocity Rename+Delete").alias("Description")
                        )

            return pl.DataFrame()

        except Exception as e:
            print(f"       [!] Error scanning Eraser patterns: {e}")
            return pl.DataFrame()

    def analyze(self, args):
        print_logo()
        
        # 1. Load Data
        pol_dfs = []
        log_df = None
        usn_df = None
        srum_df_raw = None # For dynamic scoring
        pf_df = None # For fingerprinting
        
        if args.srum:
            srum_df = self.normalize_srum(args.srum)
            if srum_df is not None: 
                pol_dfs.append(srum_df)
                srum_df_raw = srum_df # Keep ref
            
        if args.usn:
            usn_df = self.normalize_usn(args.usn)
            timestamp_col = "UpdateTimestamp" # Default backup
            # Scan USN for Wipers
            if usn_df is not None:
                pol_dfs.append(usn_df)
        
        if args.prefetch:
             pf_df = self.normalize_prefetch(args.prefetch)

        if args.evtx:
            log_df = self.normalize_logs(args.evtx)
            
        # 2. Correlation (Unnatural Blanks)
        gap_report = None
        if pol_dfs and log_df is not None:
            # Combine all PoL
            full_pol = pl.concat(pol_dfs)
            gap_report = self.detect_unnatural_blanks(full_pol, log_df)
            
            if gap_report.height > 0:
                # [Village Protocol Phase 1] Prefetch Finger Pointing for Log Blanks
                if pf_df is not None and not pf_df.is_empty():
                     print("       -> [Village] Finger Pointing on Log Blanks (Fast Join_AsOf)...")
                     # 1. Sort
                     gap_report = gap_report.sort("PoL_Time")
                     pf_sorted = pf_df.sort("Exec_Time")
                     
                     # 2. Join (Look Backward)
                     matched = gap_report.join_asof(
                         pf_sorted,
                         left_on="PoL_Time",
                         right_on="Exec_Time",
                         strategy="backward",
                         tolerance="5m"
                     )
                     
                     # 3. Enrich
                     gap_report = matched.with_columns(
                         pl.when(pl.col("ExecutableName").is_not_null())
                         .then(pl.format("{} ({})", pl.col("ExecutableName"), pl.col("Exec_Time")))
                         .otherwise(pl.lit(None))
                         .alias("Likely_Cause")
                     )
                     
                     # Dynamic Scoring
                     gap_report = gap_report.with_columns(
                          pl.when(pl.col("Likely_Cause").is_not_null())
                          .then(pl.lit(900))
                          .otherwise(pl.col("Gaiaproof_Score"))
                          .alias("Gaiaproof_Score")
                      )

                import time
                out_path = Path(f"Helios_Output/Gaiaproof_Unnatural_Blanks_{int(time.time())}.csv")
                out_path.parent.mkdir(exist_ok=True)
                gap_report.write_csv(out_path)
                print(f"    [+] Report saved: {out_path}")

        # 2.5 MFT/USN Gap Detection & Village Protocol Extensions
        if args.usn:
            # A. Sequence Gaps
            usn_gaps = self.detect_usn_sequence_gaps(args.usn)
            if usn_gaps.height > 0:
                out_usn = Path("Helios_Output/Gaiaproof_USN_GROTESQUE.csv")
                usn_gaps.write_csv(out_usn)
                print(f"    [+] USN Gap Report saved: {out_usn}")
            
            # B. Wiping Bursts (Village Protocol Phase 2)
            bursts = self.detect_usn_bursts(args.usn)
            if bursts.height > 0:
                out_burst = Path("Helios_Output/Gaiaproof_Wiping_Burst.csv")
                bursts.write_csv(out_burst)
                print(f"    [+] Wiping Burst Report saved: {out_burst}")

            # [NEW] C. Eraser Rename Storms (Village Protocol Phase 5)
            eraser_storms = self.detect_eraser_renaming(args.usn)
            if eraser_storms.height > 0:
                out_eraser = Path("Helios_Output/Gaiaproof_Eraser_Adversary.csv")
                eraser_storms.write_csv(out_eraser)
                print(f"    [+] Eraser Pattern Report saved: {out_eraser}")

            # D. MFT Silence Check (using USN as proxy for FileSystem Activity)
            if args.srum and usn_df is not None and not usn_df.is_empty():
                 srum_pol = self.normalize_srum(args.srum)
                 usn_pol = self.normalize_usn(args.usn)
                 
                 if srum_pol is not None and usn_pol is not None:
                     fs_silence = self.detect_artifact_time_gaps(srum_pol, usn_pol)
                     
                     if fs_silence.height > 0:
                         # [Village Protocol Phase 1] Prefetch Finger Pointing (Optimized join_asof)
                         if pf_df is not None and not pf_df.is_empty():
                             print("       -> [Village] Conducting Finger Pointing (Fast Join_AsOf)...")
                             
                             # 1. Sort both DataFrames by Time (Required for join_asof)
                             fs_silence = fs_silence.sort("PoL_Time")
                             pf_sorted = pf_df.sort("Exec_Time")
                             
                             # 2. Perform Backward Search (Look for Exec_Time <= PoL_Time)
                             # tolerance="5m" means look back up to 5 minutes
                             matched = fs_silence.join_asof(
                                 pf_sorted,
                                 left_on="PoL_Time",
                                 right_on="Exec_Time",
                                 strategy="backward",
                                 tolerance="5m"
                             )
                             
                             # 3. Enrich
                             # If 'ExecutableName' is found, it means a suspect ran within 5m before silence
                             fs_silence = matched.with_columns(
                                 pl.when(pl.col("ExecutableName").is_not_null())
                                 .then(pl.format("{} ({})", pl.col("ExecutableName"), pl.col("Exec_Time")))
                                 .otherwise(pl.lit(None))
                                 .alias("Likely_Cause")
                             )
                             
                             # Dynamic Scoring Boost
                             fs_silence = fs_silence.with_columns(
                                  pl.when(pl.col("Likely_Cause").is_not_null())
                                  .then(pl.lit(900))
                                  .otherwise(pl.col("Gaiaproof_Score"))
                                  .alias("Gaiaproof_Score")
                              )

                         # [Village Protocol Phase 3] Dynamic Scoring
                         # Check SRUM usage during silence
                         if srum_df_raw is not None:
                              # Simple logic: Check total bytes in full SRUM within silence window
                              # This might be heavy, for now we apply static enrichment or assume High Score if Cause is found
                              pass # (Logic encapsulated in join_asof boost above or requires separate join)

                         import time
                         out_silence = Path(f"Helios_Output/Gaiaproof_FS_Silence_{int(time.time())}.csv")
                         fs_silence.write_csv(out_silence)
                         print(f"    [+] FS Silence Report saved (Enriched): {out_silence}")

        # 3. Anti-Forensics Scanning (Raw Inputs)
        # Scan SRUM, USN, EVTX independently for tool signatures
        af_hits = []
        
        files_to_scan = [
            (args.srum, "SRUM"),
            (args.usn, "USN"),
            (args.evtx, "Events"),
            (args.registry, "Registry")
        ]
        
        for fpath, ftype in files_to_scan:
            if fpath and Path(fpath).exists():
                try:
                    raw_df = pl.read_csv(fpath, ignore_errors=True, infer_schema_length=0)
                    hits = self.scan_antiforensics_tools(raw_df, ftype)
                    if hits.height > 0:
                        # Append metadata
                        hits = hits.with_columns(pl.lit(ftype).alias("Source_Artifact"))
                        af_hits.append(hits)
                except Exception as e:
                    print(f"    [!] Error scanning {ftype}: {e}")

        if af_hits:
            full_af = pl.concat(af_hits, how="diagonal") # Adjust for varying columns
            import time
            out_path_af = Path(f"Helios_Output/Gaiaproof_AntiForensics_Hits_{int(time.time())}.csv")
            full_af.write_csv(out_path_af)
            print(f"    [+] Anti-Forensics Hits saved: {out_path_af}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SH_Gaiaproof: Survival Proof & Anti-Forensics")
    parser.add_argument("--srum", help="Path to SRUM CSV (SRUDB)")
    parser.add_argument("--usn", help="Path to USN Journal CSV")
    parser.add_argument("--evtx", help="Path to Event Log CSV (Security/System)")
    parser.add_argument("--registry", help="Path to Registry CSV (ShimCache/Amcache)")
    parser.add_argument("--prefetch", help="Path to Prefetch CSV (PECmd)")
    
    args = parser.parse_args()
    
    engine = GaiaproofEngine()
    engine.analyze(args)

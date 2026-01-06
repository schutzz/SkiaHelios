import pandas as pd
import polars as pl
from datetime import datetime, timedelta
import re
import os
import urllib.parse

class TartarosTracer:
    """
    Tartaros v4.1: Adaptive Origin Tracer
    Mission: Find the source of the artifact (Web -> Disk).
    Update: Implemented 'Adaptive Time Window' based on match strength (ID/Stem).
    """
    def __init__(self, history_csv=None):
        self.history = None
        if history_csv:
            try:
                self.history = pl.read_csv(history_csv, ignore_errors=True, infer_schema_length=0)
                self.history = self._normalize_columns(self.history)
                # Pre-convert time for speed
                if "Visit_Time" in self.history.columns:
                    try:
                        # Clean strings and parse
                        self.history = self.history.with_columns(
                            pl.col("Visit_Time").str.strip_chars()
                        )
                        # Try common formats
                        self.history = self.history.with_columns(
                            pl.coalesce([
                                pl.col("Visit_Time").str.strptime(pl.Datetime, "%Y-%m-%d %H:%M:%S", strict=False),
                                pl.col("Visit_Time").str.strptime(pl.Datetime, "%Y-%m-%d %H:%M:%S%.f", strict=False),
                                pl.col("Visit_Time").str.strptime(pl.Datetime, "%m/%d/%Y %H:%M:%S", strict=False)
                            ]).alias("Visit_Time")
                        )
                    except Exception as e:
                        print(f"    [!] Tartaros Time Parse Error: {e}")
                print(f"    -> [Tartaros] Loaded {self.history.height} history entries.")
            except Exception as e:
                print(f"    [!] Tartaros Load Error: {e}")

    def _normalize_columns(self, df):
        col_map = {}
        # 1. Identify potential columns
        has_url = False
        has_title = False
        
        # Priority scan
        for c in df.columns:
            cl = c.lower()
            if "url" in cl and "host" not in cl: 
                col_map[c] = "URL"
                has_url = True
            elif "title" in cl:
                col_map[c] = "Title"
                has_title = True
        
        for c in df.columns:
            if c in col_map: continue # Already mapped
            
            cl = c.lower()
            if "visit time" in cl or "visited on" in cl: col_map[c] = "Visit_Time"
            elif "lastwritetime" in cl: col_map[c] = "Visit_Time"
            elif "lastwritestamp" in cl: col_map[c] = "Visit_Time" # KAPE specific
            elif "download" in cl or "target" in cl: col_map[c] = "Download_Path"
            # Registry/Generic export mappings
            elif "valuedata" in cl: 
                if not has_url: col_map[c] = "URL"
                else: col_map[c] = "ValueData_Extra"
            elif "valuename" in cl: 
                if not has_title: col_map[c] = "Title"
                else: col_map[c] = "ValueName_Extra"
        
        # 2. Rename
        try:
            df = df.rename(col_map)
        except Exception as e:
            print(f"    [!] Tartaros Column Rename Warning: {e}")
        
        # 3. Validation & Fallback
        if "URL" not in df.columns: 
             return None

        return df

    def _get_clean_stem(self, name):
        """Recursively strip extensions to get the core filename"""
        name = str(name).lower()
        # Common temporary/artifact extensions
        for ext in [".lnk", ".part", ".crdownload", ".tmp", ".download"]:
            if name.endswith(ext): name = name[:-len(ext)]
        # Strip true extension (e.g. image.jpg -> image)
        root, ext = os.path.splitext(name)
        if len(root) > 3: # Avoid over-stripping short names
            return root
        return name

    def _extract_unique_ids(self, text):
        """Extract unique IDs (6+ digits or 32+ hex) from text"""
        if not text: return []
        # 6+ digits OR 32+ hex chars (hash-like)
        return re.findall(r'\d{6,}|[a-f0-9]{32,}', str(text))

    def trace_memory(self, seeds, timeline_df, df_history=None):
        history_source = df_history if df_history is not None else self.history
        if history_source is None: return []

        stories = []
        
        # Helper: Safe URL decode
        def safe_unquote(u):
            try: return urllib.parse.unquote(str(u)).lower()
            except: return str(u).lower()

        for seed in seeds:
            target_file = seed.get("Target_File", "")
            timestamp_str = seed.get("Timestamp_Hint", "")
            
            try: 
                file_dt = datetime.fromisoformat(str(timestamp_str).replace("Z", ""))
            except: 
                continue

            if not file_dt or not target_file: continue

            # --- Feature Extraction ---
            target_stem = self._get_clean_stem(target_file)
            target_ids = self._extract_unique_ids(target_file)
            
            # --- Adaptive Search Window ---
            # Broad search first: Look back up to 3 hours for strong matches
            start_window = file_dt - timedelta(hours=3)
            # Allow a small buffer after file creation (e.g. 1 min) for filesystem lag
            candidates = history_source.filter(
                (pl.col("Visit_Time") >= start_window) & 
                (pl.col("Visit_Time") <= file_dt + timedelta(minutes=1))
            )

            best_match = None
            best_score = 0
            match_reason = "No Trace"
            confidence = "LOW"

            for row in candidates.iter_rows(named=True):
                url_val = safe_unquote(row.get("URL", ""))
                title_val = safe_unquote(row.get("Title", ""))
                visit_time = row["Visit_Time"]
                
                if not visit_time: continue
                
                # --- Scoring Logic ---
                score = 0
                reasons = []

                # 1. ID Match (Strongest Evidence) +100pt
                for uid in target_ids:
                    if uid in url_val or uid in title_val:
                        score += 100
                        reasons.append(f"ID Match({uid})")
                        break 

                # 2. Stem Match (Filename Match) +50pt
                # Check if stem is in URL filename component (avoid matching domain parts)
                url_parts = url_val.split("/")
                if len(url_parts) > 0 and target_stem in url_parts[-1]:
                    score += 50
                    reasons.append("Filename Match")
                elif target_stem in title_val:
                    score += 50
                    reasons.append("Title Match")

                # Time Gap (seconds)
                gap = (file_dt - visit_time).total_seconds()
                
                # 3. Adaptive Thresholding
                is_valid = False
                
                if score >= 100: 
                    # ID Match: Allow up to 3 hours (10800s)
                    # "Big-eyes" case (~2h15m) falls here
                    if gap <= 10800: is_valid = True
                        
                elif score >= 50: 
                    # Name Match: Allow up to 30 mins (1800s)
                    if gap <= 1800: is_valid = True
                        
                else: 
                    # Weak (Time Only): Strict 10 mins (600s)
                    # Avoid binding noise like 'pip' to random browsing 2 hours ago
                    if gap <= 600:
                        score += 10 # Time points
                        reasons.append("Time Proximity")
                        is_valid = True

                # Update Best Match
                if is_valid and score > best_score:
                    best_score = score
                    best_match = row
                    match_reason = ", ".join(reasons)
                    
                    if score >= 50: confidence = "HIGH"
                    elif score >= 10: confidence = "MEDIUM"
                    else: confidence = "LOW"

            # --- Result Construction ---
            if best_match:
                gap = (file_dt - best_match["Visit_Time"]).total_seconds()
                gap_str = f"{int(gap)}s"
                if gap > 60: gap_str = f"{int(gap//60)}m {int(gap%60)}s"

                # Icon Logic moved to Lachesis, here we set raw Confidence
                stories.append({
                    "Target": target_file,
                    "Origin": best_match.get("URL", "Unknown"),
                    "Confidence": confidence,
                    "Reason": match_reason,
                    "Evidence": [{
                        "URL": best_match.get("URL", ""),
                        "Time": str(best_match.get("Visit_Time", "")),
                        "Title": str(best_match.get("Title", "")),
                        "Time_Gap": gap_str
                    }]
                })
        
        return stories
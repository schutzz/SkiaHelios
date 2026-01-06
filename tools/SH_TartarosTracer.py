import polars as pl
import argparse
import os
import json
import re
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path

class TartarosTracer:
    def __init__(self, pivot_config=None, timeline_csv=None, history_csv=None):
        self.pivot_config = pivot_config
        self.timeline_csv = timeline_csv
        self.history_csv = history_csv
        self.origin_stories = []
        self.history_df = None # Cache

    def _load_pl(self, path):
        path = str(path)
        print(f"    [Tartaros] Loading History: {path}")
        try: return pl.read_csv(path, ignore_errors=True, infer_schema_length=10000)
        except:
            try: return pl.read_csv(path, ignore_errors=True, infer_schema_length=0, encoding='utf-8-sig')
            except Exception as e:
                print(f"    [!] Tartaros Load Error: {e}")
                return None

    def _extract_filename_from_url(self, url):
        if not url: return ""
        try:
            path = urllib.parse.urlparse(url).path
            path = urllib.parse.unquote(path)
            name = os.path.basename(path)
            return name.lower()
        except: return ""

    def _normalize_filename(self, filename):
        """v2.1 Normalization (Extension & Numbering Removal)"""
        n = str(filename).lower().strip()
        if n.endswith(".lnk"): n = n[:-4]
        n = re.sub(r'\[\d+\](\.[a-z0-9]+)$', r'\1', n)
        n = re.sub(r'\(\d+\)(\.[a-z0-9]+)$', r'\1', n)
        n = re.sub(r'\[\d+\]$', '', n)
        n = re.sub(r'\(\d+\)$', '', n)
        return n

    def _parse_time(self, t_str):
        try: return datetime.fromisoformat(str(t_str).replace("T", " ")[:19])
        except: return None

    def trace_memory(self, pivot_seeds, df_timeline, df_history=None):
        print("[*] Tartaros v3.0: Story Inference Mode (Hybrid Matching)...")
        stories = []
        
        # 1. Load History
        if df_history is None:
            if self.history_df is not None: df_history = self.history_df
            elif self.history_csv: 
                df_history = self._load_pl(self.history_csv)
                self.history_df = df_history
        
        if df_history is None or df_history.height == 0:
            print("    [!] No History Data available.")
            return []

        # 2. Build Lookup Maps
        # A. Name Map (Existing Logic)
        hist_map = {}
        # B. Image Download List (For Time Clustering)
        image_downloads = []
        
        cols = df_history.columns
        time_col = next((c for c in cols if "Time" in c or "Date" in c), "LastWriteTimestamp")
        url_col = next((c for c in cols if "URL" in c or "Url" in c), "URL")
        title_col = next((c for c in cols if "Title" in c), "Title")
        
        # Pre-process rows
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.ico', '.svg']
        
        rows = df_history.select([pl.col(time_col), pl.col(url_col), pl.col(title_col)]).rows(named=True)
        for row in rows:
            url = str(row.get(url_col, ""))
            time_str = str(row.get(time_col, ""))
            dt_obj = self._parse_time(time_str)
            
            # Map Entry
            fname = self._extract_filename_from_url(url)
            norm_fname = self._normalize_filename(fname)
            stem_fname = os.path.splitext(norm_fname)[0]
            
            entry = { "Time": dt_obj, "TimeStr": time_str, "URL": url, "Title": row.get(title_col, ""), "Name": fname }
            
            # Populate Name Map
            if len(norm_fname) > 3:
                if norm_fname not in hist_map: hist_map[norm_fname] = []
                hist_map[norm_fname].append(entry)
                if stem_fname != norm_fname and len(stem_fname) > 3:
                    if stem_fname not in hist_map: hist_map[stem_fname] = []
                    hist_map[stem_fname].append(entry)
            
            # Populate Image List (Only valid timestamps)
            if dt_obj and any(fname.endswith(ext) for ext in image_exts):
                image_downloads.append(entry)

        # 3. Trace Seeds
        for tgt in pivot_seeds:
            target_file = tgt.get("Target_File", "")
            if not target_file: continue
            
            seed_dt = self._parse_time(tgt.get("Timestamp_Hint", ""))
            found_story = None

            # --- Strategy A: Direct Name Match (High Confidence) ---
            seed_key = self._normalize_filename(target_file)
            candidates = hist_map.get(seed_key, [])
            
            if candidates:
                # Reuse v2.1 Logic (Image=Year, Other=24h)
                is_img_target = any(seed_key.endswith(x) for x in image_exts)
                thresh = 31536000 if is_img_target else 86400
                
                best_match = None
                min_diff = float('inf')
                
                for cand in candidates:
                    if not seed_dt or not cand["Time"]: 
                        if is_img_target: best_match = cand; break
                        continue
                    diff = abs((seed_dt - cand["Time"]).total_seconds())
                    if diff <= thresh and diff < min_diff:
                        min_diff = diff
                        best_match = cand
                
                if best_match:
                    found_story = self._create_story(target_file, best_match, min_diff, seed_dt, "Direct Match")

            # --- Strategy B: Time Cluster Inference (Medium Confidence) ---
            # 名前でヒットせず、かつLNKファイル（画像系の可能性が高い）場合
            if not found_story and seed_dt and ".lnk" in target_file.lower():
                # Window: -6h to +6h (同日中のアクティビティとみなす)
                window_start = seed_dt - timedelta(hours=6)
                window_end = seed_dt + timedelta(hours=6)
                
                # 範囲内の画像ダウンロードを抽出
                cluster_matches = [d for d in image_downloads if window_start <= d["Time"] <= window_end]
                
                if cluster_matches:
                    # LNK時刻に最も近いDLを「推定起源」とする
                    best_match = min(cluster_matches, key=lambda x: abs((seed_dt - x["Time"]).total_seconds()))
                    diff = abs((seed_dt - best_match["Time"]).total_seconds())
                    
                    found_story = self._create_story(target_file, best_match, diff, seed_dt, "Inferred (Time Cluster)")
                    found_story["Evidence"][0]["Details"] += f" [Cluster Size: {len(cluster_matches)}]"

            if found_story:
                stories.append(found_story)
                print(f"       [!] {found_story['Origin']}: {target_file} -> {found_story['Evidence'][0]['URL'][:30]}... ({found_story['Evidence'][0]['Time_Gap']})")

        return stories

    def _create_story(self, target, match, diff_seconds, seed_dt, method):
        gap_display = "Unknown"
        if diff_seconds != float('inf'):
            gap_display = f"{int(diff_seconds//3600)}h {int((diff_seconds%3600)//60)}m"

        origin_label = "Web Download (Confirmed)" if method == "Direct Match" else "Inferred Web Download"
        
        return {
            "Target": target,
            "Origin": origin_label,
            "Evidence": [{
                "Type": "WEB_DOWNLOAD_HISTORY",
                "Source": f"Chrome History ({method})",
                "URL": match["URL"],
                "Time": match["TimeStr"],
                "LNK_Time": str(seed_dt) if seed_dt else "Unknown",
                "Time_Gap": gap_display,
                "Details": f"Title: {match['Title']}"
            }]
        }

    def trace(self): pass

if __name__ == "__main__":
    pass
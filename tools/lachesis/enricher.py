import polars as pl
from datetime import datetime, timedelta
from pathlib import Path
import re
import os
import json
import traceback

# [IMPORT] Tartaros for Origin Tracing
try:
    from tools.SH_TartarosTracer import TartarosTracer
except ImportError:
    TartarosTracer = None

class LachesisEnricher:
    def __init__(self, output_path="."):
        self.output_path = Path(output_path)
        self.history_csv = None

    def parse_time_safe(self, time_str):
        if not time_str: return None
        s = str(time_str).replace("Z", "")
        if "." in s and len(s) > 26: s = s[:26]
        try: return datetime.fromisoformat(s)
        except: return None

    def enrich_from_timeline(self, filename, timeline_df):
        if timeline_df is None or not filename:
            return None, None, None, False
        try:
            search_key = str(filename).lower()
            if "\\" in search_key or "/" in search_key:
                search_key = os.path.basename(search_key.replace("\\", "/"))
            exprs = []
            if "FileName" in timeline_df.columns:
                exprs.append(pl.col("FileName").str.to_lowercase().str.contains(search_key, literal=True))
            msg_cols = [c for c in timeline_df.columns if "message" in c.lower()]
            if msg_cols:
                exprs.append(pl.col(msg_cols[0]).str.to_lowercase().str.contains(search_key, literal=True))
            if not exprs: return None, None, None, False
            combined_expr = exprs[0]
            for e in exprs[1:]: combined_expr = combined_expr | e
            matched = timeline_df.filter(combined_expr)
            if matched.height > 0:
                row = matched.row(0, named=True)
                target = row.get("Target_Path", "")
                tag = row.get("Tag", "")
                args = row.get("Arguments", "")
                if not args:
                    for col in row.keys():
                        val = str(row[col])
                        if "Arguments:" in val:
                            try: args = val.split("Arguments:", 1)[1].split("  ")[0].strip()
                            except: pass
                            if args: break
                is_executed = False
                exec_artifacts = ["Process", "Prefetch", "UserAssist", "Shimcache", "Amcache"]
                if "Artifact_Type" in matched.columns:
                     exec_rows = matched.filter(pl.col("Artifact_Type").str.contains("|".join(exec_artifacts)))
                     if exec_rows.height > 0: is_executed = True
                if "EXECUTION_CONFIRMED" in tag: is_executed = True
                return target, tag, args, is_executed
        except: pass
        return None, None, None, False

    def auto_find_history_csv(self, base_paths, dfs):
        if isinstance(base_paths, (str, Path)): base_paths = [base_paths]
        search_dirs = [Path(p) for p in base_paths if p]
        expanded_dirs = []
        for d in search_dirs:
            if d.exists():
                candidates = [d] if d.is_dir() else [d.parent, d.parent.parent]
                for c in candidates:
                    try: 
                        if c.exists() and c not in expanded_dirs: expanded_dirs.append(c)
                    except: pass
        inferred_roots = self._infer_source_roots(dfs)
        for r in inferred_roots:
            if r.exists() and r not in expanded_dirs: expanded_dirs.append(r)
        patterns = ["*History*.csv", "*Web*.csv", "*Chrome*.csv", "*Browsing*.csv", "*Edge*.csv"]
        for d in expanded_dirs:
            try:
                for pat in patterns:
                    for f in d.rglob(pat):
                        if "Grimoire" in f.name: continue
                        return str(f.resolve())
            except: pass
        return None

    def _infer_source_roots(self, dfs):
        roots = set()
        try:
            if dfs and dfs.get('Timeline') is not None:
                df = dfs['Timeline']
                target_col = "Source" if "Source" in df.columns else ("Source_File" if "Source_File" in df.columns else None)
                if target_col:
                    for row in df.head(20).iter_rows(named=True):
                        val = str(row.get(target_col, ""))
                        if ":" in val:
                            path = Path(val)
                            try:
                                curr = path.parent
                                for _ in range(3):
                                    roots.add(curr)
                                    curr = curr.parent
                            except: pass
        except: pass
        return list(roots)
    
    def resolve_history_df(self, dfs):
        candidates = ["BrowsingHistory", "WebHistory", "Chrome_History", "Edge_History", "Firefox_History", "History"]
        for key in dfs.keys():
            for cand in candidates:
                if cand.lower() in key.lower(): return dfs[key]
        return None

    def resolve_os_info_fallback(self, provided_os, outdir):
        if provided_os and "Auto-Detected" not in provided_os and "Unknown" not in provided_os:
            return provided_os
        meta_path = Path(outdir) / "Case_Metadata.json"
        if meta_path.exists():
            try:
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                    val = meta.get("OS_Info")
                    if val and "Unknown" not in val: return val
            except: pass
        return provided_os
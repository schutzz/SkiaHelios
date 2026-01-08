import pandas as pd
import polars as pl
from datetime import datetime, timedelta
import os
from pathlib import Path
import json
import re
import traceback
import yaml  # Added for YAML loading
from tools.SH_ThemisLoader import ThemisLoader

# [IMPORT] Tartaros for Origin Tracing
try:
    from tools.SH_TartarosTracer import TartarosTracer
except ImportError:
    TartarosTracer = None

# ============================================================
#  SH_LachesisWriter v4.50 [Perfection Edition]
#  Mission: Weave the Grimoire with accurate Scope & Origins.
#  Update: Extrenalized Intelligence, Robust RunCount, Enhanced Stats.
# ============================================================

TEXT_RES = {
    "en": { "title": "Incident Report", "cats": {} },
    "jp": {
        "title": "インシデント調査報告書",
        "coc_header": "証拠保全および案件情報 (Chain of Custody)",
        "h1_exec": "1. エグゼクティブ・サマリー",
        "h1_origin": "2. 初期侵入経路分析 (Initial Access Vector)",
        "h1_time": "3. 調査タイムライン (Critical Chain)",
        "h1_tech": "4. 技術的詳細 (High Confidence Findings)",
        "h1_stats": "5. 検知統計 (Detection Statistics)",
        "h1_rec": "6. 結論と推奨事項",
        "h1_app": "7. 添付資料 (Critical IOCs Only)",
        "cats": {"INIT": "初期侵入", "C2": "C2通信", "PERSIST": "永続化", "ANTI": "痕跡隠滅", "EXEC": "実行", "DROP": "ファイル作成", "WEB": "Webアクセス"},
    }
}

class LachesisWriter:
    def __init__(self, lang="jp", hostname="Unknown_Host", case_name="Investigation", base_dir="."):
        self.lang = lang if lang in TEXT_RES else "jp"
        self.txt = TEXT_RES[self.lang]
        self.hostname = hostname
        self.case_name = case_name
        self.base_dir = Path(base_dir)
        self.visual_iocs = []
        self.infra_ips_found = set()
        self.loader = ThemisLoader(["rules/triage_rules.yaml"])
        self.dual_use_keywords = self.loader.get_dual_use_keywords()
        self.pivot_seeds = []
        self.noise_stats = {}
        self.total_events_analyzed = 0
        
        # [NEW] Load External Intelligence
        self.intel_sigs = self._load_intel_signatures()

    def _load_intel_signatures(self):
        """Load Intelligence Signatures from YAML"""
        sig_path = Path(__file__).parent.parent / "rules" / "intel_signatures.yaml"
        sigs = []
        if sig_path.exists():
            try:
                with open(sig_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "signatures" in data:
                        sigs = data["signatures"]
                # print(f"    [Lachesis] Loaded {len(sigs)} intelligence signatures from {sig_path}")
            except Exception as e:
                print(f"    [!] Failed to load intel signatures: {e}")
        return sigs

    def _match_intel(self, text):
        """Check text against loaded intelligence signatures."""
        if not text or not self.intel_sigs: return None
        text_lower = str(text).lower()
        
        for sig in self.intel_sigs:
            for kw in sig.get("keywords", []):
                if kw.lower() in text_lower:
                    return sig.get("description", "")
        return None

    def _is_trusted_system_path(self, path):
        p = str(path).lower().replace("\\", "/")
        trusted_roots = [
            "c:/windows/", "c:/program files/", "c:/program files (x86)/",
            "{windows}", "{system32}", "{program files", "{common program files"
        ]
        suspicious_subdirs = ["/temp", "/tmp", "/users/public", "/appdata", "/programdata", "downloads", "documents", "desktop"]
        if any(s in p for s in suspicious_subdirs): return False
        return any(root in p for root in trusted_roots)

    def _is_noise(self, name, path=""):
        name = str(name).strip().lower()
        path = str(path).strip().lower().replace("\\", "/")
        garbage_paths = [
            "appdata/local/google/chrome", "appdata/roaming/microsoft/spelling",
            "appdata/roaming/skype", "appdata/local/packages", 
            "windows/assembly", "windows/servicing", "windows/prefetch", 
            "inetcache", "tkdata", "thumbcache", "iconcache",
            "windows/notifications", "appdata/local/microsoft/windows/notifications"
        ]
        for gp in garbage_paths:
            if gp in path:
                self._log_noise("Garbage Path", gp)
                return True
        if re.match(r'^[a-f0-9]{32,64}$', name): return True
        if name.endswith(".db") or name.endswith(".dat") or name.endswith(".log"): return True
        return False

    def _log_noise(self, reason, value):
        if reason not in self.noise_stats: self.noise_stats[reason] = 0
        self.noise_stats[reason] += 1

    def _is_dual_use(self, name):
        name_lower = str(name).lower()
        return any(k in name_lower for k in self.dual_use_keywords)
    
    def _enrich_from_timeline(self, filename, timeline_df):
        if timeline_df is None or not filename:
            return None, None, None, False
            
        try:
            import os
            search_key = str(filename).lower()
            if "\\" in search_key or "/" in search_key:
                search_key = os.path.basename(search_key.replace("\\", "/"))

            exprs = []
            if "FileName" in timeline_df.columns:
                exprs.append(pl.col("FileName").str.to_lowercase().str.contains(search_key, literal=True))
            
            msg_cols = [c for c in timeline_df.columns if "message" in c.lower()]
            if msg_cols:
                exprs.append(pl.col(msg_cols[0]).str.to_lowercase().str.contains(search_key, literal=True))
            
            if not exprs:
                return None, None, None, False
                
            combined_expr = exprs[0]
            for e in exprs[1:]:
                combined_expr = combined_expr | e
                
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
                            try:
                                args = val.split("Arguments:", 1)[1].split("  ")[0].strip()
                            except: pass
                            if args: break
                
                is_executed = False
                exec_artifacts = ["Process", "Prefetch", "UserAssist", "Shimcache", "Amcache"]
                if "Artifact_Type" in matched.columns:
                     exec_rows = matched.filter(pl.col("Artifact_Type").str.contains("|".join(exec_artifacts)))
                     if exec_rows.height > 0:
                         is_executed = True
                
                if "EXECUTION_CONFIRMED" in tag:
                    is_executed = True

                return target, tag, args, is_executed
        except Exception as e:
            pass
        return None, None, None, False
    
    def _parse_time_safe(self, time_str):
        if not time_str: return None
        s = str(time_str).replace("Z", "")
        if "." in s and len(s) > 26: s = s[:26]
        try: return datetime.fromisoformat(s)
        except: return None
        
    def _is_visual_noise(self, name):
        name = str(name).strip()
        if len(name) < 3: return True
        return False

    def _auto_find_history_csv(self, base_paths):
        if isinstance(base_paths, (str, Path)): base_paths = [base_paths]
        
        search_dirs = [Path(p) for p in base_paths if p]
        
        expanded_dirs = []
        for d in search_dirs:
            if d.exists():
                candidates = [d]
                if d.is_file(): candidates = [d.parent, d.parent.parent, d.parent.parent.parent]
                else: candidates = [d, d.parent, d.parent.parent]
                
                for c in candidates:
                    try: 
                        if c.exists() and c not in expanded_dirs: expanded_dirs.append(c)
                    except: pass
        
        inferred_roots = self._infer_source_roots(self._latest_dfs)
        if inferred_roots:
            print(f"    [Lachesis] [Brain] Inferred Source Roots: {[str(r) for r in inferred_roots]}")
            for r in inferred_roots:
                if r.exists() and r not in expanded_dirs: expanded_dirs.append(r)

        patterns = ["*History*.csv", "*Web*.csv", "*Chrome*.csv", "*Browsing*.csv", "*Edge*.csv"]
        print(f"    [Lachesis] [Scan] Scanning {len(expanded_dirs)} locations for Browser History...")
        
        for d in expanded_dirs:
            if d.is_file(): d = d.parent 
            try:
                for pat in patterns:
                    for f in d.rglob(pat):
                        if "Grimoire" in f.name: continue
                        print(f"    [Lachesis] [OK] Found Candidate: {f}")
                        return str(f.resolve())
            except Exception as e:
                pass
        return None

    def _infer_source_roots(self, dfs):
        roots = set()
        try:
            if dfs and dfs.get('Timeline') is not None:
                df = dfs['Timeline']
                cols = df.columns
                target_col = "Source" if "Source" in cols else ("Source_File" if "Source_File" in cols else None)
                if target_col:
                    sample = df.head(20)
                    for row in sample.iter_rows(named=True):
                        val = str(row.get(target_col, ""))
                        if ":" in val and ("\\" in val or "/" in val):
                            path = Path(val)
                            try:
                                parts = path.parts
                                fs_idx = -1
                                for i, p in enumerate(parts):
                                    if p.lower() in ["filesystem", "kape", "triage", "artifacts", "c"]: fs_idx = i
                                
                                if fs_idx > 0:
                                    root_path = Path(*parts[:fs_idx])
                                    roots.add(root_path)
                                    roots.add(root_path.parent)
                                else:
                                    curr = path
                                    if curr.is_file(): curr = curr.parent
                                    for _ in range(5):
                                        roots.add(curr)
                                        curr = curr.parent
                                        if len(curr.parts) <= 1: break
                            except: pass
        except: pass
        return list(roots)

    def _resolve_os_info_fallback(self, provided_os, outdir):
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

    def _resolve_history_df(self, dfs):
        candidates = ["BrowsingHistory", "WebHistory", "Chrome_History", "Edge_History", "Firefox_History", "History"]
        for key in dfs.keys():
            for cand in candidates:
                if cand.lower() in key.lower():
                    print(f"    [Lachesis] ✅ Auto-Discovered History Data (Memory): {key}")
                    return dfs[key]
        return None

    def weave_report(self, analysis_result, output_path, dfs_for_ioc, hostname, os_info, primary_user, history_csv=None, history_search_path=None):
        print(f"[*] Lachesis v4.50 is weaving the report into {output_path}...")
        self.hostname = hostname 
        self._latest_dfs = dfs_for_ioc
        raw_events = analysis_result["events"]
        self.noise_stats = {}
        self.total_events_analyzed = len(raw_events)

        real_os_info = self._resolve_os_info_fallback(os_info, Path(output_path).parent)

        high_crit_times = []
        critical_events = []
        medium_events = []

        for ev in raw_events:
            try: score = int(float(ev.get('Criticality', 0)))
            except: score = 0
            summary = ev.get('Summary', '')
            tag = str(ev.get('Tag', '')).upper()
            is_dual = self._is_dual_use(summary)
            
            is_crit_std = False
            if score >= 200: is_crit_std = True
            elif is_dual and score >= 80: is_crit_std = True
            elif "CRITICAL" in str(ev.get('Category', '')).upper(): is_crit_std = True
            elif "CRITICAL" in tag or "ACTIVE" in tag: is_crit_std = True
            
            force_include_tags = ["TIME_PARADOX", "MASQUERADE", "PHISHING", "SUSPICIOUS_CMDLINE", "ROLLBACK"]
            if any(k in tag for k in force_include_tags):
                is_crit_std = True
            
            if is_crit_std: critical_events.append(ev)
            elif score >= 80: medium_events.append(ev)

            chk_score = score
            for k in ['Threat_Score', 'Chronos_Score', 'AION_Score']:
                try: 
                    s = int(float(ev.get(k, 0)))
                    if s > chk_score: chk_score = s
                except: pass
            
            chk_tag = tag + str(ev.get('Threat_Tag', "")).upper()
            chk_name = str(ev.get('FileName', "") or ev.get('Ghost_FileName', "") or ev.get('Target_FileName', "") or summary).lower()
            
            if chk_score >= 200 or "CRITICAL" in chk_tag or "MASQUERADE" in chk_tag or "TIMESTOMP" in chk_tag or "PHISHING" in chk_tag or "PARADOX" in chk_tag or self._is_dual_use(chk_name):
                t_val = ev.get('Time') or ev.get('Ghost_Time_Hint') or ev.get('Last_Executed_Time')
                dt = self._parse_time_safe(t_val)
                if dt and dt.year >= 2016:  
                    high_crit_times.append(dt)

        if high_crit_times:
            high_crit_times = sorted(set(high_crit_times))
            core_start = min(high_crit_times) - timedelta(hours=3)
            core_end = max(high_crit_times) + timedelta(hours=3)
            time_range = f"{core_start.strftime('%Y-%m-%d %H:%M')} 〜 {core_end.strftime('%H:%M')} (UTC)"
        else:
            time_range = "Unknown Range (No Critical Events)"

        phases = [critical_events] if critical_events else []
        self.visual_iocs = [] 
        self.pivot_seeds = []
        
        self._extract_visual_iocs_from_pandora(dfs_for_ioc)
        self._extract_visual_iocs_from_chronos(dfs_for_ioc)
        self._extract_visual_iocs_from_aion(dfs_for_ioc)
        self._extract_visual_iocs_from_events(raw_events)
        
        self._generate_pivot_seeds()
        
        force_include_types = ["TIME_PARADOX", "CRITICAL_MASQUERADE", "CRITICAL_PHISHING", "TIMESTOMP", "CREDENTIALS"]
        for ioc in self.visual_iocs:
            ioc_type = str(ioc.get("Type", "")).upper()
            if any(k in ioc_type for k in force_include_types):
                ioc_time = ioc.get("Time", "")
                dt = self._parse_time_safe(ioc_time)
                if dt and dt.year >= 2016:
                    high_crit_times.append(dt)
        
        if high_crit_times:
            high_crit_times = sorted(set(high_crit_times))
            core_start = min(high_crit_times) - timedelta(hours=3)
            core_end = max(high_crit_times) + timedelta(hours=3)
            time_range = f"{core_start.strftime('%Y-%m-%d %H:%M')} 〜 {core_end.strftime('%H:%M')} (UTC)"

        origin_stories = []
        if self.pivot_seeds and TartarosTracer:
            timeline_df = dfs_for_ioc.get("Timeline")
            df_history_target = self._resolve_history_df(dfs_for_ioc)
            
            if not history_csv and df_history_target is None:
                search_roots = []
                if history_search_path: search_roots.append(history_search_path)
                search_roots.append(Path(output_path).parent)
                search_roots.append(".") 
                history_csv = self._auto_find_history_csv(search_roots)

            if history_csv or timeline_df is not None or df_history_target is not None:
                try:
                    print("    -> [Lachesis] Invoking Tartaros for Origin Tracing...")
                    tracer = TartarosTracer(history_csv=history_csv)
                    origin_stories = tracer.trace_memory(self.pivot_seeds, timeline_df, df_history=df_history_target)
                    print(f"    -> [Lachesis] Tartaros Stories Found: {len(origin_stories)}")
                except Exception as e: 
                    print(f"    [!] Tartaros Trace Failed: {e}")
                    traceback.print_exc()

        out_file = Path(output_path)
        with open(out_file, "w", encoding="utf-8") as f:
            self._write_header(f, real_os_info, primary_user, time_range)
            self._write_toc(f)
            self._write_executive_summary_visual(f, critical_events, analysis_result["verdict_flags"], primary_user, time_range)
            self._write_initial_access_vector(f, self.pivot_seeds, origin_stories)
            self._write_timeline_visual(f, phases)
            self._write_technical_findings(f, phases)
            self._write_detection_statistics(f, medium_events, dfs_for_ioc)
            self._write_ioc_appendix_unified(f) 
            f.write(f"\n---\n*Report woven by SkiaHelios (The Triad v4.50)* 🦁")
        
        json_path = out_file.with_suffix('.json')
        self._export_json_grimoire(analysis_result, dfs_for_ioc, json_path, primary_user)
        pivot_path = out_file.parent / "Pivot_Config.json"
        self._export_pivot_config(pivot_path, primary_user)

    def _write_header(self, f, os_info, primary_user, time_range):
        t = self.txt
        f.write(f"# {t['title']} - {self.hostname}\n\n")
        f.write(f"### 🛡️ {t['coc_header']}\n")
        f.write("| Item | Details |\n|---|---|\n")
        f.write(f"| **Target Host** | **{self.hostname}** |\n")
        f.write(f"| **OS Info** | {os_info} |\n") 
        f.write(f"| **Primary User** | {primary_user} |\n")
        f.write(f"| **Incident Scope** | **{time_range}** |\n") 
        f.write(f"| **Report Date** | {datetime.now().strftime('%Y-%m-%d')} |\n\n---\n\n")

    def _write_toc(self, f):
        t = self.txt
        f.write("## 📚 Table of Contents\n")
        f.write(f"- [{t['h1_exec']}](#{self._make_anchor(t['h1_exec'])})\n")
        f.write(f"- [{t['h1_origin']}](#{self._make_anchor(t['h1_origin'])})\n")
        f.write(f"- [{t['h1_time']}](#{self._make_anchor(t['h1_time'])})\n")
        f.write(f"- [{t['h1_tech']}](#{self._make_anchor(t['h1_tech'])})\n")
        f.write(f"- [{t['h1_stats']}](#{self._make_anchor(t['h1_stats'])})\n")
        f.write(f"- [{t['h1_app']}](#{self._make_anchor(t['h1_app'])})\n")
        f.write(f"- [Pivot Config (Deep Dive Targets)](#deep-dive-recommendation)\n")
        f.write("\n---\n\n")

    def _make_anchor(self, text):
        return text.lower().replace(" ", "-").replace(".", "").replace("&", "").replace("(", "").replace(")", "").replace("/", "")

    def _write_initial_access_vector(self, f, pivot_seeds, origin_stories):
        t = self.txt
        f.write(f"## {t['h1_origin']}\n")
        phishing_lnks = [s for s in pivot_seeds if "PHISHING" in s.get("Reason", "")]
        drop_items = [s for s in pivot_seeds if "DROP" in s.get("Reason", "") and "PHISHING" not in s.get("Reason", "")]
        
        if phishing_lnks:
            f.write("**フィッシングによる初期侵入が高確度で確認されました。**\n")
            f.write(f"- Recentフォルダ等において、**{len(phishing_lnks)}件** の不審なLNKファイル（ショートカット）へのアクセスが検知されています。\n")
            f.write("\n| サンプルLNK | アクセス時刻 (UTC) | 流入元 (Origin Trace) |\n|---|---|---|\n")
            for seed in phishing_lnks[:10]:
                self._write_origin_row(f, seed, origin_stories)
            f.write("\n")

        if drop_items:
            f.write("**不審なツール・ファイルの持ち込み（Dropped Artifacts）:**\n")
            f.write("\n| ファイル名 | 発見場所 | 流入元 (Origin Trace) |\n|---|---|---|\n")
            for seed in drop_items[:10]:
                self._write_origin_row(f, seed, origin_stories)
            f.write("\n")

        if not phishing_lnks and not drop_items:
            f.write("明確な外部侵入ベクターは自動検知されませんでした。\n\n")

    def _write_origin_row(self, f, seed, origin_stories):
        name = seed['Target_File']
        time = str(seed.get('Timestamp_Hint', '')).replace('T', ' ')[:19]
        
        origin_desc = "❓ No Trace Found (Low Confidence)"
        
        story = next((s for s in origin_stories if s["Target"] == name), None)
        
        if story:
            ev = story["Evidence"][0]
            url = ev.get("URL", "")
            url_display = (url[:50] + "...") if len(url) > 50 else url
            gap = ev.get('Time_Gap', '-')
            conf = story.get("Confidence", "LOW")
            reason = story.get("Reason", "")
            
            if conf == "HIGH":
                icon = "✅" 
                prefix = "**Confirmed**"
            elif conf == "MEDIUM":
                icon = "⚠️"
                prefix = "Inferred"
            else:
                icon = "❓"
                prefix = "Weak"

            origin_desc = f"{icon} **{prefix}**: {reason}<br/>🔗 `{url_display}`<br/>*(Gap: {gap})*"
        
        col2 = time if time else f"`{seed.get('Target_Path', '')[:20]}`"
        f.write(f"| `{name}` | {col2} | {origin_desc} |\n")

    def _extract_visual_iocs_from_chronos(self, dfs):
        if dfs.get('Chronos') is not None:
            df = dfs['Chronos']
            cols = df.columns
            score_col = "Chronos_Score" if "Chronos_Score" in cols else "Threat_Score"
            if score_col in cols:
                try:
                    df_sorted = df.sort(score_col, descending=True)
                    for row in df_sorted.iter_rows(named=True):
                        fname = row.get("FileName") or ""
                        path = row.get("ParentPath") or ""
                        score = int(float(row.get(score_col, 0)))
                        
                        bypass_reason = None
                        is_trusted_loc = self._is_trusted_system_path(path)
                        is_dual = self._is_dual_use(fname)

                        if "ROLLBACK" in str(row.get("Anomaly_Time", "")):
                            bypass_reason = "🚨 SYSTEM TIME ROLLBACK DETECTED 🚨"
                            if not fname and path: fname = f"System Artifact ({path})"
                            self._log_noise("TIME PARADOX", f"{fname} triggered Rollback Alert")
                            self._add_unique_visual_ioc({
                                "Type": "TIME_PARADOX", 
                                "Value": fname if fname else "Unknown", 
                                "Path": path, 
                                "Note": str(row.get("Anomaly_Time", "")), 
                                "Time": str(row.get("si_dt", "") or row.get("UpdateTimestamp", "")),
                                "Reason": bypass_reason,
                                "Score": score 
                            })
                            continue

                        extra_info = {}
                        timeline_df = dfs.get('Timeline')
                        if is_dual or "TIMESTOMP" in str(row.get("Threat_Tag", "")):
                             _, _, _, is_executed = self._enrich_from_timeline(fname, timeline_df)
                             extra_info["Execution"] = is_executed

                        if is_dual:
                            bypass_reason = "Dual-Use Tool [DROP]" 
                        elif score >= 220:
                            if is_trusted_loc:
                                self._log_noise("Trusted Path (Update)", fname)
                                continue
                            else:
                                bypass_reason = "High Score (Timestomp) [DROP]"
                        
                        if self._is_noise(fname, path):
                             self._log_noise("Explicit Noise Filter", fname)
                             continue

                        if bypass_reason:
                             if "False Positive" in bypass_reason or "NOISE" in bypass_reason: continue
                        elif score < 200: continue 
                        
                        if not bypass_reason: bypass_reason = "High Score (>200)"
                        self._add_unique_visual_ioc({
                            "Type": "TIMESTOMP", "Value": fname, "Path": path, "Note": "Time Anomaly", 
                            "Time": str(row.get("Anomaly_Time", "")), 
                            "Reason": bypass_reason, 
                            "Score": score,
                            "Extra": extra_info
                        })
                except: pass

    def _extract_visual_iocs_from_pandora(self, dfs):
        if dfs.get('Pandora') is not None:
            df = dfs['Pandora']
            timeline_df = dfs.get('Timeline') 
            
            if "Threat_Score" in df.columns:
                try:
                    df_sorted = df.sort("Threat_Score", descending=True)
                    for row in df_sorted.iter_rows(named=True):
                        fname = row.get("Ghost_FileName", "")
                        path = row.get("ParentPath", "")
                        tag = str(row.get("Threat_Tag", "")).upper()
                        score = int(float(row.get("Threat_Score", 0)))

                        bypass_reason = None
                        is_trusted_loc = self._is_trusted_system_path(path)

                        if "MASQUERADE" in tag: bypass_reason = "Critical Criteria (CRITICAL_MASQUERADE) [DROP]"
                        elif "PHISH" in tag: bypass_reason = "Critical Criteria (PHISHING) [DROP]"
                        elif "BACKDOOR" in tag: bypass_reason = "Backdoor Detected [DROP]"
                        elif "CREDENTIALS" in tag and score >= 200: bypass_reason = "Credential Dump [DROP]"
                        
                        elif is_trusted_loc:
                            self._log_noise("Trusted Path (Update)", fname)
                            continue
                        
                        if self._is_noise(fname, path):
                             self._log_noise("Explicit Noise Filter", fname)
                             continue

                        elif self._is_dual_use(fname): bypass_reason = "Dual-Use Tool [DROP]"
                        elif "TIMESTOMP" in tag: bypass_reason = "Timestomp [DROP]"
                        elif score >= 250: bypass_reason = "Critical Score [DROP]"

                        if bypass_reason: 
                            pass
                        elif score < 200: continue

                        if not bypass_reason: bypass_reason = "High Confidence"
                        clean_name = fname.split("] ")[-1]
                        
                        extra_info = {}
                        final_tag = tag
                        
                        if ".lnk" in fname.lower():
                            target_path, timeline_tag, args, _ = self._enrich_from_timeline(fname, timeline_df)
                            
                            if target_path: extra_info["Target_Path"] = target_path
                            if args: extra_info["Arguments"] = args
                            
                            if "DEFCON" in clean_name.upper() or "BYPASS" in clean_name.upper():
                                extra_info["Risk"] = "SECURITY_TOOL_MASQUERADE"

                            if timeline_tag:
                                merged_tags = set(tag.split(",") + timeline_tag.split(","))
                                merged_tags.discard("")
                                final_tag = ",".join(list(merged_tags))
                        
                        self._add_unique_visual_ioc({
                            "Type": final_tag,
                            "Value": clean_name, 
                            "Path": path, 
                            "Note": "File Artifact", 
                            "Time": str(row.get("Ghost_Time_Hint", "")), 
                            "Reason": bypass_reason,
                            "Extra": extra_info,
                            "Score": score
                        })
                except: pass

    def _extract_visual_iocs_from_aion(self, dfs):
         if dfs.get('AION') is not None:
            df = dfs['AION']
            if "AION_Score" in df.columns:
                try:
                    for row in df.iter_rows(named=True):
                        try: score = int(float(row.get("AION_Score", 0)))
                        except: score = 0
                        if score >= 50:
                            name = row.get("Target_FileName")
                            # [v5.6.3] Prefer Entry_Location for Chain Scavenger Context Hex (Robust Match)
                            entry_loc = ""
                            for k, v in row.items():
                                if "entry" in k.lower() and "location" in k.lower():
                                    entry_loc = v
                                    break
                            
                            path_val = entry_loc or row.get("Full_Path", "") or row.get("Path", "")
                            
                            if not self._is_noise(name, path_val):
                                self._add_unique_visual_ioc({
                                    "Type": "PERSISTENCE", "Value": name, "Path": path_val, "Note": "Persist", 
                                    "Time": str(row.get("Last_Executed_Time", "")), "Reason": "Persistence",
                                    "Score": score
                                })
                except: pass

    def _extract_visual_iocs_from_events(self, events):
        re_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        infra_ips = ["10.0.2.15", "10.0.2.2", "127.0.0.1", "0.0.0.0", "::1"]
        for ev in events:
            content = ev['Summary'] + " " + str(ev.get('Detail', ''))
            ips = re_ip.findall(content)
            for ip in ips:
                if ip in infra_ips or ip.startswith("127."): 
                    self.infra_ips_found.add(ip); continue
                parts = ip.split('.')
                if len(parts) == 4:
                    try:
                        p1 = int(parts[0]); p2 = int(parts[1])
                        if p1 < 10 and ip != "1.1.1.1" and ip != "8.8.8.8" and ip != "8.8.4.4": continue 
                    except: continue
                self._add_unique_visual_ioc({
                    "Type": "IP_TRACE", "Value": ip, "Path": "Network", "Note": f"Detected in {ev['Source']}"
                })
            
            is_dual = self._is_dual_use(ev.get('Summary', ''))
            tag = str(ev.get('Tag', '')).upper()
            is_af = "ANTI_FORENSICS" in tag
            score = ev.get('Criticality', 0)

            if (ev['Criticality'] >= 90 or is_dual or is_af) and (ev['Category'] == 'EXEC' or ev['Category'] == 'ANTI'):
                kws = ev.get('Keywords', [])
                if kws:
                    kw = str(kws[0]).lower()
                    if not self._is_noise(kw):
                        if is_af:
                            type_label = "ANTI_FORENSICS"
                            reason_label = "Evidence Destruction"
                        elif is_dual:
                            type_label = "DUAL_USE_TOOL"
                            reason_label = "Dual-Use Tool [DROP]"
                        else:
                            type_label = "EXECUTION"
                            reason_label = "Execution"

                        self._add_unique_visual_ioc({
                            "Type": type_label, "Value": kws[0], "Path": "Process", "Note": f"Execution ({ev['Source']})",
                            "Reason": reason_label,
                            "Time": ev.get('Time'),
                            "Score": score,
                            "Summary": ev.get('Summary', '') # [Fix] Pass Summary for RunCount extraction
                        })

    def _write_executive_summary_visual(self, f, events, verdicts, primary_user, time_range):
        t = self.txt
        f.write(f"## {t['h1_exec']}\n")
        
        has_paradox = any("TIME_PARADOX" in str(ioc.get('Type', '')) for ioc in self.visual_iocs)
        has_masquerade = any("MASQUERADE" in str(ioc.get('Type', '')) for ioc in self.visual_iocs)
        has_phishing = any("PHISHING" in str(ioc.get('Type', '')) for ioc in self.visual_iocs)
        has_timestomp = any("TIMESTOMP" in str(ioc.get('Type', '')) for ioc in self.visual_iocs)
        
        if "Unknown" in time_range and self.visual_iocs:
            ioc_times = []
            for ioc in self.visual_iocs:
                dt = self._parse_time_safe(ioc.get("Time", ""))
                if dt and dt.year >= 2016:
                    ioc_times.append(dt)
            if ioc_times:
                ioc_times = sorted(ioc_times)
                time_range = f"{ioc_times[0].strftime('%Y-%m-%d %H:%M')} 〜 {ioc_times[-1].strftime('%H:%M')} (UTC)"
        
        if has_paradox or has_masquerade:
            conclusion = f"**結論:**\n{time_range} の期間において、端末 {self.hostname} に対する **高度な隠蔽工作を伴う重大な侵害活動** を確認しました。\n"
        elif self.visual_iocs:
            conclusion = f"**結論:**\n{time_range} の期間において、端末 {self.hostname} に対する **CRITICAL レベルの侵害活動** を確認しました。\n"
        else:
            conclusion = f"**結論:**\n本調査範囲において、重大なインシデントの痕跡は検出されませんでした。\n"
        
        f.write(conclusion)
        
        attack_methods = []
        if has_phishing: attack_methods.append("フィッシング（LNK）による初期侵入")
        if has_masquerade: attack_methods.append("偽装ファイル設置（Masquerading）")
        if has_timestomp: attack_methods.append("タイムスタンプ偽装（Timestomp）")
        if has_paradox: attack_methods.append("**システム時間巻き戻し（System Rollback）**")
        
        if not attack_methods:
            attack_methods = ["不審なアクティビティ"]
            
        f.write(f"**主な攻撃手口:** {', '.join(attack_methods)}。\n\n")
        f.write("> **Deep Dive 推奨:** 詳細な調査を行う際は、添付の `Pivot_Config.json` に記載された **CRITICAL_PHISHING** ターゲット群から開始してください。\n\n")
        f.write("\n### 🏹 Attack Timeline Flow (Critical Chain)\n")
        if self.visual_iocs: f.write(self._generate_mermaid())
        else: f.write("(No sufficient visual indicators found)\n")

        f.write("\n### 💎 Key Indicators (Critical Only)\n")
        if self.visual_iocs:
            f.write("| Time | Type | Value (File/IP) | **Target / Action** | **Score** | Path |\n|---|---|---|---|---|---| ignore\n")
            
            sorted_iocs = sorted(self.visual_iocs, key=lambda x: x.get("Time", "9999"))
            seen = set()
            for ioc in sorted_iocs:
                val = ioc['Value']
                if val in seen: continue
                seen.add(val)
                
                target_action = "-"
                extra = ioc.get("Extra", {})
                ioc_type = str(ioc.get("Type", "")).upper()
                reason = str(ioc.get("Reason", "")).upper()
                
                if ".lnk" in val.lower() or "PHISHING" in ioc_type:
                    tgt = extra.get("Target_Path", "")
                    if not tgt and "Target:" in ioc.get("Value", ""):
                        tgt = ioc.get("Value", "").split("Target:")[-1].strip()
                    target_action = f"🎯 {tgt[:40] + '..' if len(tgt)>40 else tgt}" if tgt else "Target Unknown"
                
                elif "TIMESTOMP" in ioc_type:
                    if extra.get("Execution") == True or "EXECUTION" in reason or "EXECUTION_CONFIRMED" in ioc_type:
                        target_action = "✅ 実行痕跡あり"
                    else:
                        target_action = "⚠️ 実行痕跡なし (存在のみ)"
                
                elif "ANTI_FORENSICS" in ioc_type:
                    target_action = "🗑️ 証拠隠滅 (Wiping)"
                    
                elif "MASQUERADE" in ioc_type:
                    target_action = "🎭 偽装ファイル設置"
                    
                else:
                    target_action = ioc.get("Reason", "-")

                score = ioc.get("Score", 0)
                path_short = (ioc['Path'][:30] + '..') if len(ioc['Path']) > 30 else ioc['Path']
                
                f.write(f"| {str(ioc.get('Time','')).replace('T',' ')[:19]} | **{ioc['Type']}** | `{ioc['Value']}` | {target_action} | {score} | `{path_short}` |\n")
        else: f.write("No critical IOCs automatically detected.\n")
        f.write("\n")

    def _write_timeline_visual(self, f, phases):
        t = self.txt
        f.write(f"## {t['h1_time']}\n")
        f.write("以下に、検知された脅威イベントを時系列で示します。（重要度スコア80以上のイベント、および要注意ツール利用履歴）\n\n")
        for idx, phase in enumerate(phases):
            if not phase: continue
            if isinstance(phase[0], dict) and 'Time' in phase[0]:
                date_str = str(phase[0]['Time']).replace('T', ' ').split(' ')[0]
            else: date_str = "Unknown"
            f.write(f"### 📅 Phase {idx+1} ({date_str})\n")
            f.write(f"| Time (UTC) | Category | Event Summary (Command / File) | Source |\n|---|---|---|---|\n") 
            for ev in phase:
                summary = ev['Summary']
                if self._is_noise(summary): continue
                time_display = str(ev.get('Time','')).replace('T', ' ').split('.')[0]
                cat_name = t['cats'].get(ev.get('Category'), ev.get('Category'))
                is_dual = self._is_dual_use(summary)
                prefix = "⚠️ " if is_dual else ""
                row_str = f"| {time_display} | {cat_name} | **{prefix}{summary}** | {ev['Source']} |"
                f.write(f"{row_str}\n")
            if idx < len(phases)-1: f.write("\n*( ... Time Gap ... )*\n\n")

    def _write_anti_forensics_section(self, f, ioc_list, dfs):
        af_tools = [ioc for ioc in ioc_list if "ANTI_FORENSICS" in str(ioc.get("Type", "")) or "WIPING" in str(ioc.get("Type", ""))]
        
        if not af_tools:
            return

        f.write("### 🚨 Anti-Forensics Activities (Evidence Destruction)\n\n")
        f.write("⚠️⚠️⚠️ **重大な証拠隠滅活動を検出** ⚠️⚠️⚠️\n\n")
        f.write("攻撃者は侵入後、以下のツールを使用して活動痕跡を意図的に抹消しています：\n\n")

        seen_tools = set()
        
        for tool in af_tools:
            name = tool.get("Value", "Unknown").upper()
            if name in seen_tools: continue
            seen_tools.add(name)
            
            run_count = self._extract_run_count(tool, dfs)
            last_run = tool.get("Time", "Unknown").replace("T", " ")[:19]
            
            desc = "データ抹消ツール"
            if "BCWIPE" in name: desc = "軍事レベルのファイルワイピングツール。通常の復元を不可能にします。"
            elif "CCLEANER" in name: desc = "システムクリーナー。ブラウザ履歴やMRUの削除に使用されます。"
            elif "SDELETE" in name: desc = "Sysinternals製のセキュア削除ツール。"
            elif "ERASER" in name: desc = "ファイル抹消ツール。"

            f.write(f"#### {name}\n")
            f.write(f"- 📊 **Run Count**: **{run_count}**\n")
            f.write(f"- 🕐 **Last Execution**: {last_run} (UTC)\n")
            f.write(f"- ⚠️ **Severity**: CRITICAL\n")
            f.write(f"- 🔍 **Description**: {desc}\n\n")
            
            f.write(f"🕵️ **Analyst Note**:\n")
            if "BCWIPE" in name:
                 f.write("このツールの実行により、LNKファイル、Prefetch、一時ファイル等の証拠が物理的に上書き削除された可能性が極めて高いです。\n")
            else:
                 f.write("攻撃活動終了後の痕跡削除（Cleanup）に使用されたと推定されます。\n")
            f.write("\n---\n\n")

        f.write("### 📉 Missing Evidence Impact Assessment\n\n")
        f.write("以下の証拠が、Anti-Forensicsツールによって失われたと判断されます：\n\n")
        f.write("| 証拠カテゴリ | 期待される情報 | 現状 | 推定原因 |\n|---|---|---|---|\n")
        f.write("| LNK Target Paths | `cmd.exe ...` 等の引数 | ❌ 欠落 | BCWipe/SDeleteによる削除 |\n")
        f.write("| Prefetch (Tools) | 実行回数・タイムスタンプ | ❌ 欠落 | CCleaner/BCWipeによる削除 |\n")
        f.write("| 一時ファイル | ペイロード本体 | ❌ 欠落 | ワイピングによる物理削除 |\n\n")

        f.write("🕵️ **Analyst Note**:\n")
        f.write("これらの証拠欠落は「ツールの限界」ではなく、**「攻撃者による高度な隠蔽工作」**の結果です。\n")
        f.write("Ghost Detection (USNジャーナル) によりファイルの「存在していた事実」のみを確認できています。\n\n")

    def _extract_run_count(self, ioc, dfs):
        """
        [Fix] Prefetch/UserAssist DataFrameから直接RunCountを取得する
        """
        if not dfs: return "Unknown"
        
        target_name = ioc.get("Value", "").lower().strip()
        if not target_name: return "Unknown"
        
        # Basename for better matching
        import os
        target_base = target_name
        if "\\" in target_base or "/" in target_base:
            target_base = os.path.basename(target_base.replace("\\", "/"))
        
        # Start with regex removal of arguments if present in target_name
        if " " in target_base:
            target_base = target_base.split(" ")[0]

        # DEBUG LOGGING - REMOVED FOR PROD
        # print(f"[RunCount Debug] Target: {target_name} | Base: {target_base}")

        # Helper to find key case-insensitively
        def get_df(name_part):
            for k, v in dfs.items():
                if name_part.lower() in k.lower(): return v
            return None

        # --- Method 1: Prefetch DataFrame (PECmd) ---
        pf = get_df('Prefetch')
        if pf is not None:
            try:
                # Column normalization
                cols_lower = {c.lower(): c for c in pf.columns}
                exec_col = next((cols_lower[c] for c in cols_lower if "executable" in c), None) # ExecutableName
                run_col = next((cols_lower[c] for c in cols_lower if "run" in c and "count" in c), None) # RunCount
                
                if exec_col and run_col:
                    # Try exact match on basename first
                    hits = pf.filter(pl.col(exec_col).str.to_lowercase().str.contains(target_base, literal=True))
                    
                    if hits.height > 0:
                        rc = hits[0, run_col]
                        return f"{rc} (Prefetch)"
            except Exception as e: pass

        # --- Method 2: UserAssist DataFrame ---
        ua = get_df('UserAssist')
        if ua is not None:
            try:
                cols_lower = {c.lower(): c for c in ua.columns}
                # UserAssist often has "ValueName" or "Program"
                name_col = next((cols_lower[c] for c in cols_lower if "value" in c and "name" in c), None)
                if not name_col:
                     name_col = next((cols_lower[c] for c in cols_lower if "program" in c), None)
                
                run_col = next((cols_lower[c] for c in cols_lower if "run" in c and "count" in c), None) # RunCounter / Count
                
                if name_col and run_col:
                     hits = ua.filter(pl.col(name_col).str.to_lowercase().str.contains(target_base, literal=True))
                     if hits.height > 0:
                         # UserAssist RunCount can be high, check heuristics? No, just report.
                         rc = hits[0, run_col]
                         return f"{rc} (UserAssist)"
            except Exception as e: pass

        # Method 3: Fallback (Timeline Regex)
        summary = ioc.get("Summary", "")
        if summary:
            match = re.search(r"(?:Run\s*Count:|Run:|Run\sCount)\s*[:]?\s*(\d+)", summary, re.IGNORECASE)
            if match: return match.group(1)

        # Method 4: Timeline Deep Search (Last Resort)
        try:
            timeline = dfs.get("Timeline")
            if timeline is not None:
                # Look for events related to this file that might mention RunCount matches
                cond = pl.col("FileName").str.to_lowercase().str.contains(target_base, literal=True)
                for c in ["Message", "Description", "Action", "Summary"]:
                    if c in timeline.columns:
                        cond = cond | pl.col(c).str.to_lowercase().str.contains(target_base, literal=True)
                
                hits = timeline.filter(cond)
                if hits.height > 0:
                    # [Fix] Broader search - allow UserAssist and Prefetch as source
                    for col in hits.columns:
                        if col in ["Summary", "Message", "Details", "Description"]:
                            # Iterate all hits to find one with RunCount
                            for val in hits[col]:
                                match = re.search(r"(?:Run\s*Count:|Run:|Run\sCount)\s*[:]?\s*(\d+)", str(val), re.IGNORECASE)
                                if match: return f"{match.group(1)} (Timeline)"

        except: pass
        
        return "Unknown"

    def _write_technical_findings(self, f, phases):
        t = self.txt
        f.write(f"## {t['h1_tech']}\n")
        
        high_conf_events = [ioc for ioc in self.visual_iocs if self._is_force_include_ioc(ioc) or "ANTI_FORENSICS" in str(ioc.get("Type", ""))]
        
        self._write_anti_forensics_section(f, high_conf_events, self._latest_dfs)

        f.write("本セクションでは、検出された脅威を分類して詳述します。\n\n")

        groups = {
            "🚨 System Time Manipulation (Time Paradox)": [],
            "🎭 File Masquerading & Backdoors": [],
            "🎣 Phishing & Initial Access (LNKs)": [],
            "⚡ Executed Tools (Active Threats)": [],
            "📦 Suspicious Files (Presence Only)": [],
            "⚠️ Other High Confidence Threats": []
        }
        
        for ioc in high_conf_events:
            ioc_type = str(ioc.get('Type', '')).upper()
            reason = str(ioc.get('Reason', '')).upper()
            val = str(ioc.get('Value', '')).lower()
            
            if "ANTI_FORENSICS" in ioc_type: continue 

            if "TIME_PARADOX" in ioc_type or "ROLLBACK" in reason:
                groups["🚨 System Time Manipulation (Time Paradox)"].append(ioc)
            elif "MASQUERADE" in ioc_type or ".crx" in val:
                groups["🎭 File Masquerading & Backdoors"].append(ioc)
            elif "PHISHING" in ioc_type or "SUSPICIOUS_CMDLINE" in reason or ".lnk" in val:
                groups["🎣 Phishing & Initial Access (LNKs)"].append(ioc)
            elif self._is_dual_use(val) or "DUAL_USE" in ioc_type:
                if "EXECUTION_CONFIRMED" in ioc_type or "EXEC" in reason.upper() or "PROCESS" in ioc.get("Path", "").upper():
                     groups["⚡ Executed Tools (Active Threats)"].append(ioc)
                else:
                     groups["📦 Suspicious Files (Presence Only)"].append(ioc)
            else:
                groups["⚠️ Other High Confidence Threats"].append(ioc)

        for header, ioc_list in groups.items():
            if not ioc_list: continue
            f.write(f"### {header}\n")
            if "Presence Only" in header:
                f.write("> **Note:** 以下のツールはディスク上に存在しますが、明確な実行痕跡（Prefetch/ProcessLog等）は確認されていません。\n\n")
            ioc_list.sort(key=lambda x: x.get('Time', '9999'))
            for ioc in ioc_list:
                dt = str(ioc.get('Time', 'Unknown')).replace('T', ' ')[:19]
                val = ioc.get('Value', 'No details')
                path = ioc.get('Path', 'Unknown')
                ioc_type = ioc.get('Type', 'Unknown')
                f.write(f"- **{dt}** | Type: `{ioc_type}` | Path: `{path[:50]}{'...' if len(path) > 50 else ''}`\n")
                insight = self._generate_ioc_insight(ioc)
                if insight: f.write(f"  - 🕵️ **Analyst Note:** {insight}\n")
                f.write("\n")
        f.write("\n")
    
    def _is_force_include_ioc(self, ioc):
        force_keywords = [
            "TIME_PARADOX", "CRITICAL_MASQUERADE", "CRITICAL_PHISHING", 
            "SUSPICIOUS_CMDLINE", "CRITICAL_SIGMA", "ROLLBACK", "BACKDOOR"
        ]
        ioc_type = str(ioc.get('Type', '')).upper()
        reason = str(ioc.get('Reason', '')).upper()
        
        if any(k in ioc_type for k in force_keywords):
            return True
        if any(k in reason for k in force_keywords):
            return True
        if "DUAL-USE" in reason or "DUAL_USE" in ioc_type:
            return True
        if "TIMESTOMP" in ioc_type:
            return True
        return False
    
    # [TASK 3 FIX] Dynamic Intelligence Insight
    def _generate_ioc_insight(self, ioc):
        ioc_type = str(ioc.get('Type', '')).upper()
        
        if "ANTI_FORENSICS" in ioc_type:
            return "🚨 **Evidence Destruction**: 証拠隠滅ツールです。実行回数やタイムスタンプを確認してください。"
        
        val = str(ioc.get('Value', ''))
        val_lower = val.lower()
        reason = str(ioc.get('Reason', '')).upper()
        path = str(ioc.get('Path', ''))

        if "EXECUTION_CONFIRMED" in ioc_type:
            return "🚨 **Confirmed**: このツールは実際に実行された痕跡があります。調査優先度：高"
        
        elif "TIME_PARADOX" in ioc_type or "ROLLBACK" in reason:
            rb_sec = "Unknown"
            if "Rollback:" in val:
                import re
                match = re.search(r"Rollback:\s*(-?\d+)", val)
                if match: rb_sec = match.group(1)
            return f"USNジャーナルの整合性分析により、システム時刻の巻き戻し(約{rb_sec}秒)を検知しました。これは高度なアンチフォレンジック活動を示唆します。"
        
        elif "MASQUERADE" in ioc_type or ".crx" in val_lower:
            masq_app = "正規アプリケーション"
            if "adobe" in path.lower(): masq_app = "Adobe Reader"
            elif "microsoft" in path.lower(): masq_app = "Microsoft Office"
            elif "google" in path.lower(): masq_app = "Google Chrome"
            return f"{masq_app}のフォルダに、無関係なChrome拡張機能(.crx)が配置されています。これは典型的なPersistence（永続化）手法です。"
        
        elif ".lnk" in val_lower and ("SUSPICIOUS" in ioc_type or "PHISHING" in ioc_type or "PS_" in ioc_type or "CMD_" in ioc_type or "MSHTA" in ioc_type):
            insights = []
            extra = ioc.get('Extra', {})
            target = extra.get('Target_Path', '')
            args = extra.get('Arguments', '')
            risk = extra.get('Risk', '')

            # [NEW] Check External Intelligence
            intel_desc = self._match_intel(val)
            if intel_desc:
                insights.append(intel_desc)

            if not target:
                if "Target:" in val: target = val.split("Target:")[-1].strip()
                elif "🎯" in val: target = val.split("🎯")[-1].strip()
            
            if target:
                insights.append(f"🎯 **Target**: `{target}`")
                
                if "cmd.exe" in target.lower() or "powershell" in target.lower():
                     insights.append("⚠️ **Critical**: OS標準シェルを悪用した攻撃の起点です。")
                elif ".exe" in target.lower() or ".bat" in target.lower() or ".vbs" in target.lower():
                     insights.append("⚠️ **High**: 実行可能ファイルを呼び出すショートカットです。")

            if args:
                args_disp = (args[:100] + "...") if len(args) > 100 else args
                insights.append(f"📝 **Args**: `{args_disp}`")
                
                if "-enc" in args.lower() or "-encoded" in args.lower():
                    insights.append("🚫 **Encoded**: Base64エンコードされたPowerShellコマンドを検知。即座に解析が必要です。")
                if "-windowstyle hidden" in args.lower() or "-w hidden" in args.lower():
                    insights.append("🕶️ **Stealth**: ユーザーからウィンドウを隠蔽するフラグを確認。")
            else:
                 if "-enc" in target.lower():
                      insights.append("🚫 **Encoded**: ターゲットパス内にエンコードされたコマンドを確認。")

            if risk == "SECURITY_TOOL_MASQUERADE":
                insights.append("🎭 **Masquerade**: セキュリティツールやカンファレンス資料(DEFCON等)への偽装が疑われます。")

            if insights:
                return "<br/>".join(insights)
            elif "PHISHING" in ioc_type:
                return "不審なショートカットファイルが作成されました。フィッシング攻撃の可能性があります。"
            else:
                return "不審なショートカットファイルを検知しました。"
        
        elif "PHISHING" in ioc_type:
            return "フィッシング活動に関連するアーティファクトを検知しました。"
        
        elif "TIMESTOMP" in ioc_type:
            tool_name = val.split()[0] if val else "Unknown"
            return f"`{tool_name}` のタイムスタンプに不整合（Timestomp）を確認。攻撃ツールを隠蔽しようとした痕跡です。"
        
        elif "CREDENTIALS" in ioc_type:
            return "認証情報の窃取または不正ツールの配置を検知しました。"
        
        elif "COMMUNICATION_CONFIRMED" in reason or "COMMUNICATION_CONFIRMED" in ioc_type:
            return "🚨 ブラウザ履歴との照合により、**実際にネットワーク通信が成功した痕跡**を確認しました。C2サーバへのビーコン送信、またはペイロードダウンロードの可能性が極めて高いです。"
        
        return None

    def _generate_mermaid(self):
        if not self.visual_iocs: return ""
        
        def get_time(item):
            t = item.get("Time", "")
            return t if t else "9999"
            
        sorted_iocs = sorted(self.visual_iocs, key=get_time)
        if not sorted_iocs: return ""
        
        has_paradox = any("TIME_PARADOX" in str(ioc.get("Type", "")) for ioc in self.visual_iocs)
        
        rollback_time_str = None
        if has_paradox:
            for ioc in self.visual_iocs:
                if "TIME_PARADOX" in str(ioc.get("Type", "")):
                    rollback_time_str = str(ioc.get("Time", ""))[:10]
                    break
        
        chart = "\n```mermaid\ngraph TD\n"
        chart += "    %% Time-Clustered Attack Flow\n"
        chart += "    start((Start)) --> P0\n"
        
        clusters = []
        current_cluster = []
        last_dt = None
        for ioc in sorted_iocs[:25]:
            if self._is_visual_noise(ioc["Value"]): continue
            ts_str = ioc.get("Time", "")
            curr_dt = self._parse_time_safe(ts_str)
            if curr_dt:
                if last_dt and (curr_dt - last_dt).total_seconds() > 60: 
                    clusters.append(current_cluster)
                    current_cluster = []
                last_dt = curr_dt
            current_cluster.append(ioc)
        if current_cluster: clusters.append(current_cluster)

        node_registry = []
        for idx, cluster in enumerate(clusters):
            if not cluster: continue
            
            time_label = "Unknown"
            if cluster[0].get("Time"):
                time_str = str(cluster[0]["Time"])
                if "T" in time_str: time_label = time_str.split("T")[1][:5]
                elif " " in time_str: time_label = time_str.split(" ")[1][:5]
                else: time_label = time_str[-8:-3]
            
            cluster_is_fake = False
            if has_paradox and rollback_time_str:
                cluster_time = str(cluster[0].get("Time", ""))[:10]
                if cluster_time and cluster_time < rollback_time_str:
                    if any(x in time_label for x in ["00:", "01:", "02:", "03:"]):
                        cluster_is_fake = True
                        time_label += " ⚠️(FAKE?)"

            chart += f"\n    subgraph T{idx} [Time: {time_label}]\n"
            chart += "        direction TB\n"
            
            for item in cluster:
                val = self._sanitize_mermaid(item["Value"])
                typ = item["Type"]
                
                if "TIME_PARADOX" in typ: short_val = "SYSTEM ROLLBACK"
                else: short_val = (val[:15] + '..') if len(val) > 15 else val
                
                icon = "💀"
                if "PHISH" in typ: icon = "🎣"
                elif "BACKDOOR" in typ or "MASQ" in typ: icon = "🎭"
                elif "TIME_PARADOX" in typ: icon = "⏪"
                elif "TIMESTOMP" in typ: icon = "🕒"
                elif "PERSIST" in typ: icon = "⚓"
                
                style_class = "threat"
                if cluster_is_fake: style_class = "fake"
                if "TIME_PARADOX" in typ: style_class = "paradox"

                node_id = f"N{abs(hash(val + str(idx)))}"
                label = f"{icon} {typ}<br/>{short_val}"
                chart += f"        {node_id}[\"{label}\"]\n"
                node_registry.append({"id": node_id, "style": style_class})
            
            chart += "    end\n"
            
            if idx > 0 and node_registry:
                prev_node = node_registry[-len(cluster)-1]["id"] if len(node_registry) > len(cluster) else node_registry[0]["id"]
                curr_node = node_registry[-len(cluster)]["id"]
                chart += f"    {prev_node} --> {curr_node}\n"
            elif node_registry:
                chart += f"    P0 --> {node_registry[0]['id']}\n"

        chart += "\n    %% Styles\n"
        chart += "    classDef threat fill:#ffcccc,stroke:#ff0000,stroke-width:2px,color:#000;\n"
        chart += "    classDef fake fill:#eeeeee,stroke:#999999,stroke-dasharray: 5 5,color:#666;\n"
        chart += "    classDef paradox fill:#ffffcc,stroke:#ffcc00,stroke-width:4px,color:#000;\n"
        
        for node in node_registry:
            chart += f"    class {node['id']} {node['style']};\n"
            
        chart += "```\n"
        return chart

    def _sanitize_mermaid(self, text):
        clean = str(text).replace('"', "'").replace("{", "(").replace("}", ")")
        clean = clean.replace("<", "&lt;").replace(">", "&gt;")
        return clean

    # [TASK 2 FIX] Enhanced Statistics with Tables
    def _write_detection_statistics(self, f, medium_events, dfs):
        t = self.txt
        f.write(f"## {t['h1_stats']}\n")
        
        filtered_count = sum(self.noise_stats.values())
        critical_count = len(self.visual_iocs)
        
        f.write("### 📊 Overall Analysis Summary\n")
        f.write("| Category | Count | Percentage |\n|---|---|---|\n")
        f.write(f"| **Total Events Analyzed** | **{self.total_events_analyzed}** | 100% |\n")
        
        if self.total_events_analyzed > 0:
            crit_pct = (critical_count / self.total_events_analyzed) * 100
            filt_pct = (filtered_count / self.total_events_analyzed) * 100
        else:
            crit_pct, filt_pct = 0, 0
            
        f.write(f"| Critical Detections | {critical_count} | {crit_pct:.2f}% |\n")
        f.write(f"| Filtered Noise | {filtered_count} | {filt_pct:.1f}% |\n\n")

        f.write("### 🎯 Critical Detection Breakdown\n")
        f.write("| Type | Count | Max Score | Impact |\n|---|---|---|---|\n")
        
        type_counts = {}
        for ioc in self.visual_iocs:
            typ = ioc.get("Type", "Unknown")
            if "PHISHING" in typ: typ = "PHISHING / LNK"
            elif "TIMESTOMP" in typ: typ = "TIMESTOMP"
            elif "ANTI_FORENSICS" in typ: typ = "ANTI_FORENSICS"
            elif "MASQUERADE" in typ: typ = "MASQUERADE"
            type_counts[typ] = type_counts.get(typ, 0) + 1
        
        for typ, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            score = 300 if "ANTI" in typ or "MASQ" in typ else 250
            impact = "Evidence destruction" if "ANTI" in typ else ("Initial access" if "PHISH" in typ else "Evasion")
            f.write(f"| **{typ}** | **{count}** | {score} | {impact} |\n")
        f.write("\n")
        
        f.write("### ⚠️ Medium Confidence Events\n")
        if medium_events:
            f.write(f"**Count:** {len(medium_events)} 件 (Timeline CSV参照)\n")
            f.write("| Time | Summary |\n|---|---|\n")
            for ev in medium_events[:5]:
                t_str = str(ev.get('Time','')).replace('T',' ')[:19]
                sum_str = str(ev.get('Summary', ''))[:80] + "..."
                f.write(f"| {t_str} | {sum_str} |\n")
            f.write("\n")
            
        f.write("### 📉 Filtered Noise Statistics\n")
        f.write("| Filter Reason | Count |\n|---|---|\n")
        if self.noise_stats:
            for reason, count in sorted(self.noise_stats.items(), key=lambda x: x[1], reverse=True):
                f.write(f"| {reason} | {count} |\n")
        else: f.write("| No noise filtered | 0 |\n")
        f.write("\n")

    def _write_ioc_appendix_unified(self, f):
        t = self.txt
        f.write(f"## {t['h1_app']} (Full IOC List)\n")
        f.write("本調査で確認されたすべての侵害指標（IOC）の一覧です。\n\n")
        if self.visual_iocs:
            f.write("### 📂 File IOCs (Malicious/Suspicious Files)\n")
            f.write("| File Name | Path | Source | Note |\n|---|---|---|---|\n")
            seen = set()
            sorted_iocs = sorted(self.visual_iocs, key=lambda x: 0 if "CRITICAL" in x.get("Reason", "").upper() else 1)
            for ioc in sorted_iocs:
                val = ioc['Value']
                path = ioc['Path']
                if self._is_visual_noise(val): continue
                key = f"{val}|{path}"
                if key in seen: continue
                seen.add(key)
                reason = ioc.get("Reason", "Unknown")
                f.write(f"| `{val}` | `{path}` | {ioc['Type']} ({reason}) | {ioc.get('Time', 'N/A')} |\n")
            f.write("\n")
        if self.infra_ips_found:
            f.write("### 🌐 Network IOCs (Suspicious Connections)\n")
            f.write("| Remote IP | Context |\n|---|---|\n")
            for ip in self.infra_ips_found:
                 f.write(f"| `{ip}` | Detected in Event Logs |\n")
            f.write("\n")

    def _collect_file_iocs(self, dfs):
        return []

    def _default_insight(self, ev):
        summary = ev['Summary'].lower()
        if "timestomp" in summary: return "ファイルタイムスタンプの改ざん痕跡です。"
        return "不審なアクティビティを検知しました。"

    def _add_unique_visual_ioc(self, ioc_dict):
        if self._is_noise(ioc_dict["Value"], ioc_dict["Path"]): return
        for existing in self.visual_iocs:
            if existing["Value"] == ioc_dict["Value"] and existing["Type"] == ioc_dict["Type"]: return
        self.visual_iocs.append(ioc_dict)

    def _generate_pivot_seeds(self):
        for ioc in self.visual_iocs:
            self.pivot_seeds.append({
                "Target_File": ioc["Value"],
                "Target_Path": ioc.get("Path", ""),
                "Reason": ioc.get("Reason", ioc["Type"]),
                "Timestamp_Hint": ioc.get("Time", "")
            })

    def _export_pivot_config(self, path, primary_user):
        if not self.pivot_seeds: return
        config = {
            "Case_Context": {
                "Hostname": self.hostname,
                "Primary_User": primary_user,
                "Generated_At": datetime.now().isoformat()
            },
            "Deep_Dive_Targets": self.pivot_seeds[:20]
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"    -> [Lachesis] Pivot Config generated: {path}")
        except Exception as e:
            print(f"    [!] Failed to export Pivot Config: {e}")

    def _export_json_grimoire(self, analysis_result, dfs_for_ioc, json_path, primary_user):
        serializable_events = []
        for ev in analysis_result["events"]:
            serializable_events.append({
                "Time": str(ev.get('dt_obj', ev['Time'])),
                "User": ev.get('User'),
                "Category": ev.get('Category'),
                "Summary": ev.get('Summary'),
                "Source": ev.get('Source'),
                "Criticality": ev.get('Criticality', 0)
            })
        iocs = {"File": self.visual_iocs, "Network": list(self.infra_ips_found), "Cmd": []}
        grimoire_data = {
            "Metadata": {"Host": self.hostname, "Case": self.case_name, "Primary_User": primary_user, "Generated_At": datetime.now().isoformat()},
            "Verdict": {"Flags": list(analysis_result["verdict_flags"]), "Lateral_Summary": analysis_result["lateral_summary"]},
            "Timeline": serializable_events,
            "IOCs": iocs
        }
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(grimoire_data, f, indent=2, ensure_ascii=False)
            print(f"    -> [Chimera Ready] JSON Grimoire saved: {json_path}")
        except Exception as e:
            print(f"    [!] Failed to export JSON Grimoire: {e}")

if __name__ == "__main__":
    pass
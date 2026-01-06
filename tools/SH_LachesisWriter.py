import pandas as pd
import polars as pl
from datetime import datetime, timedelta
import os
from pathlib import Path
import json
import re
import traceback
from tools.SH_ThemisLoader import ThemisLoader

# [IMPORT] Tartaros for Origin Tracing
try:
    from tools.SH_TartarosTracer import TartarosTracer
except ImportError:
    TartarosTracer = None

# ============================================================
#  SH_LachesisWriter v4.40 [Deep History Hunter]
#  Mission: Weave the Grimoire with accurate Scope & Origins.
#  Update: 
#    1. Recursive Search (rglob) to find CSVs in subfolders (e.g., out/Browser_Artifacts/).
#    2. Fixed missing Executive Summary visual method.
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
        "h1_stats": "5. 検知統計 (Medium Confidence / Filtered Noise)",
        "h1_rec": "6. 結論と推奨事項",
        "h1_app": "7. 添付資料 (Critical IOCs Only)",
        "cats": {"INIT": "初期侵入", "C2": "C2通信", "PERSIST": "永続化", "ANTI": "痕跡隠滅", "EXEC": "実行", "DROP": "ファイル作成", "WEB": "Webアクセス"},
    }
}

class LachesisWriter:
    def __init__(self, lang="jp", hostname="Unknown_Host", case_name="Investigation"):
        self.lang = lang if lang in TEXT_RES else "jp"
        self.txt = TEXT_RES[self.lang]
        self.hostname = hostname
        self.case_name = case_name
        self.visual_iocs = []
        self.infra_ips_found = set()
        self.loader = ThemisLoader(["rules/triage_rules.yaml"])
        self.dual_use_keywords = self.loader.get_dual_use_keywords()
        self.pivot_seeds = []
        self.noise_stats = {}

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
            "inetcache", "tkdata", "thumbcache", "iconcache"
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
        """[v4.41] Deep Disk-based discovery with prioritized paths."""
        if isinstance(base_paths, (str, Path)): base_paths = [base_paths]
        
        search_dirs = [Path(p) for p in base_paths if p]
        
        # [v4.42 Enhancement] Walk UP 3 levels to find sibling folders
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
        
        # [v4.43 Enhancement] Data-Driven Inference from Timeline Source
        inferred_roots = self._infer_source_roots(self._latest_dfs)
        if inferred_roots:
            print(f"    [Lachesis] 🧠 Inferred Source Roots from Data: {[str(r) for r in inferred_roots]}")
            for r in inferred_roots:
                if r.exists() and r not in expanded_dirs: expanded_dirs.append(r)

        patterns = ["*History*.csv", "*Web*.csv", "*Chrome*.csv", "*Browsing*.csv", "*Edge*.csv"]
        print(f"    [Lachesis] 🔍 Scanning {len(expanded_dirs)} locations (Up-then-Down + Data-Inferred) for Browser History...")
        for d in expanded_dirs: print(f"      - Search Scope: {d}")
        
        for d in expanded_dirs:
            if d.is_file(): d = d.parent 
            try:
                for pat in patterns:
                    for f in d.rglob(pat):
                        if "Grimoire" in f.name: continue
                        print(f"    [Lachesis] ✅ Found Candidate: {f}")
                        return str(f.resolve())
            except Exception as e:
                print(f"    [!] Disk scan error in {d}: {e}")
                
        print("    [Lachesis] ❌ No History CSV found on disk.")
        return None



    def _infer_source_roots(self, dfs):
        """[v4.43] Scan Timeline/Pandora for absolute source paths to guess the artifact root."""
        roots = set()
        try:
            # Check Timeline for 'Source' or 'Source_File'
            if dfs and dfs.get('Timeline') is not None:
                df = dfs['Timeline']
                cols = df.columns
                target_col = "Source" if "Source" in cols else ("Source_File" if "Source_File" in cols else None)
                if target_col:
                    # Sample first 20 rows to avoid heavy processing
                    sample = df.head(20)
                    for row in sample.iter_rows(named=True):
                        val = str(row.get(target_col, ""))
                        if ":" in val and ("\\" in val or "/" in val): # Looks like a path
                            path = Path(val)
                            path = Path(val)
                            try:
                                # [v4.44] Smart Deep Walk
                                # Walk up until we find "filesystem" or "out" or just grab upper levels
                                parts = path.parts
                                # Look for "filesystem" index
                                fs_idx = -1
                                for i, p in enumerate(parts):
                                    if p.lower() in ["filesystem", "kape", "triage", "artifacts", "c"]: fs_idx = i
                                
                                if fs_idx > 0:
                                    # If ".../out/filesystem/...", we want ".../out"
                                    # fs_idx points to "filesystem". So path is parts[:fs_idx]
                                    root_path = Path(*parts[:fs_idx])
                                    roots.add(root_path)
                                    roots.add(root_path.parent)
                                else:
                                    # Fallback: Just add parents up to 5 levels
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
        """Memory-based discovery."""
        candidates = ["BrowsingHistory", "WebHistory", "Chrome_History", "Edge_History", "Firefox_History", "History"]
        for key in dfs.keys():
            for cand in candidates:
                if cand.lower() in key.lower():
                    print(f"    [Lachesis] ✅ Auto-Discovered History Data (Memory): {key}")
                    return dfs[key]
        return None



    def weave_report(self, analysis_result, output_path, dfs_for_ioc, hostname, os_info, primary_user, history_csv=None, history_search_path=None):
        print(f"[*] Lachesis v4.43 is weaving the report into {output_path}...")
        self.hostname = hostname 
        self._latest_dfs = dfs_for_ioc # Store for inference
        raw_events = analysis_result["events"]
        self.noise_stats = {}

        real_os_info = self._resolve_os_info_fallback(os_info, Path(output_path).parent)

        # 1. Scope Calculation
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
            
            if chk_score >= 200 or "CRITICAL" in chk_tag or "MASQUERADE" in chk_tag or "TIMESTOMP" in chk_tag or "PHISHING" in chk_tag or self._is_dual_use(chk_name):
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
        
        # 2. IOC Extraction & Tagging
        self._extract_visual_iocs_from_pandora(dfs_for_ioc)
        self._extract_visual_iocs_from_chronos(dfs_for_ioc)
        self._extract_visual_iocs_from_aion(dfs_for_ioc)
        self._extract_visual_iocs_from_events(raw_events)
        
        self._generate_pivot_seeds()

        # 3. Tartaros Origin Tracing
        origin_stories = []
        if self.pivot_seeds and TartarosTracer:
            timeline_df = dfs_for_ioc.get("Timeline")
            
            # [Fix v4.41] 3-Stage History Resolution
            df_history_target = self._resolve_history_df(dfs_for_ioc)
            
            # Disk search if memory check failed and no explicit path provided
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

        # 4. Write Report
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
            f.write(f"\n---\n*Report woven by SkiaHelios (The Triad v4.43)* 🦁")
        
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
        
        # 1. Phishing LNKs
        if phishing_lnks:
            f.write("**フィッシングによる初期侵入が高確度で確認されました。**\n")
            f.write(f"- Recentフォルダ等において、**{len(phishing_lnks)}件** の不審なLNKファイル（ショートカット）へのアクセスが検知されています。\n")
            f.write("\n| サンプルLNK | アクセス時刻 (UTC) | 流入元 (Origin Trace) |\n|---|---|---|\n")
            for seed in phishing_lnks[:10]:
                self._write_origin_row(f, seed, origin_stories)
            f.write("\n")

        # 2. Dropped Tools (Dual-Use / Malware)
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
        path_short = seed.get('Target_Path', '')[:20] + "..." if len(seed.get('Target_Path', '')) > 20 else seed.get('Target_Path', '')
        
        origin_desc = "Unknown (Local/Network)"
        for story in origin_stories:
            if story["Target"] == name:
                ev = story["Evidence"][0]
                url_short = ev.get("URL", "")
                if len(url_short) > 60: url_short = url_short[:57] + "..."
                
                note = "⚠️ **(推定)** " if "Inferred" in story.get("Origin", "") else ""
                gap = ev.get('Time_Gap', '-')
                
                origin_desc = f"{note}🌐 {story['Origin']}<br/>`{url_short}`<br/>*(Gap: {gap})*"
                break
        
        col2 = time if time else f"`{path_short}`"
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
                        fname = row.get("FileName", "")
                        path = row.get("ParentPath", "")
                        score = int(float(row.get(score_col, 0)))
                        
                        bypass_reason = None
                        is_trusted_loc = self._is_trusted_system_path(path)
                        is_dual = self._is_dual_use(fname)

                        if is_dual:
                            bypass_reason = "Dual-Use Tool [DROP]" 
                        elif score >= 220:
                            if is_trusted_loc:
                                self._log_noise("Trusted Path (Update)", fname)
                                continue
                            else:
                                bypass_reason = "High Score (Timestomp) [DROP]"
                        
                        if bypass_reason:
                            print(f"    [BYPASS] Retained {fname} (Score: {score})")
                        elif score < 200 or self._is_noise(fname, path): continue 
                        
                        if not bypass_reason: bypass_reason = "High Score (>200)"
                        self._add_unique_visual_ioc({
                            "Type": "TIMESTOMP", "Value": fname, "Path": path, "Note": "Time Anomaly", "Time": str(row.get("Anomaly_Time", "")), "Reason": bypass_reason
                        })
                except: pass

    def _extract_visual_iocs_from_pandora(self, dfs):
        if dfs.get('Pandora') is not None:
            df = dfs['Pandora']
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
                        
                        elif self._is_dual_use(fname): bypass_reason = "Dual-Use Tool [DROP]"
                        elif "TIMESTOMP" in tag: bypass_reason = "Timestomp [DROP]"
                        elif score >= 250: bypass_reason = "Critical Score [DROP]"

                        if bypass_reason: print(f"    [BYPASS] Retained {fname} ({bypass_reason})")
                        elif score < 200 or self._is_noise(fname, path): continue

                        if not bypass_reason: bypass_reason = "High Confidence"
                        clean_name = fname.split("] ")[-1]
                        self._add_unique_visual_ioc({
                            "Type": row.get("Threat_Tag", "SUSPICIOUS"), "Value": clean_name, "Path": path, "Note": "File Artifact", 
                            "Time": str(row.get("Ghost_Time_Hint", "")), "Reason": bypass_reason
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
                            if not self._is_noise(name, row.get("Full_Path", "")):
                                self._add_unique_visual_ioc({
                                    "Type": "PERSISTENCE", "Value": name, "Path": row.get("Full_Path"), "Note": "Persist", "Time": str(row.get("Last_Executed_Time", "")), "Reason": "Persistence"
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
            if (ev['Criticality'] >= 90 or is_dual) and ev['Category'] == 'EXEC':
                kws = ev.get('Keywords', [])
                if kws:
                    kw = str(kws[0]).lower()
                    if not self._is_noise(kw):
                        type_label = "DUAL_USE_TOOL" if is_dual else "EXECUTION"
                        reason_label = "Dual-Use Tool [DROP]" if is_dual else "Execution"
                        self._add_unique_visual_ioc({
                            "Type": type_label, "Value": kws[0], "Path": "Process", "Note": f"Execution ({ev['Source']})",
                            "Reason": reason_label
                        })

    def _write_executive_summary_visual(self, f, events, verdicts, primary_user, time_range):
        """[v4.38/v4.40] Restored & Updated Visual Executive Summary"""
        t = self.txt
        f.write(f"## {t['h1_exec']}\n")
        f.write(f"**結論:**\n{time_range} の期間において、端末 {self.hostname} に対する **CRITICAL レベルの侵害活動** を確認しました。\n")
        f.write(f"**主な攻撃手口:** フィッシング（LNK）による初期侵入、バックドア設置（Persistence）、およびタイムスタンプ偽装（Timestomp）。\n\n")
        f.write("> **Deep Dive 推奨:** 詳細な調査を行う際は、添付の `Pivot_Config.json` に記載された **CRITICAL_PHISHING** ターゲット群から開始してください。\n\n")
        f.write("\n### 🏹 Attack Timeline Flow (Critical Chain)\n")
        if self.visual_iocs: f.write(self._generate_mermaid())
        else: f.write("(No sufficient visual indicators found)\n")
        f.write("\n### 💎 Key Indicators (Critical Only)\n")
        if self.visual_iocs:
            f.write("| Time | Type | Value (File/IP) | Reason (Bypass) | Path |\n|---|---|---|---|---|\n")
            sorted_iocs = sorted(self.visual_iocs, key=lambda x: x.get("Time", "9999"))
            seen = set()
            for ioc in sorted_iocs:
                val = ioc['Value']
                if val in seen: continue
                seen.add(val)
                path_short = (ioc['Path'][:30] + '..') if len(ioc['Path']) > 30 else ioc['Path']
                reason = ioc.get("Reason", "-")
                f.write(f"| {str(ioc.get('Time','')).replace('T',' ')[:19]} | **{ioc['Type']}** | `{ioc['Value']}` | {reason} | `{path_short}` |\n")
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
        f.write("\n")

    def _write_technical_findings(self, f, phases):
        t = self.txt
        f.write(f"## {t['h1_tech']}\n")
        f.write("本セクションでは、確度が高い（High Confidence）と判定された重要イベントのみを集約して記載します。\n")
        f.write("詳細なログデータは、添付のマスタータイムライン（CSV）を参照してください。\n\n")
        has_any_findings = False
        for idx, phase in enumerate(phases):
            if not phase: continue
            created_files = set()
            for ev in phase:
                if ev['Category'] in ['DROP', 'EXEC'] and ev.get('Keywords'):
                    for k in ev['Keywords']: created_files.add(str(k).lower())
            grouped_events = {}
            if isinstance(phase[0], dict) and 'Time' in phase[0]:
                date_str = str(phase[0]['Time']).replace('T', ' ').split(' ')[0]
            else:
                date_str = "Unknown Date"

            for ev in phase:
                if self._is_noise(ev['Summary']): continue
                is_dual = self._is_dual_use(ev.get('Summary', ''))
                is_high_conf = ev['Criticality'] >= 90 or is_dual
                if is_high_conf:
                    insight = self._generate_insight(ev, created_files) 
                    if insight not in grouped_events:
                        grouped_events[insight] = []
                    grouped_events[insight].append(ev)
            if grouped_events:
                has_any_findings = True
                f.write(f"### 📅 Phase {idx+1} ({date_str})\n")
                for insight, events in grouped_events.items():
                    f.write(f"- **{insight}**\n")
                    targets = []
                    for ev in events: targets.append(ev['Summary'])
                    unique_targets = sorted(list(set(targets)))
                    count = len(unique_targets)
                    if count == 1:
                        f.write(f"  - Target: {unique_targets[0]}\n")
                    else:
                        f.write(f"  - **Total Events:** {len(events)} (Unique Targets: {count})\n")
                        for tgt in unique_targets[:3]: f.write(f"  - {tgt}\n")
                        if count > 3: f.write(f"  - *(... and {count - 3} more targets)*\n")
                    f.write("\n")
                f.write("\n")
        if not has_any_findings:
            f.write("本調査範囲において、特筆すべき高確度の技術的痕跡は検出されませんでした。\n\n")

    def _generate_mermaid(self):
        if not self.visual_iocs: return ""
        def get_time(item):
            t = item.get("Time", "")
            return t if t else "9999"
        sorted_iocs = sorted(self.visual_iocs, key=get_time)
        if not sorted_iocs: return ""
        chart = "\n```mermaid\ngraph TD\n"
        chart += "    %% Time-Clustered Attack Flow\n"
        chart += "    start((Start)) --> P0\n"
        clusters = []
        current_cluster = []
        last_dt = None
        for ioc in sorted_iocs[:20]:
            if self._is_visual_noise(ioc["Value"]): continue
            ts_str = ioc.get("Time", "")
            curr_dt = self._parse_time_safe(ts_str)
            if curr_dt:
                if last_dt and (curr_dt - last_dt).total_seconds() > 45: 
                    clusters.append(current_cluster)
                    current_cluster = []
                last_dt = curr_dt
            current_cluster.append(ioc)
        if current_cluster: clusters.append(current_cluster)
        node_registry = []
        for idx, cluster in enumerate(clusters):
            if not cluster: continue
            time_label = "Unknown Time"
            if cluster[0].get("Time"):
                time_label = str(cluster[0]["Time"]).split("T")[1][:5]
            chart += f"\n    subgraph T{idx} [Time: {time_label}]\n"
            chart += "        direction TB\n"
            for item in cluster:
                val = self._sanitize_mermaid(item["Value"])
                typ = item["Type"]
                short_val = (val[:15] + '..') if len(val) > 15 else val
                icon = "💀"
                if "PHISH" in typ: icon = "🎣"
                elif "BACKDOOR" in typ or "MASQ" in typ: icon = "🚪"
                elif "TIMESTOMP" in typ: icon = "🕒"
                elif "PERSIST" in typ: icon = "⚓"
                node_id = f"N{abs(hash(val + str(idx)))}"
                label = f"{icon} {typ}<br/>{short_val}"
                chart += f"        {node_id}[\"{label}\"]\n"
                node_registry.append(node_id)
            chart += "    end\n"
            if idx > 0:
                prev_node_id = node_registry[len(node_registry) - len(cluster) - 1]
                curr_first_node = node_registry[len(node_registry) - len(cluster)]
                chart += f"    {prev_node_id} --> {curr_first_node}\n"
            else:
                chart += f"    P0 --> {node_registry[0]}\n"
        chart += "\n    %% Styles\n"
        chart += "    classDef threat fill:#ffcccc,stroke:#ff0000,stroke-width:2px,color:#000;\n"
        chart += "    class N* threat;\n"
        chart += "```\n"
        return chart

    def _sanitize_mermaid(self, text):
        clean = str(text).replace('"', "'").replace("{", "(").replace("}", ")")
        clean = clean.replace("<", "&lt;").replace(">", "&gt;")
        return clean

    def _write_detection_statistics(self, f, medium_events, dfs):
        t = self.txt
        f.write(f"## {t['h1_stats']}\n")
        f.write("本セクションでは、Criticalには至らなかったものの、調査の参考となる中確度（Medium Confidence）のイベント及びフィルタリング統計を示します。\n\n")
        if medium_events:
            f.write(f"**Medium Confidence Events:** {len(medium_events)} 件 (Timeline CSV参照)\n")
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

    def _generate_insight(self, ev, created_files_in_phase=None):
        summary = ev['Summary']
        path = str(ev.get('Keywords', [''])[0]).lower() if ev.get('Keywords') else ""
        if ".crx" in path and not any(b in path for b in ["chrome", "edge", "chromium", "brave"]):
             return "【致命的】正規アプリを装ったバックドア（Masquerading）の設置を検知しました。"
        if ".lnk" in path and re.search(r'\.(jpg|png|pdf|doc|docx|xls|xlsx)\.lnk$', path):
             return "【起点】二重拡張子を用いたフィッシング攻撃（LNK実行）を確認しました。"
        if ev['Category'] == "PERSIST":
            return "システムへの永続的潜伏（Persistence）設定を確認しました。"
        return self._default_insight(ev)

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
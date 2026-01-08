import json
import re
import polars as pl
import os
from datetime import datetime, timedelta
from tools.lachesis.intel import TEXT_RES

class LachesisRenderer:
    def __init__(self, output_path, lang="jp"):
        self.output_path = output_path
        self.lang = lang if lang in TEXT_RES else "jp"
        self.txt = TEXT_RES[self.lang]
        self.hostname = "Unknown"
        self.headers = {
            "en": {"exec": "Executive Summary", "chain": "Critical Chain", "iocs": "Key Indicators"},
            "jp": {"exec": "エグゼクティブ・サマリー", "chain": "攻撃フロー図 (Attack Flow)", "iocs": "重要指標 (Key Indicators)"}
        }

    def render_report(self, analysis_data, analyzer, enricher, origin_stories, dfs_for_ioc, metadata):
        self.hostname = metadata.get("hostname", "Unknown")
        out_file = self.output_path
        
        with open(out_file, "w", encoding="utf-8") as f:
            self._write_header(f, metadata["os_info"], metadata["primary_user"], analysis_data["time_range"])
            self._write_toc(f)
            self._write_executive_summary_visual(f, analyzer, analysis_data["time_range"])
            self._write_technical_findings(f, analyzer, dfs_for_ioc) 
            self._write_timeline_visual(f, analysis_data["phases"], analyzer, enricher)
            self._write_detection_statistics(f, analysis_data["medium_events"], analyzer, dfs_for_ioc)
            self._write_ioc_appendix_unified(f, analyzer) 
            f.write(f"\n---\n*Report woven by SkiaHelios (The Triad v5.0)* 🦁")
        
        print(f"[*] Lachesis v5.0 is weaving the report into {out_file}...")

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
        f.write(f"- [{t['h1_tech']}](#{self._make_anchor(t['h1_tech'])})\n")
        f.write(f"- [{t['h1_time']}](#{self._make_anchor(t['h1_time'])})\n")
        f.write(f"- [{t['h1_stats']}](#{self._make_anchor(t['h1_stats'])})\n")
        f.write(f"- [{t['h1_app']}](#{self._make_anchor(t['h1_app'])})\n")
        f.write("\n---\n\n")

    def _make_anchor(self, text):
        return text.lower().replace(" ", "-").replace(".", "").replace("&", "").replace("(", "").replace(")", "").replace("/", "")

    def _write_executive_summary_visual(self, f, analyzer, time_range):
        t = self.txt
        f.write(f"## {t['h1_exec']}\n")
        
        visual_iocs = analyzer.visual_iocs
        has_time_change = any("SYSTEM_TIME" in str(ioc.get('Tag', '')) or "4616" in str(ioc.get('Value', '')) for ioc in visual_iocs)
        has_paradox = any("TIME_PARADOX" in str(ioc.get('Type', '')) for ioc in visual_iocs) or has_time_change
        has_masquerade = any("MASQUERADE" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_phishing = any("PHISHING" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_timestomp = any("TIMESTOMP" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_anti = any("ANTI_FORENSICS" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        
        conclusion = ""
        if has_paradox:
            conclusion = f"**結論:**\n{time_range} の期間において、**システム時間の改ざん（Time Manipulation）を含む高度な隠蔽工作** が確認されました。\n"
        elif has_masquerade or has_anti:
            conclusion = f"**結論:**\n{time_range} の期間において、端末 {self.hostname} に対する **証拠隠滅・偽装を伴う重大な侵害活動** を確認しました。\n"
        elif visual_iocs:
            conclusion = f"**結論:**\n{time_range} の期間において、端末 {self.hostname} に対する **CRITICAL レベルの侵害活動** を確認しました。\n"
        else:
            conclusion = f"**結論:**\n本調査範囲において、重大なインシデントの痕跡は検出されませんでした。\n"
        
        f.write(conclusion)
        
        attack_methods = []
        if has_phishing: attack_methods.append("フィッシング（LNK）による初期侵入")
        if has_masquerade: attack_methods.append("偽装ファイル設置（Masquerading）")
        if has_paradox: attack_methods.append("**システム時間変更（System Time Change）**")
        if has_timestomp: attack_methods.append("ファイルタイムスタンプ偽装（Timestomp）")
        if has_anti: attack_methods.append("痕跡ワイピング（Anti-Forensics）")
        
        if not attack_methods: attack_methods = ["不審なアクティビティ"]
            
        f.write(f"**主な攻撃手口:** {', '.join(attack_methods)}。\n\n")
        
        f.write(self._render_mermaid_vertical_clustered(visual_iocs))
        f.write(self._render_key_indicators(visual_iocs))
        f.write("\n")

    def _render_mermaid_vertical_clustered(self, events):
        """Mermaid図の生成 (Vertical Time-Clustered & Burst Grouping)"""
        if not events: return "\n(No critical events found for visualization)\n"
        
        f = ["\n### 🏹 Attack Flow Visualization (Timeline)\n"]
        f.append("```mermaid")
        f.append("graph TD")
        
        f.append("    classDef init fill:#e63946,stroke:#333,stroke-width:2px,color:white;")
        f.append("    classDef exec fill:#f4a261,stroke:#333,stroke-width:2px,color:black;")
        f.append("    classDef persist fill:#2a9d8f,stroke:#333,stroke-width:2px,color:white;")
        f.append("    classDef anti fill:#264653,stroke:#333,stroke-width:2px,color:white;")
        f.append("    classDef time fill:#a8dadc,stroke:#457b9d,stroke-width:4px,color:black;")
        f.append("    classDef phishing fill:#ff6b6b,stroke:#c92a2a,stroke-width:2px,color:white;")
        
        def priority_score(ev):
            cat = self._get_event_category(ev)
            score = 0
            if "SYSTEM" in cat: score += 1000 
            if "ANTI" in cat: score += 500
            if "PERSIST" in cat: score += 200
            if "INITIAL" in cat: score += 100
            return score + ev.get('Score', 0)

        critical_events = [ev for ev in events if ev.get('Score', 0) >= 60 or "CRITICAL" in str(ev.get('Type', ''))]
        sorted_events = sorted(critical_events, key=lambda x: x.get('Time', '9999'))
        
        if not sorted_events: return "\n(No critical events found)\n"

        subgraphs = []
        current_subgraph = {"nodes": [], "start_time": None, "end_time": None, "label": ""}
        
        def parse_dt(t_str):
            try: return datetime.fromisoformat(t_str.replace("Z", ""))
            except: return datetime.min

        last_dt = None
        node_id_counter = 0
        burst_buffer = [] 
        
        def flush_burst_buffer(buffer, target_list, counter):
            if not buffer: return counter
            first_ev = buffer[0]
            cat = self._get_event_category(first_ev)
            
            if len(buffer) >= 3 and ("INITIAL" in cat or "EXECUTION" in cat):
                node_id = f"N{counter}"
                counter += 1
                start_t = str(buffer[0].get('Time', ''))[11:16]
                count = len(buffer)
                icon = "⚡"
                if "INITIAL" in cat: icon = "🎣"
                elif "EXEC" in cat: icon = "⚙️"
                
                short_summary = self._get_short_summary(first_ev)
                label = f"{start_t} {icon} {count}x Events<br/>({short_summary} etc.)"
                style = ":::exec"
                if "INITIAL" in cat: style = ":::phishing"
                target_list.append(f"{node_id}[\"{label}\"]{style}")
                return counter
            else:
                for ev in buffer:
                    node_id = f"N{counter}"
                    counter += 1
                    t_str = str(ev.get('Time', ''))[11:16]
                    s_sum = self._get_short_summary(ev)
                    ev_cat = self._get_event_category(ev)
                    icon = "🔹"
                    style = ":::default"
                    if "SYSTEM" in ev_cat: icon = "⏰"; style = ":::time"
                    elif "ANTI" in ev_cat: icon = "🗑️"; style = ":::anti"
                    elif "PERSIST" in ev_cat: icon = "⚓"; style = ":::persist"
                    elif "INITIAL" in ev_cat: icon = "🎣"; style = ":::init"
                    
                    label = f"{t_str} {icon} {s_sum}"
                    target_list.append(f"{node_id}[\"{label}\"]{style}")
                return counter

        for ev in sorted_events:
            dt = parse_dt(ev.get('Time', ''))
            
            if last_dt and (dt - last_dt).total_seconds() > 3600:
                node_id_counter = flush_burst_buffer(burst_buffer, current_subgraph["nodes"], node_id_counter)
                burst_buffer = []
                subgraphs.append(current_subgraph)
                current_subgraph = {"nodes": [], "start_time": dt, "end_time": dt, "label": ""}
            
            if current_subgraph["start_time"] is None: current_subgraph["start_time"] = dt
            current_subgraph["end_time"] = dt
            last_dt = dt
            
            if not burst_buffer:
                burst_buffer.append(ev)
            else:
                last_in_buff = burst_buffer[-1]
                last_buff_dt = parse_dt(last_in_buff.get('Time', ''))
                same_cat = self._get_event_category(ev) == self._get_event_category(last_in_buff)
                close_time = (dt - last_buff_dt).total_seconds() < 120 
                
                if same_cat and close_time:
                    burst_buffer.append(ev)
                else:
                    node_id_counter = flush_burst_buffer(burst_buffer, current_subgraph["nodes"], node_id_counter)
                    burst_buffer = [ev]

        node_id_counter = flush_burst_buffer(burst_buffer, current_subgraph["nodes"], node_id_counter)
        subgraphs.append(current_subgraph)

        sg_counter = 0
        prev_sg_id = None
        
        for sg in subgraphs:
            if not sg["nodes"]: continue
            sg_id = f"T{sg_counter}"
            start_s = sg["start_time"].strftime("%H:%M")
            end_s = sg["end_time"].strftime("%H:%M")
            label = f"{start_s} - {end_s}"
            
            f.append(f"    subgraph {sg_id} [\"⏰ {label}\"]")
            for n in sg["nodes"]: f.append(f"        {n}")
            f.append("    end")
            
            if prev_sg_id:
                f.append(f"    {prev_sg_id} --> {sg_id}")
            prev_sg_id = sg_id
            sg_counter += 1

        f.append("```\n")
        return "\n".join(f)

    def _get_event_category(self, ev):
        typ = str(ev.get('Type', '')).upper()
        tag = str(ev.get('Tag', '')).upper()
        val = str(ev.get('Value', '')).upper()
        if "SYSTEM_TIME" in tag or "TIME_CHANGE" in tag or "4616" in tag or "ROLLBACK" in tag: return "SYSTEM MANIPULATION"
        if "PHISH" in typ or "LNK" in typ: return "INITIAL ACCESS"
        if "WIPE" in typ or "ANTI" in typ: return "ANTI-FORENSICS"
        if "PERSIST" in typ: return "PERSISTENCE"
        if "EXEC" in typ or "RUN" in typ: return "EXECUTION"
        if "TIMESTOMP" in typ: return "TIMESTOMP (FILE)"
        return "OTHER ACTIVITY"

    def _get_short_summary(self, ev):
        val = ev.get('Value', '')
        if not val or val == "Unknown":
            val = ev.get('Summary', '')
            if not val: val = str(ev.get('Tag', 'Event'))
        if "SYSTEM_TIME" in str(ev.get('Tag', '')) or "4616" in str(val): return "System Time Changed"
        if "\\" in val or "/" in val: val = os.path.basename(val.replace("\\", "/"))
        return val[:15] + ".." if len(val) > 15 else val

    def _render_key_indicators(self, events):
        output = ["\n### 💎 Key Indicators (Critical Only)\n"]
        grouped = {}
        for ev in events:
            if ev.get('Score', 0) < 60 and "CRITICAL" not in str(ev.get('Type', '')): continue
            cat = self._get_event_category(ev)
            if cat not in grouped: grouped[cat] = []
            grouped[cat].append(ev)

        cat_titles = {
            "INITIAL ACCESS": "🎣 Initial Access", "ANTI-FORENSICS": "🙈 Anti-Forensics",
            "SYSTEM MANIPULATION": "🚨 System Time Manipulation", "PERSISTENCE": "⚓ Persistence",
            "EXECUTION": "⚡ Execution", "TIMESTOMP (FILE)": "🕒 Timestomp (Files)"
        }
        keys = sorted(grouped.keys(), key=lambda k: 0 if "SYSTEM" in k else 1)

        for cat in keys:
            items = grouped[cat]
            output.append(f"#### {cat_titles.get(cat, cat)}")
            output.append("| Time (UTC) | Value / Artifact | Impact/Target | Score |")
            output.append("|---|---|---|---|")
            items.sort(key=lambda x: x.get('Time', '9999'))
            for ioc in items:
                t = str(ioc.get('Time', 'N/A')).replace('T', ' ')[:19]
                val = ioc.get('Value', '-')
                if not val or val == "Unknown": val = ioc.get('Summary', '-')
                score = ioc.get('Score', 0)
                impact = "-"
                extra = ioc.get('Extra', {})
                tag = str(ioc.get('Tag', ''))
                if "SYSTEM_TIME" in tag or "4616" in tag:
                    impact = "**System Clock Altered**"
                    val = "Event ID 4616"
                elif cat == "INITIAL ACCESS":
                    tgt = extra.get('Target_Path', 'Unknown')
                    impact = f"Target: {tgt[:30]}..."
                output.append(f"| {t} | `{val}` | {impact} | {score} |")
            output.append("\n")
        return "\n".join(output)

    def _write_technical_findings(self, f, analyzer, dfs):
        t = self.txt
        f.write(f"## {t['h1_tech']}\n")
        high_conf_events = [ioc for ioc in analyzer.visual_iocs if analyzer.is_force_include_ioc(ioc) or "ANTI" in str(ioc.get("Type", ""))]
        self._write_anti_forensics_section(f, high_conf_events, dfs)
        f.write("### 🔍 Detailed Findings by Category\n\n")
        groups = {}
        for ioc in high_conf_events:
            cat = self._get_event_category(ioc)
            if "ANTI" in cat: continue
            if cat not in groups: groups[cat] = []
            groups[cat].append(ioc)
        for cat, items in groups.items():
            f.write(f"#### {cat}\n")
            items.sort(key=lambda x: x.get('Time', '9999'))
            for ioc in items:
                dt = str(ioc.get('Time', '')).replace('T', ' ')[:19]
                val = ioc.get('Value', '') or ioc.get('Summary', '')
                f.write(f"- **{dt}** | `{val}`\n")
            f.write("\n")

    def _write_anti_forensics_section(self, f, ioc_list, dfs):
        af_tools = [ioc for ioc in ioc_list if "ANTI" in str(ioc.get("Type", "")) or "WIPE" in str(ioc.get("Type", ""))]
        if not af_tools: return
        f.write("### 🚨 Anti-Forensics Activities\n\n")
        seen = set()
        for tool in af_tools:
            name = tool.get("Value", "Unknown").upper()
            if name in seen: continue
            seen.add(name)
            run_count = self._extract_dual_run_count(tool, dfs)
            last_run = tool.get("Time", "").replace("T", " ")[:19]
            f.write(f"#### {name}\n- 📊 **Run Count**: **{run_count}**\n- 🕐 **Last Exec**: {last_run}\n\n")

    def _extract_dual_run_count(self, ioc, dfs):
        """
        UserAssistとPrefetchの実行回数を取得する (v5.1 Regex Cheat)
        1. まずイベントのSummary/Value文字列から直接 '(Run: N)' を探す (最速・確実)
        2. なければCSV (dfs) から検索する (フォールバック)
        """
        ua_count = "N/A"
        pf_count = "N/A"
        
        # 1. Regex Extraction from Event Text (The Cheat Method)
        text_sources = [
            ioc.get("Value", ""), 
            ioc.get("Summary", ""), 
            ioc.get("Action", ""),
            ioc.get("Target_Path", "")
        ]
        
        for text in text_sources:
            if not text: continue
            # Pattern: "(Run: 2)" or "Run Count: 5"
            match = re.search(r"\(Run:\s*(\d+)\)", str(text), re.IGNORECASE)
            if match:
                ua_count = match.group(1)
                break
        
        # 2. Prefetch CSV Lookup
        target_name = ioc.get("Value", "").lower().strip()
        if target_name and dfs and dfs.get('Prefetch') is not None:
            target_base = os.path.basename(target_name.replace("\\", "/")).split(" ")[0]
            df = dfs['Prefetch']
            try:
                cols = {c.lower(): c for c in df.columns}
                exec_col = next((cols[c] for c in cols if "executable" in c), None)
                run_col = next((cols[c] for c in cols if "run" in c and "count" in c), None)
                if exec_col and run_col:
                    hits = df.filter(pl.col(exec_col).str.to_lowercase().str.contains(target_base, literal=True))
                    if hits.height > 0:
                        max_run = hits.select(pl.col(run_col).cast(pl.Int64, strict=False)).max().item()
                        if max_run is not None: pf_count = str(max_run)
            except: pass
        
        # 3. UserAssist CSV Lookup (Fallback if Regex failed)
        if ua_count == "N/A" and target_name and dfs and dfs.get('UserAssist') is not None:
            target_base = os.path.basename(target_name.replace("\\", "/")).split(" ")[0]
            df = dfs['UserAssist']
            try:
                cols = {c.lower(): c for c in df.columns}
                name_col = next((cols[c] for c in cols if "valuename" in c or "program" in c or "value" in c), None)
                run_col = next((cols[c] for c in cols if "run" in c and "count" in c), None)
                if not run_col: run_col = next((cols[c] for c in cols if "count" in c and "account" not in c), None)
                if name_col and run_col:
                    hits = df.filter(pl.col(name_col).str.to_lowercase().str.contains(target_base, literal=True))
                    if hits.height > 0:
                        max_run = hits.select(pl.col(run_col).cast(pl.Int64, strict=False)).max().item()
                        if max_run is not None: ua_count = str(max_run)
            except: pass
            
        return f"UA: {ua_count} | PF: {pf_count}"

    def _write_timeline_visual(self, f, phases, analyzer, enricher):
        t = self.txt
        f.write(f"## {t['h1_time']}\n(Detailed Timeline)\n\n")
        for idx, phase in enumerate(phases):
            if not phase: continue
            if isinstance(phase[0], dict) and 'Time' in phase[0]:
                date_str = str(phase[0]['Time']).split('T')[0]
            else: date_str = "Unknown"
            f.write(f"### 📅 Phase {idx+1} ({date_str})\n")
            f.write(f"| Time (UTC) | Category | Event Summary | Source |\n|---|---|---|---|\n") 
            for ev in phase:
                summary = ev['Summary']
                time_display = str(ev.get('Time','')).replace('T', ' ').split('.')[0]
                cat_name = t['cats'].get(ev.get('Category'), ev.get('Category'))
                row_str = f"| {time_display} | {cat_name} | **{summary}** | {ev['Source']} |"
                f.write(f"{row_str}\n")
            f.write("\n")

    def _write_detection_statistics(self, f, medium_events, analyzer, dfs):
        t = self.txt
        f.write(f"## {t['h1_stats']}\n")
        f.write(f"Total Events Analyzed: {analyzer.total_events_analyzed}\n\n")

    def _write_ioc_appendix_unified(self, f, analyzer):
        t = self.txt
        f.write(f"## {t['h1_app']}\n(Full IOC List)\n")

    def export_pivot_config(self, pivot_seeds, path, primary_user):
        if not pivot_seeds: return
        config = {"Case_Context": {"Hostname": self.hostname, "User": primary_user}, "Deep_Dive_Targets": pivot_seeds[:20]}
        try:
            with open(path, "w", encoding="utf-8") as f: json.dump(config, f, indent=2)
        except: pass

    def export_json_grimoire(self, analysis_result, analyzer, json_path, primary_user):
        data = {"Metadata": {"Host": self.hostname, "User": primary_user}, "Timeline": analysis_result.get("events", [])}
        try:
            with open(json_path, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)
        except: pass
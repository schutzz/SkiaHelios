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
            "en": {
                "exec": "Executive Summary", 
                "origin": "Initial Access Vector", 
                "chain": "Critical Chain", 
                "tech": "High Confidence Findings", 
                "iocs": "Key Indicators"
            },
            "jp": {
                "exec": "エグゼクティブ・サマリー", 
                "origin": "初期侵入経路分析 (Initial Access Vector)", 
                "chain": "調査タイムライン (Critical Chain)", 
                "tech": "技術的詳細 (High Confidence Findings)", 
                "iocs": "重要指標 (Key Indicators)"
            }
        }

    def render_report(self, analysis_data, analyzer, enricher, origin_stories, dfs_for_ioc, metadata):
        self.hostname = metadata.get("hostname", "Unknown")
        out_file = self.output_path
        
        with open(out_file, "w", encoding="utf-8") as f:
            self._write_header(f, metadata["os_info"], metadata["primary_user"], analysis_data["time_range"])
            self._write_toc(f)
            
            # 1. Executive Summary
            self._write_executive_summary_visual(f, analyzer, analysis_data["time_range"], metadata["primary_user"])
            
            # 2. Initial Access Vector
            self._write_initial_access_vector(f, analyzer.pivot_seeds, origin_stories)
            
            # 3. Timeline
            self._write_timeline_visual(f, analysis_data["phases"], analyzer, enricher)
            
            # 4. Technical Findings (Pass origin_stories for LNK enrichment)
            self._write_technical_findings(f, analyzer, dfs_for_ioc, origin_stories) 
            
            # 5. Network & Lateral Movement (Plutos)
            self._write_plutos_section(f, dfs_for_ioc)
            
            # 6. Detection Statistics
            self._write_detection_statistics(f, analysis_data["medium_events"], analyzer, dfs_for_ioc)

            # 7. Conclusions & Recommendations
            self._write_recommendations(f, analyzer)
            
            # 7. Appendix (IOCs)
            self._write_ioc_appendix_unified(f, analyzer) 
            
            f.write(f"\n---\n*Report woven by SkiaHelios (The Triad v5.2 Perfection)* 🦁")
        
        print(f"[*] Lachesis v5.2 is weaving the Grimoire into {out_file}...")

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
        f.write(f"- [{t['h1_rec']}](#{self._make_anchor(t['h1_rec'])})\n")
        f.write(f"- [{t['h1_app']}](#{self._make_anchor(t['h1_app'])})\n")
        f.write(f"- [Pivot Config (Deep Dive Targets)](#deep-dive-recommendation)\n")
        f.write("\n---\n\n")

    def _make_anchor(self, text):
        return text.lower().replace(" ", "-").replace(".", "").replace("&", "").replace("(", "").replace(")", "").replace("/", "")

    def _is_visual_noise(self, name):
        name = str(name).strip()
        if len(name) < 3: return True
        return False

    def _write_executive_summary_visual(self, f, analyzer, time_range, primary_user):
        t = self.txt
        f.write(f"## {t['h1_exec']}\n")
        
        visual_iocs = analyzer.visual_iocs
        has_time_change = any("SYSTEM_TIME" in str(ioc.get('Tag', '')) or "4616" in str(ioc.get('Value', '')) for ioc in visual_iocs)
        has_paradox = any("TIME_PARADOX" in str(ioc.get('Type', '')) for ioc in visual_iocs) or has_time_change
        has_masquerade = any("MASQUERADE" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_phishing = any("PHISHING" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_timestomp = any("TIMESTOMP" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_anti = any("ANTI_FORENSICS" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        
        # [i18n] Use TEXT_RES for conclusions
        t = self.txt
        if has_paradox:
            conclusion = t['conclusion_paradox'].format(time_range=time_range, hostname=self.hostname)
        elif has_masquerade or has_anti:
            conclusion = t['conclusion_anti'].format(time_range=time_range, hostname=self.hostname)
        elif visual_iocs:
            conclusion = t['conclusion_critical'].format(time_range=time_range, hostname=self.hostname)
        else:
            conclusion = t['conclusion_clean']
        
        f.write(conclusion)
        
        # [i18n] Use TEXT_RES for attack methods
        attack_methods = []
        if has_phishing: attack_methods.append(t['attack_phishing'])
        if has_masquerade: attack_methods.append(t['attack_masquerade'])
        if has_timestomp: attack_methods.append(t['attack_timestomp'])
        if has_paradox: attack_methods.append(t['attack_paradox'])
        if has_anti: attack_methods.append(t['attack_anti'])
        
        if not attack_methods: attack_methods = [t['attack_default']]
            
        f.write(f"{t['attack_methods_label']} {', '.join(attack_methods)}.\n\n")
        f.write(t['deep_dive_note'])
        
        f.write(self._render_mermaid_vertical_clustered(visual_iocs))
        f.write(self._render_key_indicators(visual_iocs))
        f.write("\n")

    def _write_initial_access_vector(self, f, pivot_seeds, origin_stories):
        t = self.txt
        f.write(f"## {t['h1_origin']}\n")
        phishing_lnks = [s for s in pivot_seeds if "PHISHING" in s.get("Reason", "")]
        drop_items = [s for s in pivot_seeds if "DROP" in s.get("Reason", "") and "PHISHING" not in s.get("Reason", "")]
        
        if phishing_lnks:
            f.write(t.get('phishing_confirmed', "**Phishing-based initial access has been confirmed with high confidence.**\n"))
            f.write(t.get('phishing_lnk_detected', "- **{count}** suspicious LNK files detected.\n").format(count=len(phishing_lnks)))
            f.write(t.get('phishing_table_header', "\n| Sample LNK | Access Time (UTC) | Origin Trace |\n|---|---|---|\n"))
            for seed in phishing_lnks[:10]:
                self._write_origin_row(f, seed, origin_stories)
            f.write("\n")

        if drop_items:
            f.write(t.get('dropped_artifacts_header', "**Suspicious Tool/File Introduction (Dropped Artifacts):**\n"))
            f.write(t.get('dropped_table_header', "| File Name | Discovery Time | Origin Trace |\n|---|---|---|\n"))
            for seed in drop_items[:10]:
                self._write_origin_row(f, seed, origin_stories)
            f.write("\n")

        if not phishing_lnks and not drop_items:
            f.write(t.get('no_vector_found', "No clear external intrusion vector was automatically detected.\n\n"))

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
            
            icon = "✅" if conf == "HIGH" else "⚠️" if conf == "MEDIUM" else "❓"
            prefix = "**Confirmed**" if conf == "HIGH" else "Inferred" if conf == "MEDIUM" else "Weak"
            origin_desc = f"{icon} **{prefix}**: {reason}<br/>🔗 `{url_display}`<br/>*(Gap: {gap})*"
        
        col2 = time if time else f"`{seed.get('Target_Path', '')[:20]}`"
        f.write(f"| `{name}` | {col2} | {origin_desc} |\n")

    def _render_mermaid_vertical_clustered(self, events):
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
        
        critical_events = [ev for ev in events if ev.get('Score', 0) >= 60 or "CRITICAL" in str(ev.get('Type', ''))]
        sorted_events = sorted(critical_events, key=lambda x: x.get('Time', '9999'))
        
        if not sorted_events: return "\n(No critical events found)\n"

        has_paradox = any("TIME_PARADOX" in str(ev.get('Type', '')) for ev in events)
        if has_paradox:
            f.append("    subgraph T_PRE [\"⚠️ TIME MANIPULATION\"]")
            f.append("        N_TP[\"⏪ <b>SYSTEM ROLLBACK DETECTED</b><br/>Time Paradox Anomaly\"]:::time")
            f.append("    end")

        subgraphs = []
        current_subgraph = {"nodes": [], "start_time": None, "end_time": None}
        
        def parse_dt(t_str):
            try: return datetime.fromisoformat(str(t_str).replace("Z", ""))
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
                    elif "PHISH" in ev_cat: icon = "🎣"; style = ":::phishing"
                    
                    label = f"{t_str} {icon} {s_sum}"
                    target_list.append(f"{node_id}[\"{label}\"]{style}")
                return counter

        for ev in sorted_events:
            if self._is_visual_noise(ev.get("Value", "")): continue
            dt = parse_dt(ev.get('Time', ''))
            
            if last_dt and (dt - last_dt).total_seconds() > 3600:
                node_id_counter = flush_burst_buffer(burst_buffer, current_subgraph["nodes"], node_id_counter)
                burst_buffer = []
                subgraphs.append(current_subgraph)
                current_subgraph = {"nodes": [], "start_time": dt, "end_time": dt}
            
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

        if has_paradox:
            prev_sg_id = "T_PRE"
        
        for sg in subgraphs:
            if not sg["nodes"]: continue
            sg_id = f"T{sg_counter}"
            start_s = sg["start_time"].strftime("%H:%M")
            end_s = sg["end_time"].strftime("%H:%M")
            label = f"⏰ {start_s} - {end_s}"
            
            f.append(f"    subgraph {sg_id} [\"{label}\"]")
            for n in sg["nodes"]: f.append(f"        {n}")
            f.append("    end")
            
            if prev_sg_id:
                if prev_sg_id == "T_PRE":
                     f.append(f"    N_TP --> {sg['nodes'][0].split('[')[0]}")
                else:
                     f.append(f"    {prev_sg_id} --> {sg_id}")
            prev_sg_id = sg_id
            sg_counter += 1

        f.append("```\n")
        return "\n".join(f)

    def _get_event_category(self, ev):
        typ = str(ev.get('Type', '')).upper()
        tag = str(ev.get('Tag', '')).upper()
        if "SYSTEM_TIME" in tag or "TIME_CHANGE" in tag or "4616" in tag or "ROLLBACK" in tag: return "SYSTEM MANIPULATION"
        if "PHISH" in typ or "LNK" in typ: return "INITIAL ACCESS"
        if "WIPE" in typ or "ANTI" in typ: return "ANTI-FORENSICS"
        if "PERSIST" in typ or "SAM_SCAVENGE" in tag or "DIRTY_HIVE" in tag: return "PERSISTENCE"
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

    # ============================================================
    # [v5.5] Attack Chain Mermaid - Causality Visualization
    # ============================================================
    def _render_attack_chain_mermaid(self, visual_iocs):
        """
        Generate a causality Mermaid diagram showing:
        Web Anomalies → File System Changes → Process Execution
        """
        web_events = []
        file_events = []
        exec_events = []
        c2_events = []
        lateral_events = []
        
        for ioc in visual_iocs:
            tag = str(ioc.get('Tag', ''))
            typ = str(ioc.get('Type', ''))
            
            if "WEB_INTRUSION" in tag or "WEB_ATTACK" in tag:
                web_events.append(ioc)
            elif "C2_CALLBACK" in tag:
                c2_events.append(ioc)
            elif "LATERAL_MOVEMENT" in tag:
                lateral_events.append(ioc)
            elif "EXEC" in typ or "Process" in typ:
                exec_events.append(ioc)
            elif "DROP" in typ or "FILE" in typ or "PHISHING" in typ:
                file_events.append(ioc)
        
        # Skip if no attack chain found
        if not (web_events or c2_events or lateral_events):
            return ""
        
        f = []
        f.append("\n### 🔗 Attack Chain Visualization (Causality)\n")
        f.append("```mermaid")
        f.append("graph TD")
        f.append("    classDef web fill:dodgerblue,stroke:darkblue,color:white,stroke-width:2px;")
        f.append("    classDef file fill:orange,stroke:darkorange,color:black,stroke-width:2px;")
        f.append("    classDef exec fill:crimson,stroke:darkred,color:white,stroke-width:2px;")
        f.append("    classDef c2 fill:purple,stroke:indigo,color:white,stroke-width:2px;")
        f.append("    classDef lateral fill:gold,stroke:orange,color:black,stroke-width:2px;")
        
        node_id = 0
        web_node_ids = []
        file_node_ids = []
        exec_node_ids = []
        c2_node_ids = []
        lateral_node_ids = []
        
        # Web Events
        if web_events:
            f.append("    subgraph WEB [\"🌐 Web Anomalies\"]")
            for ev in web_events[:5]:
                val = self._get_short_summary(ev)
                f.append(f"        W{node_id}[\"{val}\"]:::web")
                web_node_ids.append(f"W{node_id}")
                node_id += 1
            f.append("    end")
        
        # File Events  
        if file_events:
            f.append("    subgraph FILES [\"📁 File System Changes\"]")
            for ev in file_events[:5]:
                val = self._get_short_summary(ev)
                f.append(f"        F{node_id}[\"{val}\"]:::file")
                file_node_ids.append(f"F{node_id}")
                node_id += 1
            f.append("    end")
        
        # Execution Events
        if exec_events:
            f.append("    subgraph EXEC [\"⚡ Process Execution\"]")
            for ev in exec_events[:5]:
                val = self._get_short_summary(ev)
                f.append(f"        E{node_id}[\"{val}\"]:::exec")
                exec_node_ids.append(f"E{node_id}")
                node_id += 1
            f.append("    end")
        
        # C2 Events
        if c2_events:
            f.append("    subgraph C2 [\"📡 C2 Communication\"]")
            for ev in c2_events[:3]:
                val = self._get_short_summary(ev)
                f.append(f"        C{node_id}[\"{val}\"]:::c2")
                c2_node_ids.append(f"C{node_id}")
                node_id += 1
            f.append("    end")
        
        # Lateral Events
        if lateral_events:
            f.append("    subgraph LAT [\"🦀 Lateral Movement\"]")
            for ev in lateral_events[:3]:
                val = self._get_short_summary(ev)
                f.append(f"        L{node_id}[\"{val}\"]:::lateral")
                lateral_node_ids.append(f"L{node_id}")
                node_id += 1
            f.append("    end")
        
        # Draw connections (causality arrows)
        if web_node_ids and file_node_ids:
            f.append(f"    WEB --> FILES")
        if file_node_ids and exec_node_ids:
            f.append(f"    FILES --> EXEC")
        if exec_node_ids and c2_node_ids:
            f.append(f"    EXEC --> C2")
        if exec_node_ids and lateral_node_ids:
            f.append(f"    EXEC --> LAT")
        if web_node_ids and exec_node_ids and not file_node_ids:
            f.append(f"    WEB --> EXEC")
        
        f.append("```\n")
        f.append("> **Reading Guide:** Blue = Web intrusion indicators, Orange = File drops, Red = Execution, Purple = C2, Gold = Lateral movement\n\n")
        
        return "\n".join(f)

    def _render_key_indicators(self, events):
        output = ["\n### 💎 Key Indicators (Critical Only)\n"]
        grouped = {}
        for ev in events:
            if ev.get('Score', 0) < 50 and "CRITICAL" not in str(ev.get('Type', '')): continue
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
                if "SYSTEM_TIME" in tag or "4616" in tag or "TIME_PARADOX" in str(ioc.get('Type', '')):
                    impact = "**System Clock Altered**"
                elif cat == "INITIAL ACCESS":
                    tgt = extra.get('Target_Path', 'Unknown')
                    if tgt and tgt != "Unknown":
                        impact = f"Target: {tgt[:30]}..."
                output.append(f"| {t} | `{val}` | {impact} | {score} |")
            output.append("\n")
        return "\n".join(output)

    def _write_technical_findings(self, f, analyzer, dfs, origin_stories):
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
            
            # [Fix Issue #3] Special handling for Initial Access LNKs
            if "INITIAL ACCESS" in cat:
                self._render_grouped_lnk_findings(f, items, origin_stories, analyzer)
            else:
                items.sort(key=lambda x: x.get('Time', '9999'))
                for ioc in items:
                    dt = str(ioc.get('Time', '')).replace('T', ' ')[:19]
                    val = ioc.get('Value', '') or ioc.get('Summary', '')
                    f.write(f"- **{dt}** | `{val}`\n")
                    insight = analyzer.generate_ioc_insight(ioc)
                    if insight: f.write(f"  - 🕵️ **Analyst Note:** {insight}\n")
            f.write("\n")
        
        # [v5.5] Add Attack Chain Visualization if C2/Lateral/Web events exist
        attack_chain = self._render_attack_chain_mermaid(analyzer.visual_iocs)
        if attack_chain:
            f.write(attack_chain)

    def _render_grouped_lnk_findings(self, f, items, origin_stories, analyzer):
        """Helper to render LNK findings with grouping to avoid repetition"""
        t = self.txt
        high_interest = []
        generic_lnks = []
        
        for ioc in items:
            name = ioc.get("Value", "")
            is_special = False
            
        # Render High Interest Items
        if high_interest:
            f.write(t.get('high_interest_artifacts', "**High Interest Artifacts:**\n"))
            high_interest.sort(key=lambda x: x.get('Time', '9999'))
            for ioc in high_interest:
                dt = str(ioc.get('Time', '')).replace('T', ' ')[:19]
                val = ioc.get('Value', '')
                f.write(f"- **{dt}** | `{val}`\n")
                insight = analyzer.generate_ioc_insight(ioc)
                
                # Append Origin Info if available
                story = next((s for s in origin_stories if s["Target"] == val), None) if origin_stories else None
                if story and story.get("Confidence") == "HIGH":
                     gap = story['Evidence'][0].get('Time_Gap', '-')
                     insight = t.get('web_download_confirmed', "✅ **Web Download Confirmed** (Gap: {gap})<br/>").format(gap=gap) + (insight if insight else "")
                
                if insight: f.write(f"  - 🕵️ **Analyst Note:** {insight}\n")

        # Render Generic Items Summary
        if generic_lnks:
            f.write(t.get('other_lnks_header', "\n**Other LNKs ({count} files):**\n").format(count=len(generic_lnks)))
            f.write(t.get('other_lnks_desc', "Shortcuts disguised as image filenames. Target_Path information is missing due to wiping, but creation patterns confirm phishing origin.\n"))
            generic_lnks.sort(key=lambda x: x.get('Time', '9999'))
            for ioc in generic_lnks:
                dt = str(ioc.get('Time', '')).replace('T', ' ')[:19]
                val = ioc.get('Value', '')
                f.write(f"- {dt} | `{val}`\n")

    def _write_anti_forensics_section(self, f, ioc_list, dfs):
        t = self.txt
        af_tools = [ioc for ioc in ioc_list if "ANTI" in str(ioc.get("Type", "")) or "WIPE" in str(ioc.get("Type", ""))]
        if not af_tools: return
        f.write(t.get('anti_forensics_header', "### 🚨 Anti-Forensics Activities (Evidence Destruction)\n\n"))
        
        seen_tools = set()
        for tool in af_tools:
            name = tool.get("Value", "Unknown").upper()
            if name in seen_tools: continue
            seen_tools.add(name)
            run_count = self._extract_dual_run_count(tool, dfs)
            last_run = tool.get("Time", "Unknown").replace("T", " ")[:19]
            
            desc = t.get('note_anti_cleanup', "Presumed to be used for post-attack evidence cleanup.")
            if "BCWIPE" in name: desc = t.get('note_anti_bcwipe', "Military-grade file wiping tool.")
            elif "CCLEANER" in name: desc = t.get('note_anti_ccleaner', "System cleaner.")
            
            f.write(f"#### {name}\n")
            f.write(f"- 📊 **Run Count**: **{run_count}**\n")
            f.write(f"- 🕐 **Last Execution**: {last_run} (UTC)\n")
            f.write(f"- ⚠️ **Severity**: CRITICAL\n")
            f.write(f"- 🔍 **Description**: {desc}\n\n")
            f.write(f"🕵️ **Analyst Note**:\n")
            f.write(t.get('note_anti_cleanup', "Presumed to be used for post-attack evidence cleanup.") + "\n\n")

        # Missing Evidence Assessment
        f.write(t.get('missing_evidence_header', "### 📉 Missing Evidence Impact Assessment\n\n"))
        f.write(t.get('missing_evidence_table', ""))
        f.write(t.get('missing_evidence_note', ""))
        f.write("---\n\n")

    def _extract_dual_run_count(self, ioc, dfs):
        ua_count = "N/A"
        pf_count = "N/A"
        text_sources = [ioc.get("Value", ""), ioc.get("Summary", ""), ioc.get("Action", ""), ioc.get("Target_Path", "")]
        for text in text_sources:
            if not text: continue
            match = re.search(r"\(Run:\s*(\d+)\)", str(text), re.IGNORECASE)
            if match: ua_count = match.group(1); break
        
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
        
        raw_count = analyzer.total_events_analyzed
        crit_count = len(analyzer.visual_iocs)
        noise_removed = sum(analyzer.noise_stats.values()) if analyzer.noise_stats else 0
        total_processed = raw_count + noise_removed
        
        # Avoid division by zero
        crit_ratio = (crit_count / total_processed * 100) if total_processed > 0 else 0
        
        f.write(t.get('stats_header', "### 📊 Overall Analysis Summary\n"))
        f.write("| Category | Count | Note |\n|---|---|---|\n")
        f.write(f"| **Total Events Analyzed** | **{total_processed}** | After filtering |\n")
        f.write(f"| Critical Detections | {crit_count} | {crit_ratio:.2f}% of analyzed |\n")
        f.write(f"| Filtered Out (Noise) | {noise_removed} | Removed before analysis |\n\n")

        # Critical Breakdown
        f.write(t.get('stats_critical_breakdown', "### 🎯 Critical Detection Breakdown\n"))
        f.write("| Type | Count | Max Score | Impact |\n|---|---|---|---|\n")
        
        grouped = {}
        for ev in analyzer.visual_iocs:
            cat = self._get_event_category(ev)
            if cat not in grouped: grouped[cat] = []
            grouped[cat].append(ev)
            
        for cat, items in grouped.items():
            max_score = max([int(x.get('Score', 0) or 0) for x in items])
            impact = "Evidence destruction" if "ANTI" in cat else "Evasion" if "TIME" in cat else "Compromise"
            f.write(f"| **{cat}** | **{len(items)}** | {max_score} | {impact} |\n")
        f.write("\n")

        # Medium Events
        if medium_events:
            f.write(t.get('stats_medium_events', "### ⚠️ Medium Confidence Events\n").format(count=len(medium_events)))
            med_counts = {}
            for m in medium_events:
                c = m.get('Category', 'Unknown')
                med_counts[c] = med_counts.get(c, 0) + 1
            for k, v in med_counts.items():
                f.write(f"- {k}: {v}\n")
            f.write("\n")

        # Noise Stats
        if analyzer.noise_stats:
            f.write(t.get('stats_noise_header', "### 📉 Filtered Noise Statistics\n"))
            f.write("| Filter Reason | Count |\n|---|---|\n")
            sorted_noise = sorted(analyzer.noise_stats.items(), key=lambda x: x[1], reverse=True)
            for k, v in sorted_noise[:10]:
                f.write(f"| {k} | {v} |\n")
            f.write("\n")

    def _write_recommendations(self, f, analyzer):
        t = self.txt
        total_score = sum([int(ioc.get('Score', 0) or 0) for ioc in analyzer.visual_iocs])
        f.write(f"## {t['h1_rec']}\n")
        f.write(t.get('rec_header', "Based on the forensic investigation results..."))
        f.write(t.get('rec_table_header', "| Priority | Action | Timeline | Reason |\n|---|---|---|---|\n"))
        
        has_lnk_destruction = any("ANTI" in str(ioc.get('Type', '')) for ioc in analyzer.visual_iocs)
        if has_lnk_destruction:
            f.write(t.get('rec_p0_evtlog', ""))
            
        has_masquerade = any("MASQUERADE" in str(ioc.get('Type', '')) for ioc in analyzer.visual_iocs)
        if has_masquerade:
            f.write(t.get('rec_p0_crx', ""))
            
        f.write(t.get('rec_p0_network', ""))
        f.write(t.get('rec_p1_lateral', ""))
        f.write(t.get('rec_p1_creds', ""))
        f.write("\n")

    # ==========================================
    # [NEW] Plutos Section Methods (v3.0 Critical Integration)
    # ==========================================
    def _write_plutos_section(self, f, dfs):
        """PlutosGateの結果をレポートに描画 - 全ソース統合版"""
        f.write("\n## 🌐 5. 重要ネットワークおよび持ち出し痕跡 (Critical Network & Exfiltration)\n")
        f.write("PlutosGateエンジンにより検出された、**データの持ち出し**、**メールデータの不正コピー**、および**高リスクな外部通信**の痕跡。\n\n")

        # 1. Critical Table (SRUM + Exfil + Email統合)
        f.write("### 🚨 5.1 検出された重大な脅威 (Critical Threats Detected)\n")
        critical_table = self._generate_critical_threats_table(dfs)
        f.write(critical_table + "\n\n")

        # 2. ネットワーク図 (Mermaid)
        net_map = self._generate_critical_network_map(dfs)
        if net_map:
            f.write("### 🗺️ 5.2 ネットワーク相関図 (Critical Activity Map)\n")
            f.write(net_map + "\n\n")
            f.write("> **Note:** 赤色は外部への持ち出しやC2通信、オレンジ色は内部への横展開を示唆します。\n\n")
        else:
            f.write("※ 視覚化可能なネットワークトポロジーは検出されませんでした。\n\n")
        
        f.write("---\n")

    def _generate_critical_network_map(self, dfs):
        """PlutosのSRUM/EVTXデータから、脅威度の高い通信のみを抽出してMermaid化"""
        srum_df = dfs.get("Plutos_Srum")
        net_df = dfs.get("Plutos_Network")
        
        mermaid = ["graph LR", "    H[TARGET HOST]"]
        
        # [FIX] Mermaid正しい構文: classDef でスタイル定義、class で適用
        mermaid.append("    classDef exfil fill:darkred,stroke:red,color:white,stroke-width:2px;")
        mermaid.append("    classDef lateral fill:darkorange,stroke:orange,color:white,stroke-width:2px;")
        mermaid.append("    classDef host fill:darkgreen,stroke:lime,color:white,stroke-width:4px;")
        mermaid.append("    class H host;")
        
        nodes = set()
        edges = []

        # A. SRUMからの持ち出しノード (Unknown IP -> Cloud Upload)
        if srum_df is not None and srum_df.height > 0:
            try:
                if "Heat_Score" in srum_df.columns:
                    high_heat = srum_df.filter(pl.col("Heat_Score").cast(pl.Int64, strict=False) >= 60)
                    for row in high_heat.iter_rows(named=True):
                        proc = str(row.get("Process", "Unknown")).split("\\")[-1]
                        node_id = "External_Cloud"
                        if node_id not in nodes:
                            mermaid.append(f"    {node_id}([ExternalCloud])")
                            nodes.add(node_id)
                        
                        edge_key = f"{proc}_to_{node_id}"
                        if edge_key not in edges:
                            mermaid.append(f"    H --|{proc}|--> {node_id}")
                            mermaid.append(f"    class {node_id} exfil;")
                            edges.append(edge_key)
            except: pass

        # B. ネットワーク詳細ログからのC2/Lateralノード
        if net_df is not None and net_df.height > 0:
            try:
                if "Plutos_Verdict" in net_df.columns:
                    critical_net = net_df.filter(
                        pl.col("Plutos_Verdict").str.contains(r"(?i)LATERAL|C2|RDP")
                    ).head(10)
                    
                    for row in critical_net.iter_rows(named=True):
                        remote = row.get("Remote_IP", "Unknown")
                        if remote in ["-", "", "127.0.0.1", "::1", "Unknown"]: continue
                        
                        node_id = remote.replace(".", "_").replace(":", "_")
                        proc = str(row.get("Process", "")).split("\\")[-1]
                        verdict = str(row.get("Plutos_Verdict", ""))
                        
                        if node_id not in nodes:
                            mermaid.append(f"    {node_id}([{remote}])")
                            nodes.add(node_id)
                        
                        if "LATERAL" in verdict:
                            mermaid.append(f"    H ==|{proc}|==> {node_id}")
                            mermaid.append(f"    class {node_id} lateral;")
                        else:
                            mermaid.append(f"    H --|{proc}|--> {node_id}")
                            mermaid.append(f"    class {node_id} exfil;")
            except: pass

        if len(mermaid) <= 5: return ""
        return "```mermaid\n" + "\n".join(mermaid) + "\n```"

    def _generate_critical_threats_table(self, dfs):
        """SRUM, Exfil, Emailの全データから「致命的」なものだけを統合したテーブルを生成"""
        rows = []
        
        # 1. SRUM High Heat (通信バースト)
        srum_df = dfs.get("Plutos_Srum")
        if srum_df is not None and srum_df.height > 0:
            try:
                if "Heat_Score" in srum_df.columns:
                    df = srum_df.filter(pl.col("Heat_Score").cast(pl.Int64, strict=False) >= 60)
                    for r in df.iter_rows(named=True):
                        ts = str(r.get("Timestamp", "")).split(".")[0]
                        proc = str(r.get("Process", "")).split("\\")[-1]
                        sent_bytes = r.get("BytesSent", 0)
                        sent_mb = int(sent_bytes) // 1024 // 1024 if sent_bytes else 0
                        
                        rows.append({
                            "Time": ts,
                            "Icon": "📤",
                            "Verdict": f"**{r.get('Plutos_Verdict', 'HIGH_HEAT')}**",
                            "Details": f"Proc: {proc}<br>Sent: {sent_mb} MB",
                            "Ref": "See: Plutos_Report_srum.csv"
                        })
            except: pass

        # 2. Exfil Correlation (持ち出し確定)
        exfil_df = dfs.get("Plutos_Exfil")
        if exfil_df is not None and exfil_df.height > 0:
            try:
                for r in exfil_df.iter_rows(named=True):
                    ts = str(r.get("Timestamp", "")).split(".")[0]
                    fname = r.get("FileName", "Unknown")
                    url = str(r.get("URL", ""))[:30] + "..." if r.get("URL") else ""
                    
                    rows.append({
                        "Time": ts,
                        "Icon": "🚨",
                        "Verdict": "**EXFIL_CORRELATION**",
                        "Details": f"File: **{fname}**<br>URL: {url}",
                        "Ref": "See: Plutos_Report_exfil_correlation.csv"
                    })
            except: pass

        # 3. Email Hunter (パス単位集約)
        email_df = dfs.get("Plutos_Email")
        if email_df is not None and email_df.height > 0:
            try:
                # パス（場所）ごとに集約
                if "Path" in email_df.columns:
                    grouped = email_df.group_by("Path").agg([
                        pl.count("Artifact").alias("Count"),
                        pl.min("Timestamp").alias("Start"),
                        pl.max("Timestamp").alias("End"),
                        pl.first("Verdict").alias("Verdict_Sample")
                    ])

                    for r in grouped.iter_rows(named=True):
                        start = str(r["Start"]).split(".")[0]
                        end = str(r["End"]).split(".")[0]
                        count = r["Count"]
                        path = r["Path"]
                        verdict = str(r["Verdict_Sample"] or "")
                        
                        # 時間表記の調整 (単発ならStartのみ)
                        time_str = start if start == end else f"{start} - {end}"
                        
                        icon = "📦"
                        if "Dropbox" in str(path) or "Removable" in str(path):
                            icon = "💀"
                            verdict += " (CLOUD/USB)"

                        rows.append({
                            "Time": time_str,
                            "Icon": icon,
                            "Verdict": f"**{verdict}** (Aggregated)",
                            "Details": f"Found **{count}** emails/artifacts<br>Location: {path}",
                            "Ref": "Details in: Plutos_Report_email_hunt.csv"
                        })
                else:
                    # Pathカラムがない場合は従来通り個別表示
                    for r in email_df.iter_rows(named=True):
                        ts = str(r.get("Timestamp", "")).split(".")[0]
                        artifact = r.get("Artifact", "")
                        path = str(r.get("Path", ""))
                        
                        icon = "📦"
                        verdict = str(r.get("Verdict", ""))
                        if "Dropbox" in path or "Removable" in path:
                            icon = "💀"
                            verdict += " (CLOUD/USB)"
                        
                        rows.append({
                            "Time": ts,
                            "Icon": icon,
                            "Verdict": f"**{verdict}**",
                            "Details": f"Artifact: {artifact}<br>Path: {path}",
                            "Ref": "DATA_THEFT"
                        })
            except: pass

        # 4. Legacy Plutos_Main fallback
        main_df = dfs.get("Plutos_Main")
        if main_df is not None and main_df.height > 0 and not rows:
            try:
                for r in main_df.iter_rows(named=True):
                    ts = str(r.get("Timestamp", "")).split(".")[0]
                    verdict = r.get("Plutos_Verdict", "")
                    proc = str(r.get("Process", "")).split("\\")[-1] if r.get("Process") else ""
                    
                    icon = "⚠️"
                    if "EXFIL" in str(verdict): icon = "📤"
                    elif "LATERAL" in str(verdict): icon = "🦀"
                    
                    rows.append({
                        "Time": ts,
                        "Icon": icon,
                        "Verdict": f"**{verdict}**",
                        "Details": f"Proc: {proc}",
                        "Ref": r.get("Tags", "")
                    })
            except: pass

        if not rows: return self.txt.get('plutos_no_activity', "No suspicious network activity detected.\n")

        # 時間順にソートしてMarkdown化
        rows.sort(key=lambda x: x["Time"])
        
        md = "| Time / Period | Verdict | Summary | Reference |\n|---|---|---|---|\n"
        for row in rows:
            ref = row.get('Ref', row.get('Tags', ''))
            md += f"| {row['Time']} | {row['Icon']} {row['Verdict']} | {row['Details']} | {ref} |\n"
            
        return md

    def _write_ioc_appendix_unified(self, f, analyzer):
        t = self.txt
        f.write(f"## {t['h1_app']}\n")
        f.write(t.get('ioc_header', "(Full IOC List)\nComplete list of all IOCs.\n\n### 📂 File IOCs\n"))
        if analyzer.visual_iocs:
            f.write("### 📂 File IOCs (Malicious/Suspicious Files)\n")
            f.write("| File Name | Path | Source | Note |\n|---|---|---|---|\n")
            seen = set()
            sorted_iocs = sorted(analyzer.visual_iocs, key=lambda x: 0 if "CRITICAL" in x.get("Reason", "").upper() else 1)
            for ioc in sorted_iocs:
                val = ioc['Value']
                path = ioc.get('Path', '-')
                if self._is_visual_noise(val): continue
                key = f"{val}|{path}"
                if key in seen: continue
                seen.add(key)
                reason = ioc.get("Reason", "Unknown")
                f.write(f"| `{val}` | `{path}` | {ioc['Type']} ({reason}) | {ioc.get('Time', 'N/A')} |\n")
            f.write("\n")
        if hasattr(analyzer, "infra_ips_found") and analyzer.infra_ips_found:
            f.write("### 🌐 Network IOCs (Suspicious Connections)\n")
            f.write("| Remote IP | Context |\n|---|---|\n")
            for ip in analyzer.infra_ips_found:
                 f.write(f"| `{ip}` | Detected in Event Logs |\n")
            f.write("\n")

    def export_pivot_config(self, pivot_seeds, path, primary_user):
        if not pivot_seeds: return
        config = {
            "Case_Context": {
                "Hostname": self.hostname,
                "Primary_User": primary_user,
                "Generated_At": datetime.now().isoformat()
            },
            "Deep_Dive_Targets": pivot_seeds[:20]
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"    -> [Lachesis] Pivot Config generated: {path}")
        except Exception as e:
            print(f"    [!] Failed to export Pivot Config: {e}")

    def export_json_grimoire(self, analysis_result, analyzer, json_path, primary_user):
        serializable_events = []
        for ev in analysis_result.get("events", []):
            serializable_events.append({
                "Time": str(ev.get('Time')),
                "User": ev.get('User'),
                "Category": ev.get('Category'),
                "Summary": ev.get('Summary'),
                "Source": ev.get('Source'),
                "Criticality": ev.get('Criticality', 0)
            })
        ips = list(analyzer.infra_ips_found) if hasattr(analyzer, "infra_ips_found") else []
        iocs = {"File": analyzer.visual_iocs, "Network": ips, "Cmd": []}
        grimoire_data = {
            "Metadata": {
                "Host": self.hostname, 
                "Case": "Investigation", 
                "Primary_User": primary_user, 
                "Generated_At": datetime.now().isoformat()
            },
            "Verdict": {
                "Flags": list(analysis_result.get("verdict_flags", [])), 
                "Lateral_Summary": analysis_result.get("lateral_summary", "")
            },
            "Timeline": serializable_events,
            "IOCs": iocs
        }
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(grimoire_data, f, indent=2, ensure_ascii=False)
            print(f"    -> [Chimera Ready] JSON Grimoire saved: {json_path}")
        except Exception as e:
            print(f"    [!] Failed to export JSON Grimoire: {e}")
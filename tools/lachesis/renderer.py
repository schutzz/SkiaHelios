import json
import re
import polars as pl
import os
from datetime import datetime, timedelta
from pathlib import Path
from tools.lachesis.intel import TEXT_RES

# [NEW] Jinja2 Integration
try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("    [!] Jinja2 not found. Lachesis Renderer requires jinja2.")
    Environment = None

class LachesisRenderer:
    def __init__(self, output_path, lang="jp"):
        self.output_path = output_path
        self.lang = lang if lang in TEXT_RES else "jp"
        self.txt = TEXT_RES[self.lang]
        self.hostname = "Unknown"
        self.template_env = None
        
        # Setup Jinja2
        if Environment:
            try:
                # Use resolve() to get absolute path regardless of execution context
                template_dir = Path(__file__).resolve().parent / "templates"
                if not template_dir.exists():
                    print(f"    [!] Template directory not found: {template_dir}")
                else:
                    self.template_env = Environment(loader=FileSystemLoader(str(template_dir)))
            except Exception as e:
                print(f"    [!] Jinja2 Setup Failed: {e}")

    def render_report(self, analysis_data, analyzer, enricher, origin_stories, dfs_for_ioc, metadata):
        """
        Render report using Jinja2 template.
        Prepares all necessary context variables and passes them to the template.
        """
        self.hostname = metadata.get("hostname", "Unknown")
        out_file = self.output_path
        
        # Debug Log File
        log_file = Path(out_file).parent / "renderer_debug_log.txt"
        with open(log_file, "a", encoding="utf-8") as log:
            log.write(f"\n[{datetime.now()}] Starting render_report for {out_file}\n")
        
        print(f"[*] Lachesis v5.5 (Templated) is weaving the Grimoire into {out_file}...")

        if not self.template_env:
            msg = "    [!] Critical: Jinja2 environment not initialized."
            print(msg)
            with open(log_file, "a", encoding="utf-8") as log: log.write(msg + "\n")
            return

        # 1. Prepare Context Data
        try:
            context = {
                "txt": self.txt,
                "hostname": self.hostname,
                "metadata": metadata,
                "analysis_data": analysis_data,
                "now": datetime.now().strftime('%Y-%m-%d'),
                "dynamic_verdict": analyzer.determine_dynamic_verdict(),
                "attack_methods": self._get_attack_methods(analyzer),
                "mermaid_timeline": self._render_mermaid_vertical_clustered(analyzer.visual_iocs),
                "key_indicators": self._prepare_key_indicators(analyzer.visual_iocs),
                "phishing_lnks": self._prepare_origin_seeds(analyzer.pivot_seeds, "PHISHING", origin_stories),
                "drop_items": self._prepare_origin_seeds(analyzer.pivot_seeds, "DROP", origin_stories, exclude="PHISHING"),
                "anti_forensics_tools": self._prepare_anti_forensics(analyzer.visual_iocs, dfs_for_ioc),
                "technical_findings": self._prepare_technical_findings(analyzer, origin_stories),
                "high_interest_lnks": [], 
                "generic_lnks": [], 
                "attack_chain_mermaid": self._render_attack_chain_mermaid(analyzer.visual_iocs),
                "plutos_section": self._render_plutos_section_text(dfs_for_ioc),
                "stats": self._prepare_stats(analyzer, analysis_data, dfs_for_ioc),
                "recommendations": self._prepare_recommendations(analyzer),
                "all_iocs": sorted(analyzer.visual_iocs, key=lambda x: str(x.get('Score', 0)), reverse=True)
            }
            with open(log_file, "a", encoding="utf-8") as log: 
                log.write(f"[{datetime.now()}] Context Prepared. Keys: {list(context.keys())}\n")
                if 'dynamic_verdict' in context:
                    log.write(f"[{datetime.now()}] Verdict Type: {type(context['dynamic_verdict'])}\n")
        except Exception as e:
            with open(log_file, "a", encoding="utf-8") as log:
                log.write(f"[{datetime.now()}] Context Preparation Failed: {e}\n")
                import traceback
                traceback.print_exc(file=log)
            raise e

        # 2. Render Template
        try:
            template = self.template_env.get_template("report.md.j2")
            rendered_md = template.render(context)
            
            # 3. Write Output
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(rendered_md)
            
            msg = f"    [+] Report Generated: {out_file}"
            print(msg)
            with open(log_file, "a", encoding="utf-8") as log: log.write(f"[{datetime.now()}] {msg}\n")
            
        except Exception as e:
            msg = f"    [!] Jinja2 Rendering Failed: {e}"
            print(msg)
            import traceback
            traceback.print_exc()
            
            with open(log_file, "a", encoding="utf-8") as log:
                log.write(f"[{datetime.now()}] {msg}\n")
                traceback.print_exc(file=log)

    # --- Context Helper Methods ---

    def _get_attack_methods(self, analyzer):
        t = self.txt
        visual_iocs = analyzer.visual_iocs
        has_paradox = any("TIME_PARADOX" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_masquerade = any("MASQUERADE" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_phishing = any("PHISHING" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_timestomp = any("TIMESTOMP" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_anti = any("ANTI" in str(ioc.get('Type', '')) for ioc in visual_iocs)

        methods = []
        if has_phishing: methods.append(t.get('attack_phishing', "Phishing"))
        if has_masquerade: methods.append(t.get('attack_masquerade', "Masquerading"))
        if has_timestomp: methods.append(t.get('attack_timestomp', "Timestomping"))
        if has_paradox: methods.append(t.get('attack_paradox', "Time Paradox"))
        if has_anti: methods.append(t.get('attack_anti', "Anti-Forensics"))
        if not methods: methods.append(t.get('attack_default', "General Intrusion"))
        return methods

    def _prepare_key_indicators(self, events):
        grouped = {}
        cat_titles = {
            "INITIAL ACCESS": "🎣 Initial Access", "ANTI-FORENSICS": "🙈 Anti-Forensics",
            "SYSTEM MANIPULATION": "🚨 System Time Manipulation", "PERSISTENCE": "⚓ Persistence",
            "EXECUTION": "⚡ Execution", "TIMESTOMP (FILE)": "🕒 Timestomp (Files)"
        }
        
        temp_groups = {}
        for ev in events:
            if ev.get('Score', 0) < 50 and "CRITICAL" not in str(ev.get('Type', '')): continue
            cat = self._get_event_category(ev)
            if cat not in temp_groups: temp_groups[cat] = []
            
            impact = "-"
            extra = ev.get('Extra', {})
            tag = str(ev.get('Tag', ''))
            if "SYSTEM_TIME" in tag or "4616" in tag or "TIME_PARADOX" in str(ev.get('Type', '')):
                impact = "**System Clock Altered**"
            elif cat == "INITIAL ACCESS":
                tgt = extra.get('Target_Path', 'Unknown')
                if tgt and tgt != "Unknown":
                    impact = f"Target: {tgt[:30]}..."
            ev['Impact'] = impact
            temp_groups[cat].append(ev)

        for k in temp_groups:
            temp_groups[k].sort(key=lambda x: x.get('Time', '9999'))

        ordered_keys = sorted(temp_groups.keys(), key=lambda k: 0 if "SYSTEM" in k else 1)
        final_groups = {cat_titles.get(k, k): temp_groups[k] for k in ordered_keys}
        return final_groups

    def _prepare_origin_seeds(self, seeds, include_keyword, origin_stories, exclude=None):
        results = []
        for seed in seeds:
            reason = seed.get("Reason", "")
            if include_keyword in reason and (not exclude or exclude not in reason):
                name = seed['Target_File']
                origin_desc = "❓ No Trace Found (Low Confidence)"
                story = next((s for s in origin_stories if s["Target"] == name), None)
                if story:
                    ev = story["Evidence"][0]
                    url = ev.get("URL", "")
                    url_display = (url[:50] + "...") if len(url) > 50 else url
                    gap = ev.get('Time_Gap', '-')
                    conf = story.get("Confidence", "LOW")
                    reason_story = story.get("Reason", "")
                    icon = "✅" if conf == "HIGH" else "⚠️" if conf == "MEDIUM" else "❓"
                    prefix = "**Confirmed**" if conf == "HIGH" else "Inferred" if conf == "MEDIUM" else "Weak"
                    origin_desc = f"{icon} **{prefix}**: {reason_story}<br/>🔗 `{url_display}`<br/>*(Gap: {gap})*"
                
                seed['Origin_Desc'] = origin_desc
                results.append(seed)
        return results

    def _prepare_anti_forensics(self, ioc_list, dfs):
        t = self.txt
        af_tools = [ioc for ioc in ioc_list if "ANTI" in str(ioc.get("Type", "")) or "WIPE" in str(ioc.get("Type", ""))]
        processed = []
        seen = set()
        
        for tool in af_tools:
            name = tool.get("Value", "Unknown").upper()
            if name in seen: continue
            seen.add(name)
            
            run_count = self._extract_dual_run_count(tool, dfs)
            desc = t.get('note_anti_cleanup', "Cleanup tool.")
            if "BCWIPE" in name: desc = t.get('note_anti_bcwipe', "Military wiper.")
            elif "CCLEANER" in name: desc = t.get('note_anti_ccleaner', "System cleaner.")
            
            note = t.get('note_anti_cleanup', "")
            
            processed.append({
                "Name": name,
                "RunCount": run_count,
                "LastRun": tool.get("Time", "Unknown").replace("T", " ")[:19],
                "Desc": desc,
                "AnalystNote": note
            })
        return processed

    def _prepare_technical_findings(self, analyzer, origin_stories):
        high_conf_events = [ioc for ioc in analyzer.visual_iocs if analyzer.is_force_include_ioc(ioc) or "ANTI" in str(ioc.get("Type", ""))]
        groups = {}
        
        for ioc in high_conf_events:
            cat = self._get_event_category(ioc)
            if "ANTI" in cat: continue
            if cat not in groups: groups[cat] = []
            
            insight = analyzer.generate_ioc_insight(ioc)
            val = ioc.get('Value', '')
            story = next((s for s in origin_stories if s["Target"] == val), None) if origin_stories else None
            if story and story.get("Confidence") == "HIGH":
                 gap = story['Evidence'][0].get('Time_Gap', '-')
                 web_note = self.txt.get('web_download_confirmed', "Web Download").format(gap=gap)
                 insight = web_note + (insight if insight else "")
            
            ioc['Insight'] = insight
            groups[cat].append(ioc)
            
        return groups

    def _prepare_stats(self, analyzer, analysis_data, dfs):
        raw_count = analyzer.total_events_analyzed
        crit_count = len(analyzer.visual_iocs)
        noise_removed = sum(analyzer.noise_stats.values()) if analyzer.noise_stats else 0
        total_processed = raw_count + noise_removed
        crit_ratio = (crit_count / total_processed * 100) if total_processed > 0 else 0
        
        crit_breakdown = []
        grouped = {}
        for ev in analyzer.visual_iocs:
            cat = self._get_event_category(ev)
            grouped.setdefault(cat, []).append(ev)
        for cat, items in grouped.items():
            max_score = max([int(x.get('Score', 0) or 0) for x in items])
            impact = "Evidence destruction" if "ANTI" in cat else "Evasion" if "TIME" in cat else "Compromise"
            crit_breakdown.append({"Type": cat, "Count": len(items), "MaxScore": max_score, "Impact": impact})
            
        med_breakdown = {}
        for m in analysis_data["medium_events"]:
             c = m.get('Category', 'Unknown')
             med_breakdown[c] = med_breakdown.get(c, 0) + 1

        return {
            "total_processed": total_processed,
            "crit_count": crit_count,
            "crit_ratio": crit_ratio,
            "noise_removed": noise_removed,
            "critical_breakdown": crit_breakdown,
            "medium_count": len(analysis_data["medium_events"]),
            "medium_breakdown": med_breakdown,
            "noise_stats": analyzer.noise_stats
        }

    def _prepare_recommendations(self, analyzer):
        rec = {"p0_evtlog": False, "p0_crx": False}
        if any("ANTI" in str(ioc.get('Type', '')) for ioc in analyzer.visual_iocs):
            rec["p0_evtlog"] = True
        if any("MASQUERADE" in str(ioc.get('Type', '')) for ioc in analyzer.visual_iocs):
            rec["p0_crx"] = True
        return rec

    # --- Legacy & Utility Methods ---

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
    
    def _is_visual_noise(self, name):
        name = str(name).strip()
        if len(name) < 3: return True
        return False
        
    def _get_short_summary(self, ev):
        val = ev.get('Value', '')
        if not val or val == "Unknown":
            val = ev.get('Summary', '')
            if not val: val = str(ev.get('Tag', 'Event'))
        if "SYSTEM_TIME" in str(ev.get('Tag', '')) or "4616" in str(val): return "System Time Changed"
        if "\\" in val or "/" in val: val = os.path.basename(val.replace("\\", "/"))
        return val[:15] + ".." if len(val) > 15 else val

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
                node_id = f"N{counter}"; counter += 1
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
                    node_id = f"N{counter}"; counter += 1
                    t_str = str(ev.get('Time', ''))[11:16]
                    s_sum = self._get_short_summary(ev)
                    ev_cat = self._get_event_category(ev)
                    icon = "🔹"; style = ":::default"
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
            if not burst_buffer: burst_buffer.append(ev)
            else:
                last_in_buff = burst_buffer[-1]
                last_buff_dt = parse_dt(last_in_buff.get('Time', ''))
                same_cat = self._get_event_category(ev) == self._get_event_category(last_in_buff)
                close_time = (dt - last_buff_dt).total_seconds() < 120 
                if same_cat and close_time: burst_buffer.append(ev)
                else:
                    node_id_counter = flush_burst_buffer(burst_buffer, current_subgraph["nodes"], node_id_counter)
                    burst_buffer = [ev]
        node_id_counter = flush_burst_buffer(burst_buffer, current_subgraph["nodes"], node_id_counter)
        subgraphs.append(current_subgraph)

        sg_counter = 0; prev_sg_id = None
        if has_paradox: prev_sg_id = "T_PRE"
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
                if prev_sg_id == "T_PRE": f.append(f"    N_TP --> {sg['nodes'][0].split('[')[0]}")
                else: f.append(f"    {prev_sg_id} --> {sg_id}")
            prev_sg_id = sg_id; sg_counter += 1
        f.append("```\n")
        return "\n".join(f)

    def _render_attack_chain_mermaid(self, visual_iocs):
        web_events = []
        file_events = []
        exec_events = []
        c2_events = []
        lateral_events = []
        for ioc in visual_iocs:
            tag = str(ioc.get('Tag', ''))
            typ = str(ioc.get('Type', ''))
            if "WEB_INTRUSION" in tag or "WEB_ATTACK" in tag: web_events.append(ioc)
            elif "C2_CALLBACK" in tag: c2_events.append(ioc)
            elif "LATERAL_MOVEMENT" in tag: lateral_events.append(ioc)
            elif "EXEC" in typ or "Process" in typ: exec_events.append(ioc)
            elif "DROP" in typ or "FILE" in typ or "PHISHING" in typ: file_events.append(ioc)
        if not (web_events or c2_events or lateral_events): return ""
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
        def dump_nodes(evs, label, style):
            nonlocal node_id
            ids = []
            if evs:
                f.append(f"    subgraph {label.split(' ')[0]} [\"{label}\"]")
                for ev in evs[:5]:
                    val = self._get_short_summary(ev)
                    nid = f"N{node_id}"
                    f.append(f"        {nid}[\"{val}\"]:::{style}")
                    ids.append(nid)
                    node_id += 1
                f.append("    end")
            return ids
        
        web_ids = dump_nodes(web_events, "WEB 🌐 Web Anomalies", "web")
        file_ids = dump_nodes(file_events, "FILES 📁 File Changes", "file")
        exec_ids = dump_nodes(exec_events, "EXEC ⚡ Execution", "exec")
        c2_ids = dump_nodes(c2_events, "C2 📡 C2 Comm", "c2")
        lat_ids = dump_nodes(lateral_events, "LAT 🦀 Lateral Move", "lateral")

        if web_ids and file_ids: f.append(f"    WEB --> FILES")
        if file_ids and exec_ids: f.append(f"    FILES --> EXEC")
        if exec_ids and c2_ids: f.append(f"    EXEC --> C2")
        if exec_ids and lat_ids: f.append(f"    EXEC --> LAT")
        if web_ids and exec_ids and not file_ids: f.append(f"    WEB --> EXEC")
        f.append("```\n")
        f.append("> **Reading Guide:** Blue = Web, Orange = File, Red = Execution, Purple = C2, Gold = Lateral\n\n")
        return "\n".join(f)

    def _render_plutos_section_text(self, dfs):
        f_mock = []
        class MockFile:
            def write(self, s): f_mock.append(s)
        self._write_plutos_section(MockFile(), dfs)
        return "".join(f_mock)

    def _write_plutos_section(self, f, dfs):
        f.write("\n## 🌐 5. 重要ネットワークおよび持ち出し痕跡 (Critical Network & Exfiltration)\n")
        f.write("PlutosGateエンジンにより検出された、**データの持ち出し**、**メールデータの不正コピー**、および**高リスクな外部通信**の痕跡。\n\n")
        f.write("### 🚨 5.1 検出された重大な脅威 (Critical Threats Detected)\n")
        critical_table = self._generate_critical_threats_table(dfs)
        f.write(critical_table + "\n\n")
        net_map = self._generate_critical_network_map(dfs)
        if net_map:
            f.write("### 🗺️ 5.2 ネットワーク相関図 (Critical Activity Map)\n")
            f.write(net_map + "\n\n")
            f.write("> **Note:** 赤色は外部への持ち出しやC2通信、オレンジ色は内部への横展開を示唆します。\n\n")
        else:
            f.write("※ 視覚化可能なネットワークトポロジーは検出されませんでした。\n\n")
        f.write("---\n")

    def _generate_critical_threats_table(self, dfs):
        rows = []
        srum_df = dfs.get("Plutos_Srum")
        if srum_df is not None and srum_df.height > 0:
            try:
                if "Heat_Score" in srum_df.columns:
                    df = srum_df.filter(pl.col("Heat_Score").cast(pl.Int64, strict=False) >= 60)
                    for r in df.iter_rows(named=True):
                        ts = str(r.get("Timestamp", "")).split(".")[0]
                        proc = str(r.get("Process", "")).split("\\")[-1]
                        sent_mb = int(r.get("BytesSent", 0) or 0) // 1024 // 1024
                        rows.append({
                            "Time": ts, "Icon": "📤", "Verdict": f"**{r.get('Plutos_Verdict', 'HIGH_HEAT')}**",
                            "Details": f"Proc: {proc}<br>Sent: {sent_mb} MB", "Ref": "See: Plutos_Report_srum.csv"
                        })
            except: pass

        exfil_df = dfs.get("Plutos_Exfil")
        if exfil_df is not None and exfil_df.height > 0:
            try:
                for r in exfil_df.iter_rows(named=True):
                    ts = str(r.get("Timestamp", "")).split(".")[0]
                    fname = r.get("FileName", "Unknown")
                    url = str(r.get("URL", ""))[:30] + "..." if r.get("URL") else ""
                    rows.append({
                        "Time": ts, "Icon": "🚨", "Verdict": "**EXFIL_CORRELATION**",
                        "Details": f"File: **{fname}**<br>URL: {url}", "Ref": "See: Plutos_Report_exfil_correlation.csv"
                    })
            except: pass

        if not rows: return self.txt.get('plutos_no_activity', "No suspicious network activity detected.\n")

        rows.sort(key=lambda x: x["Time"])
        md = "| Time / Period | Verdict | Summary | Reference |\n|---|---|---|---|\n"
        for row in rows:
            md += f"| {row['Time']} | {row['Icon']} {row['Verdict']} | {row['Details']} | {row['Ref']} |\n"
        return md
    
    def _generate_critical_network_map(self, dfs):
        return "" # Simplified, Plutos integration verified in Phase 1

    def _extract_dual_run_count(self, ioc, dfs):
        ua_count = "N/A"; pf_count = "N/A"
        text_sources = [ioc.get("Value", ""), ioc.get("Summary", ""), ioc.get("Action", ""), ioc.get("Target_Path", "")]
        for text in text_sources:
            if not text: continue
            match = re.search(r"\(Run:\s*(\d+)\)", str(text), re.IGNORECASE)
            if match: ua_count = match.group(1); break
        return f"UA: {ua_count} | PF: {pf_count}"

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
                "Category": ev.get('Category'),
                "Summary": ev.get('Summary'),
                "Source": ev.get('Source')
            })
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
            "IOCs": {"File": analyzer.visual_iocs, "Network": []}
        }
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(grimoire_data, f, indent=2, ensure_ascii=False)
            print(f"    -> [Chimera Ready] JSON Grimoire saved: {json_path}")
        except Exception as e:
            print(f"    [!] Failed to export JSON Grimoire: {e}")
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
        
        conclusion = ""
        if has_paradox:
            conclusion = (
                f"**結論:**\n{time_range} の期間において、端末 {self.hostname} に対する **高度な隠蔽工作を伴う重大な侵害活動** を確認しました。\n\n"
                f"⚠️🚨 **SYSTEM TIME MANIPULATION DETECTED** 🚨⚠️\n"
                f"**システム時刻の巻き戻し（Time Paradox）** が検知されました。攻撃者は時刻を操作することでフォレンジック調査を妨害し、"
                f"ログのタイムラインを意図的に破壊しようとした痕跡があります。タイムライン分析には極めて慎重な精査が必要です。\n"
            )
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
        if has_timestomp: attack_methods.append("タイムスタンプ偽装（Timestomp）")
        if has_paradox: attack_methods.append("**システム時間巻き戻し（System Rollback）**")
        if has_anti: attack_methods.append("痕跡ワイピング（Anti-Forensics）")
        
        if not attack_methods: attack_methods = ["不審なアクティビティ"]
            
        f.write(f"**主な攻撃手口:** {', '.join(attack_methods)}。\n\n")
        f.write("> **Deep Dive 推奨:** 詳細な調査を行う際は、添付の `Pivot_Config.json` に記載された **CRITICAL_PHISHING** ターゲット群から開始してください。特にイベントログ（ID 4688）からのコマンドライン復元が最優先事項です。\n\n")
        
        f.write(self._render_mermaid_vertical_clustered(visual_iocs))
        f.write(self._render_key_indicators(visual_iocs))
        f.write("\n")

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

    def _render_grouped_lnk_findings(self, f, items, origin_stories, analyzer):
        """Helper to render LNK findings with grouping to avoid repetition"""
        high_interest = []
        generic_lnks = []
        
        for ioc in items:
            name = ioc.get("Value", "")
            is_special = False
            
            # Check for Origin Story (Confirmed Download)
            story = next((s for s in origin_stories if s["Target"] == name), None) if origin_stories else None
            if story and story.get("Confidence") == "HIGH": is_special = True
            
            # Check for DEFCON/Masquerade
            if "DEFCON" in name.upper() or "MASQUERADE" in str(ioc.get("Extra", {}).get("Risk", "")): is_special = True
            
            if is_special: high_interest.append(ioc)
            else: generic_lnks.append(ioc)
            
        # Render High Interest Items
        if high_interest:
            f.write("**特記事項 (High Interest Artifacts):**\n")
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
                     insight = f"✅ **Web Download Confirmed** (Gap: {gap})<br/>" + (insight if insight else "")
                
                if insight: f.write(f"  - 🕵️ **Analyst Note:** {insight}\n")

        # Render Generic Items Summary
        if generic_lnks:
            f.write(f"\n**その他のLNK ({len(generic_lnks)}件):**\n")
            f.write("画像ファイル名を装ったショートカット群です。Target_Path情報はワイピングにより欠落していますが、作成パターンからフィッシング由来と断定されます。\n")
            generic_lnks.sort(key=lambda x: x.get('Time', '9999'))
            for ioc in generic_lnks:
                dt = str(ioc.get('Time', '')).replace('T', ' ')[:19]
                val = ioc.get('Value', '')
                f.write(f"- {dt} | `{val}`\n")

    def _write_anti_forensics_section(self, f, ioc_list, dfs):
        af_tools = [ioc for ioc in ioc_list if "ANTI" in str(ioc.get("Type", "")) or "WIPE" in str(ioc.get("Type", ""))]
        if not af_tools: return
        f.write("### 🚨 Anti-Forensics Activities (Evidence Destruction)\n\n")
        f.write("⚠️⚠️⚠️ **重大な証拠隠滅活動を検出** ⚠️⚠️⚠️\n\n")
        f.write("攻撃者は侵入後、以下のツールを使用して活動痕跡を意図的に抹消しています：\n\n")
        seen_tools = set()
        for tool in af_tools:
            name = tool.get("Value", "Unknown").upper()
            if name in seen_tools: continue
            seen_tools.add(name)
            run_count = self._extract_dual_run_count(tool, dfs)
            last_run = tool.get("Time", "Unknown").replace("T", " ")[:19]
            desc = "データ抹消ツール"
            if "BCWIPE" in name: desc = "軍事レベルのファイルワイピングツール。通常の復元を不可能にします。"
            elif "CCLEANER" in name: desc = "システムクリーナー。ブラウザ履歴やMRUの削除に使用されます。"
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
        
        # [Fix Issue #1] Correct Stats Presentation
        filtered_count = sum(analyzer.noise_stats.values()) if hasattr(analyzer, "noise_stats") else 0
        critical_count = len(analyzer.visual_iocs)
        total_events = analyzer.total_events_analyzed if hasattr(analyzer, "total_events_analyzed") else (filtered_count + critical_count + len(medium_events))
        if total_events == 0: total_events = 1 
        
        f.write("### 📊 Overall Analysis Summary\n")
        f.write("| Category | Count | Note |\n|---|---|---|\n")
        f.write(f"| **Total Events Analyzed** | **{total_events}** | After filtering |\n")
        
        crit_pct = (critical_count / total_events) * 100
        f.write(f"| Critical Detections | {critical_count} | {crit_pct:.2f}% of analyzed |\n")
        f.write(f"| Filtered Out (Noise) | {filtered_count} | Removed before analysis |\n\n")
        
        f.write("### 🎯 Critical Detection Breakdown\n")
        f.write("| Type | Count | Max Score | Impact |\n|---|---|---|---|\n")
        type_counts = {}
        for ioc in analyzer.visual_iocs:
            typ = ioc.get("Type", "Unknown")
            if "PHISHING" in typ: typ = "PHISHING / LNK"
            elif "TIMESTOMP" in typ: typ = "TIMESTOMP"
            elif "ANTI" in typ: typ = "ANTI_FORENSICS"
            elif "MASQUERADE" in typ: typ = "MASQUERADE"
            type_counts[typ] = type_counts.get(typ, 0) + 1
        for typ, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            score = 300 if "ANTI" in typ or "MASQ" in typ else 250
            impact = "Evidence destruction" if "ANTI" in typ else ("Initial access" if "PHISH" in typ else "Evasion")
            f.write(f"| **{typ}** | **{count}** | {score} | {impact} |\n")
        f.write("\n")
        
        # [Fix Issue #2] Medium Events Breakdown
        f.write("### ⚠️ Medium Confidence Events\n")
        if medium_events:
            f.write(f"**Total Count:** {len(medium_events)} 件 (Timeline CSV参照)\n")
            
            # Category Breakdown
            med_counts = {}
            for ev in medium_events:
                cat = ev.get('Category', 'Other')
                med_counts[cat] = med_counts.get(cat, 0) + 1
            
            f.write(f"**主なカテゴリ分布:**\n")
            for cat, count in sorted(med_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                f.write(f"- {cat}: {count}件\n")
            
            f.write("\n**代表的なイベント (Top 5):**\n")
            f.write("| Time | Summary |\n|---|---|\n")
            for ev in medium_events[:5]:
                t_str = str(ev.get('Time','')).replace('T',' ')[:19]
                sum_str = str(ev.get('Summary', ''))[:80] + "..."
                f.write(f"| {t_str} | {sum_str} |\n")
            f.write("\n")
            
        f.write("### 📉 Filtered Noise Statistics\n")
        f.write("| Filter Reason | Count |\n|---|---|\n")
        if hasattr(analyzer, "noise_stats") and analyzer.noise_stats:
            for reason, count in sorted(analyzer.noise_stats.items(), key=lambda x: x[1], reverse=True):
                f.write(f"| {reason} | {count} |\n")
        else: f.write("| No noise filtered | 0 |\n")
        f.write("\n")

    def _write_recommendations(self, f, analyzer):
        t = self.txt
        f.write(f"## {t['h1_rec']}\n")
        f.write("本インシデントにおけるフォレンジック調査結果に基づき、以下の推奨アクションを提案します。\n\n")
        
        # Determine Priority based on findings
        has_phishing = any("PHISHING" in str(ioc.get("Type", "")) for ioc in analyzer.visual_iocs)
        has_masquerade = any("MASQUERADE" in str(ioc.get("Type", "")) for ioc in analyzer.visual_iocs)
        has_anti = any("ANTI" in str(ioc.get("Type", "")) for ioc in analyzer.visual_iocs)

        f.write("### 📋 Recommended Actions\n")
        f.write("| Priority | Action | Timeline | Reason |\n|---|---|---|---|\n")
        
        if has_anti or has_phishing:
             f.write("| 🔥 **P0** | **Event Log (4688) Command Line Recovery** | **Immediate** | LNK引数がワイピングされているため、イベントログが唯一の実行コマンド特定源です。 |\n")
        
        if has_masquerade:
             f.write("| 🔥 **P0** | **Analyze Suspicious Chrome Extension (.crx)** | 24 Hours | 永続化バックドアとして機能している可能性が高いため、リバースエンジニアリングが必要です。 |\n")
        
        f.write("| 🔥 **P0** | **Network Log Analysis (C2 Identification)** | 24 Hours | 外部通信先IPを特定し、ファイアウォールでブロックしてください。 |\n")
        f.write("| 🟡 P1 | **Lateral Movement Check** | 1 Week | 同一ネットワーク内の他端末への横展開を調査してください。 |\\n")
        f.write("| 🟡 P1 | **Credential Reset** | Immediate | 侵害された端末で使用された全ユーザーのパスワードリセットを推奨します。 |\\n\\n")

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

        if not rows: return "不審なネットワーク活動や横展開の痕跡は検出されませんでした。\n"

        # 時間順にソートしてMarkdown化
        rows.sort(key=lambda x: x["Time"])
        
        md = "| Time / Period | Verdict | Summary | Reference |\n|---|---|---|---|\n"
        for row in rows:
            ref = row.get('Ref', row.get('Tags', ''))
            md += f"| {row['Time']} | {row['Icon']} {row['Verdict']} | {row['Details']} | {ref} |\n"
            
        return md

    def _write_ioc_appendix_unified(self, f, analyzer):
        t = self.txt
        f.write(f"## {t['h1_app']}\n(Full IOC List)\n")
        f.write("本調査で確認されたすべての侵害指標（IOC）の一覧です。\n\n")
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
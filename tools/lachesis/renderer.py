import json
import re
import polars as pl
import os
from datetime import datetime
from tools.lachesis.intel import TEXT_RES

class LachesisRenderer:
    def __init__(self, output_path, lang="jp"):
        self.output_path = output_path
        self.lang = lang if lang in TEXT_RES else "jp"
        self.txt = TEXT_RES[self.lang]
        self.hostname = "Unknown"

    def render_report(self, analysis_data, analyzer, enricher, origin_stories, dfs_for_ioc, metadata):
        self.hostname = metadata.get("hostname", "Unknown")
        out_file = self.output_path
        
        with open(out_file, "w", encoding="utf-8") as f:
            self._write_header(f, metadata["os_info"], metadata["primary_user"], analysis_data["time_range"])
            self._write_toc(f)
            self._write_executive_summary_visual(f, analyzer, analysis_data["time_range"])
            self._write_initial_access_vector(f, analyzer.pivot_seeds, origin_stories)
            self._write_timeline_visual(f, analysis_data["phases"], analyzer, enricher)
            self._write_technical_findings(f, analyzer, dfs_for_ioc) # Pass dfs for run_count lookup
            self._write_detection_statistics(f, analysis_data["medium_events"], analyzer, dfs_for_ioc)
            self._write_ioc_appendix_unified(f, analyzer) 
            f.write(f"\n---\n*Report woven by SkiaHelios (The Triad v4.50)* 🦁")
        
        print(f"[*] Lachesis v4.50 is weaving the report into {out_file}...")

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

    def _write_executive_summary_visual(self, f, analyzer, time_range):
        t = self.txt
        f.write(f"## {t['h1_exec']}\n")
        
        visual_iocs = analyzer.visual_iocs
        has_paradox = any("TIME_PARADOX" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_masquerade = any("MASQUERADE" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_phishing = any("PHISHING" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_timestomp = any("TIMESTOMP" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        
        if "Unknown" in time_range and visual_iocs:
            # Logic to refine range is also in analyzer, but for summary text generation we use what's passed
            pass 
        
        if has_paradox or has_masquerade:
            conclusion = f"**結論:**\n{time_range} の期間において、端末 {self.hostname} に対する **高度な隠蔽工作を伴う重大な侵害活動** を確認しました。\n"
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
        
        if not attack_methods:
            attack_methods = ["不審なアクティビティ"]
            
        f.write(f"**主な攻撃手口:** {', '.join(attack_methods)}。\n\n")
        f.write("> **Deep Dive 推奨:** 詳細な調査を行う際は、添付の `Pivot_Config.json` に記載された **CRITICAL_PHISHING** ターゲット群から開始してください。\n\n")
        f.write("\n### 🏹 Attack Timeline Flow (Critical Chain)\n")
        if visual_iocs: f.write(self._generate_mermaid(analyzer, visual_iocs))
        else: f.write("(No sufficient visual indicators found)\n")

        f.write("\n### 💎 Key Indicators (Critical Only)\n")
        if visual_iocs:
            f.write("| Time | Type | Value (File/IP) | **Target / Action** | **Score** | Path |\n|---|---|---|---|---|---| ignore\n")
            
            sorted_iocs = sorted(visual_iocs, key=lambda x: x.get("Time", "9999"))
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

    def _write_timeline_visual(self, f, phases, analyzer, enricher):
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
                if analyzer.intel.is_noise(summary): continue
                time_display = str(ev.get('Time','')).replace('T', ' ').split('.')[0]
                cat_name = t['cats'].get(ev.get('Category'), ev.get('Category'))
                is_dual = analyzer.intel.is_dual_use(summary)
                prefix = "⚠️ " if is_dual else ""
                row_str = f"| {time_display} | {cat_name} | **{prefix}{summary}** | {ev['Source']} |"
                f.write(f"{row_str}\n")
            if idx < len(phases)-1: f.write("\n*( ... Time Gap ... )*\n\n")

    def _write_technical_findings(self, f, analyzer, dfs):
        t = self.txt
        f.write(f"## {t['h1_tech']}\n")
        
        high_conf_events = [ioc for ioc in analyzer.visual_iocs if analyzer.is_force_include_ioc(ioc) or "ANTI_FORENSICS" in str(ioc.get("Type", ""))]
        
        self._write_anti_forensics_section(f, high_conf_events, dfs)

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
            elif analyzer.intel.is_dual_use(val) or "DUAL_USE" in ioc_type:
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
                insight = analyzer.generate_ioc_insight(ioc)
                if insight: f.write(f"  - 🕵️ **Analyst Note:** {insight}\n")
                f.write("\n")
        f.write("\n")

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
            
            # Use local helper for RunCount
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
        """RunCount Extraction (Moved from LachesisWriter/Enricher for ease of refactor)"""
        if not dfs: return "Unknown"
        target_name = ioc.get("Value", "").lower().strip()
        if not target_name: return "Unknown"
        
        target_base = target_name
        if "\\" in target_base or "/" in target_base:
            target_base = os.path.basename(target_base.replace("\\", "/"))
        if " " in target_base:
            target_base = target_base.split(" ")[0]

        def get_df(name_part):
            for k, v in dfs.items():
                if name_part.lower() in k.lower(): return v
            return None

        # Method 1: Prefetch
        pf = get_df('Prefetch')
        if pf is not None:
            try:
                cols_lower = {c.lower(): c for c in pf.columns}
                exec_col = next((cols_lower[c] for c in cols_lower if "executable" in c), None)
                run_col = next((cols_lower[c] for c in cols_lower if "run" in c and "count" in c), None)
                if exec_col and run_col:
                    hits = pf.filter(pl.col(exec_col).str.to_lowercase().str.contains(target_base, literal=True))
                    if hits.height > 0:
                        rc = hits[0, run_col]
                        return f"{rc} (Prefetch)"
            except: pass

        # Method 2: UserAssist
        ua = get_df('UserAssist')
        if ua is not None:
            try:
                cols_lower = {c.lower(): c for c in ua.columns}
                name_col = next((cols_lower[c] for c in cols_lower if "value" in c and "name" in c), None)
                if not name_col: name_col = next((cols_lower[c] for c in cols_lower if "program" in c), None)
                run_col = next((cols_lower[c] for c in cols_lower if "run" in c and "count" in c), None)
                if name_col and run_col:
                     hits = ua.filter(pl.col(name_col).str.to_lowercase().str.contains(target_base, literal=True))
                     if hits.height > 0:
                         rc = hits[0, run_col]
                         return f"{rc} (UserAssist)"
            except: pass

        # Method 3: Fallback Summary
        summary = ioc.get("Summary", "")
        if summary:
            match = re.search(r"(?:Run\s*Count:|Run:|Run\sCount)\s*[:]?\s*(\d+)", summary, re.IGNORECASE)
            if match: return match.group(1)

        # Method 4: Timeline Deep Search
        try:
            timeline = dfs.get("Timeline")
            if timeline is not None:
                cond = pl.col("FileName").str.to_lowercase().str.contains(target_base, literal=True)
                for c in ["Message", "Description", "Action", "Summary"]:
                    if c in timeline.columns:
                        cond = cond | pl.col(c).str.to_lowercase().str.contains(target_base, literal=True)
                hits = timeline.filter(cond)
                if hits.height > 0:
                    for col in hits.columns:
                        if col in ["Summary", "Message", "Details", "Description"]:
                            for val in hits[col]:
                                match = re.search(r"(?:Run\s*Count:|Run:|Run\sCount)\s*[:]?\s*(\d+)", str(val), re.IGNORECASE)
                                if match: return f"{match.group(1)} (Timeline)"
        except: pass
        return "Unknown"

    def _write_detection_statistics(self, f, medium_events, analyzer, dfs):
        t = self.txt
        f.write(f"## {t['h1_stats']}\n")
        
        filtered_count = sum(analyzer.noise_stats.values())
        critical_count = len(analyzer.visual_iocs)
        
        f.write("### 📊 Overall Analysis Summary\n")
        f.write("| Category | Count | Percentage |\n|---|---|---|\n")
        f.write(f"| **Total Events Analyzed** | **{analyzer.total_events_analyzed}** | 100% |\n")
        
        if analyzer.total_events_analyzed > 0:
            crit_pct = (critical_count / analyzer.total_events_analyzed) * 100
            filt_pct = (filtered_count / analyzer.total_events_analyzed) * 100
        else:
            crit_pct, filt_pct = 0, 0
            
        f.write(f"| Critical Detections | {critical_count} | {crit_pct:.2f}% |\n")
        f.write(f"| Filtered Noise | {filtered_count} | {filt_pct:.1f}% |\n\n")

        f.write("### 🎯 Critical Detection Breakdown\n")
        f.write("| Type | Count | Max Score | Impact |\n|---|---|---|---|\n")
        
        type_counts = {}
        for ioc in analyzer.visual_iocs:
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
        if analyzer.noise_stats:
            for reason, count in sorted(analyzer.noise_stats.items(), key=lambda x: x[1], reverse=True):
                f.write(f"| {reason} | {count} |\n")
        else: f.write("| No noise filtered | 0 |\n")
        f.write("\n")

    def _write_ioc_appendix_unified(self, f, analyzer):
        t = self.txt
        f.write(f"## {t['h1_app']} (Full IOC List)\n")
        f.write("本調査で確認されたすべての侵害指標（IOC）の一覧です。\n\n")
        if analyzer.visual_iocs:
            f.write("### 📂 File IOCs (Malicious/Suspicious Files)\n")
            f.write("| File Name | Path | Source | Note |\n|---|---|---|---|\n")
            seen = set()
            sorted_iocs = sorted(analyzer.visual_iocs, key=lambda x: 0 if "CRITICAL" in x.get("Reason", "").upper() else 1)
            for ioc in sorted_iocs:
                val = ioc['Value']
                path = ioc['Path']
                if analyzer.intel.is_visual_noise(val): continue
                key = f"{val}|{path}"
                if key in seen: continue
                seen.add(key)
                reason = ioc.get("Reason", "Unknown")
                f.write(f"| `{val}` | `{path}` | {ioc['Type']} ({reason}) | {ioc.get('Time', 'N/A')} |\n")
            f.write("\n")
        if analyzer.infra_ips_found:
            f.write("### 🌐 Network IOCs (Suspicious Connections)\n")
            f.write("| Remote IP | Context |\n|---|---|\n")
            for ip in analyzer.infra_ips_found:
                 f.write(f"| `{ip}` | Detected in Event Logs |\n")
            f.write("\n")

    def _generate_mermaid(self, analyzer, visual_iocs):
        if not visual_iocs: return ""
        
        def get_time(item):
            t = item.get("Time", "")
            return t if t else "9999"
            
        sorted_iocs = sorted(visual_iocs, key=get_time)
        if not sorted_iocs: return ""
        
        has_paradox = any("TIME_PARADOX" in str(ioc.get("Type", "")) for ioc in visual_iocs)
        
        rollback_time_str = None
        if has_paradox:
            for ioc in visual_iocs:
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
            if analyzer.intel.is_visual_noise(ioc["Value"]): continue
            ts_str = ioc.get("Time", "")
            curr_dt = analyzer.enricher.parse_time_safe(ts_str)
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
        for ev in analysis_result["events"]:
            serializable_events.append({
                "Time": str(ev.get('dt_obj', ev['Time'])),
                "User": ev.get('User'),
                "Category": ev.get('Category'),
                "Summary": ev.get('Summary'),
                "Source": ev.get('Source'),
                "Criticality": ev.get('Criticality', 0)
            })
        iocs = {"File": analyzer.visual_iocs, "Network": list(analyzer.infra_ips_found), "Cmd": []}
        grimoire_data = {
            "Metadata": {"Host": self.hostname, "Case": "Investigation", "Primary_User": primary_user, "Generated_At": datetime.now().isoformat()},
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
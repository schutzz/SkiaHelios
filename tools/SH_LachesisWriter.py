import pandas as pd
import polars as pl
from datetime import datetime
import os
from pathlib import Path
import json
import re
from tools.SH_ThemisLoader import ThemisLoader # Loaderをインポート

# ============================================================
#  SH_LachesisWriter v3.15 [Final Report Polish]
#  Mission: Weave the Grimoire with Summarized Findings.
#  Update: Plan G - Force include Dual-Use Tools regardless of score.
# ============================================================

TEXT_RES = {
    "en": {
        "title": "Incident Investigation Report",
        "coc_header": "Chain of Custody & Case Info",
        "h1_exec": "1. Executive Summary",
        "h1_origin": "2. Initial Access Vector (Origin Analysis)",
        "h1_time": "3. Investigation Timeline",
        "h1_tech": "4. Technical Findings (High Confidence Aggregation)",
        "h1_stats": "5. Detection Statistics (Low/Medium Confidence)",
        "h1_rec": "6. Conclusion & Recommendations",
        "h1_app": "7. Appendices",
        "cats": {"INIT": "Initial Access", "C2": "Command & Control", "PERSIST": "Persistence", "ANTI": "Anti-Forensics", "EXEC": "Execution", "DROP": "File Creation (Origin)", "WEB": "Web Access"},
        "investigator": "Forensic Analyst"
    },
    "jp": {
        "title": "インシデント調査報告書",
        "coc_header": "証拠保全および案件情報 (Chain of Custody)",
        "h1_exec": "1. エグゼクティブ・サマリー",
        "h1_origin": "2. 初期侵入経路分析 (Initial Access Vector)",
        "h1_time": "3. 調査タイムライン",
        "h1_tech": "4. 技術的詳細 (高確度イベントの集約)",
        "h1_stats": "5. 検知統計 (Detection Statistics)",
        "h1_rec": "6. 結論と推奨事項",
        "h1_app": "7. 添付資料",
        "cats": {"INIT": "初期侵入 (Initial Access)", "C2": "C2通信 (Command & Control)", "PERSIST": "永続化 (Persistence)", "ANTI": "アンチフォレンジック (Anti-Forensics)", "EXEC": "実行 (Execution)", "DROP": "ファイル作成/流入 (File Drop)", "WEB": "Webアクセス"},
        "investigator": "担当フォレンジックアナリスト"
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
        
        # [NEW] Load Dual-Use Keywords from YAML
        self.loader = ThemisLoader(["rules/triage_rules.yaml"])
        self.dual_use_keywords = self.loader.get_dual_use_keywords()
        print(f"[*] Lachesis loaded {len(self.dual_use_keywords)} dual-use keywords from YAML.")

    def weave_report(self, analysis_result, output_path, dfs_for_ioc, hostname, os_info, primary_user):
        print(f"[*] Lachesis v3.15 is weaving the refined report into {output_path}...")
        self.hostname = hostname 
        valid_events = analysis_result["events"]
        phases = analysis_result["phases"]
        origin_stories = analysis_result["origin_stories"]
        verdict_flags = analysis_result["verdict_flags"]
        lateral_summary = analysis_result["lateral_summary"]
        flow_steps = analysis_result["flow_steps"]

        self.visual_iocs = [] 
        self.infra_ips_found = set()

        self._extract_visual_iocs_from_pandora(dfs_for_ioc)
        self._extract_visual_iocs_from_chronos(dfs_for_ioc)
        self._extract_visual_iocs_from_aion(dfs_for_ioc)
        self._extract_visual_iocs_from_events(valid_events)

        out_file = Path(output_path)
        if not out_file.parent.exists(): out_file.parent.mkdir(parents=True, exist_ok=True)

        with open(out_file, "w", encoding="utf-8") as f:
            self._embed_chimera_tags(f, primary_user)
            self._write_header(f, os_info, primary_user)
            self._write_executive_summary_visual(f, valid_events, verdict_flags, lateral_summary, flow_steps, primary_user)
            if origin_stories: self._write_origin_analysis(f, origin_stories)
            self._write_timeline_visual(f, phases)
            self._write_technical_findings(f, phases)
            self._write_detection_statistics(f, dfs_for_ioc)
            self._write_ioc_appendix(f, dfs_for_ioc)
            f.write(f"\n---\n*Report woven by SkiaHelios (The Triad v3.2)* 🦁")
        
        json_path = out_file.with_suffix('.json')
        self._export_json_grimoire(analysis_result, dfs_for_ioc, json_path, primary_user)

    def _is_noise(self, name, path=""):
        name = str(name).lower()
        path = str(path).lower()
        # [NEW] Check if it is a Dual-Use tool FIRST. If so, it is NEVER noise.
        if self._is_dual_use(name): return False

        noise_keywords = [
            "desktop.ini", "thumbs.db", "safe browsing", "inputpersonalization", "traineddatastore",
            "customdestinations", "automaticdestinations", "inetcookies", "browsermetrics", 
            "mptelemetry", "crashpad", "watson", "wer", "favorites", "edge", "bing",
            # [Plan G] Safe Tool Noise (Excluded by folder in other tools, but listed here for safety)
            "tmpidcrl.dll", "bcwipe", "bcwipesvc", "vbox", "java auto updater",
            "jetico", "ccleaner", "dropbox", "skype"
        ]
        # Dual-Use tools are protected from Noise list (handled by early return above)

        noise_paths = [
            "winsxs", "servicing", "msocache", "program files", "appdata\\local\\programs\\python", 
            "lib\\test", "windows\\assembly", "windows\\fonts", "windows\\installer",
            "python27\\tcl", "python27\\lib"
        ]
        
        if any(k in name for k in noise_keywords): return True
        if any(p in path for p in noise_paths): return True
        return False

    def _is_dual_use(self, name):
        # [NEW] Use dynamic list from YAML
        name_lower = str(name).lower()
        return any(k in name_lower for k in self.dual_use_keywords)

    def _extract_visual_iocs_from_pandora(self, dfs):
        if dfs.get('Pandora') is not None:
            df = dfs['Pandora']
            if "Threat_Score" in df.columns:
                try:
                    # Score >= 80 OR Dual-Use Tool
                    threats = df.filter(
                        (pl.col("Threat_Score").cast(pl.Int64, strict=False) >= 80) |
                        (pl.col("Ghost_FileName").str.to_lowercase().str.contains("nmap|wireshark|netcat|psexec"))
                    ).unique(subset=["Ghost_FileName"])
                    
                    for row in threats.iter_rows(named=True):
                        fname = row.get("Ghost_FileName", "")
                        if self._is_noise(fname, row.get("ParentPath")): continue
                        if "lnk" in fname.lower() or "url" in fname.lower(): continue
                        ioc_type = row.get("Threat_Tag", "SUSPICIOUS")
                        if not ioc_type: ioc_type = row.get("Risk_Tag", "ANOMALY")
                        
                        if self._is_dual_use(fname): ioc_type = "DUAL_USE_TOOL"
                        
                        clean_name = fname.split("] ")[-1]
                        self._add_unique_visual_ioc({
                            "Type": ioc_type, "Value": clean_name, "Path": row.get("ParentPath", ""), "Note": "File Artifact (Pandora)"
                        })
                except: pass

    def _extract_visual_iocs_from_chronos(self, dfs):
        if dfs.get('Chronos') is not None:
            df = dfs['Chronos']
            if "Chronos_Score" in df.columns:
                try:
                    # Score >= 80 OR Dual-Use Tool
                    threats = df.filter(
                        (pl.col("Chronos_Score").cast(pl.Int64, strict=False) >= 80) |
                        (pl.col("FileName").str.to_lowercase().str.contains("nmap|wireshark|netcat|psexec"))
                    )
                    for row in threats.iter_rows(named=True):
                        name = row.get("FileName")
                        path = row.get("ParentPath")
                        if self._is_noise(name, path): continue
                        anomaly = row.get("Anomaly_Time", "TIME_ANOMALY")
                        if self._is_dual_use(name): anomaly = "DUAL_USE_TOOL"
                        
                        self._add_unique_visual_ioc({
                            "Type": anomaly, "Value": name, "Path": path, "Note": f"Timestomp Detected (Chronos)"
                        })
                except: pass

    def _extract_visual_iocs_from_aion(self, dfs):
        if dfs.get('AION') is not None:
            df = dfs['AION']
            if "AION_Score" in df.columns:
                try:
                    threats = df.filter(pl.col("AION_Score").cast(pl.Int64, strict=False) >= 80)
                    for row in threats.iter_rows(named=True):
                        name = row.get("Target_FileName")
                        path = row.get("Full_Path")
                        if self._is_noise(name, path): continue
                        self._add_unique_visual_ioc({
                            "Type": "PERSISTENCE", "Value": name, "Path": path, "Note": f"Persistence Mechanism (AION)"
                        })
                except: pass

    def _extract_visual_iocs_from_events(self, events):
        re_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        infra_ips = ["10.0.2.15", "10.0.2.2", "127.0.0.1", "0.0.0.0", "::1"]
        
        ignore_execs = [
            "tiworker.exe", "trustedinstaller.exe", "sppsvc.exe", "searchindexer.exe",
            "compattelrunner.exe", "explorer.exe", "conhost.exe", "svchost.exe",
            "sppwinob.dll", "wermgr.exe", "backgroundtaskhost.exe", "tmpidcrl.dll",
            "googleupdate.exe", "wmpnetworksvc",
            "vcredist_x64.exe", "usbpcapsetup", "chrome.exe", "firefox.exe"
        ]

        for ev in events:
            content = ev['Summary'] + " " + str(ev.get('Detail', ''))
            ips = re_ip.findall(content)
            for ip in ips:
                if ip in infra_ips or ip.startswith("127."): 
                    self.infra_ips_found.add(ip)
                    continue

                parts = ip.split('.')
                if len(parts) == 4:
                    try:
                        p1 = int(parts[0])
                        p2 = int(parts[1])
                        if p1 < 10 and ip != "1.1.1.1" and ip != "8.8.8.8" and ip != "8.8.4.4": continue 
                        if p1 == 6 and p2 == 3: continue
                        if p1 == 10 and p2 == 0: continue
                    except: continue
                
                self._add_unique_visual_ioc({
                    "Type": "IP_TRACE", "Value": ip, "Path": "Network", "Note": f"Detected in {ev['Source']}"
                })
            
            # High Crit OR Dual Use
            is_dual = self._is_dual_use(ev.get('Summary', ''))
            if (ev['Criticality'] >= 90 or is_dual) and ev['Category'] == 'EXEC':
                kws = ev.get('Keywords', [])
                if kws:
                    kw = str(kws[0]).lower()
                    if not self._is_noise(kw) and kw not in ignore_execs:
                        type_label = "DUAL_USE_TOOL" if is_dual else "EXECUTION"
                        self._add_unique_visual_ioc({
                            "Type": type_label, "Value": kws[0], "Path": "Process", "Note": f"Execution ({ev['Source']})"
                        })

    def _add_unique_visual_ioc(self, ioc_dict):
        if self._is_noise(ioc_dict["Value"], ioc_dict["Path"]): return
        for existing in self.visual_iocs:
            if existing["Value"] == ioc_dict["Value"] and existing["Type"] == ioc_dict["Type"]:
                return
        self.visual_iocs.append(ioc_dict)

    def _consolidate_attack_flow(self, flows):
        if not flows: return []
        grouped_flow = []
        clusters = {} 
        order = []    
        for step in flows:
            match = re.match(r"(.+?)\s*\((.+)\)", step)
            if match:
                prefix = match.group(1).strip()
                target = match.group(2).strip()
                if self._is_noise(target): continue
                if prefix not in clusters:
                    clusters[prefix] = []
                    order.append(prefix)
                clusters[prefix].append(target)
            else:
                if step not in order: order.append(step)
                clusters[step] = []

        final_flow = []
        for key in order:
            targets = clusters.get(key, [])
            if not targets:
                final_flow.append(key)
            else:
                unique_targets = sorted(list(set(targets)))
                count = len(unique_targets)
                if count <= 3:
                    final_flow.append(f"{key} ({', '.join(unique_targets)})")
                else:
                    examples = ", ".join(unique_targets[:2])
                    final_flow.append(f"{key} (**{count} files**: {examples}, ...)")
        return final_flow
    
    def _sanitize_verdicts(self, verdicts):
        clean_tags = set()
        for v in verdicts:
            inner = v.replace("[", "").replace("]", "")
            for ignore in ["DETECTED:", "DETECTED", "CONFIRMED", "POTENTIAL_"]:
                 inner = inner.replace(ignore, "")
            parts = [p.strip() for p in re.split(r'[, ]+', inner) if p.strip()]
            for p in parts:
                clean_tags.add(p)
        if not clean_tags: return ""
        return f"[DETECTED: {', '.join(sorted(list(clean_tags)))}]"

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
            date_str = str(phase[0]['Time']).replace('T', ' ').split(' ')[0]
            
            for ev in phase:
                if self._is_noise(ev['Summary']): continue
                
                # Report only High Criticality OR Dual Use
                is_dual = self._is_dual_use(ev.get('Summary', ''))
                if ev['Criticality'] >= 80 or is_dual:
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
        chart = "\n```mermaid\ngraph TD\n"
        chart += "    %% Nodes Definition\n"
        chart += "    Attacker((🦁 Attacker)) -->|Exploit/Access| Initial{Initial Access}\n"
        
        webshells = [i for i in self.visual_iocs if "WEBSHELL" in i["Type"] or "OBFUSCATION" in i["Type"]]
        persistence = [i for i in self.visual_iocs if "PERSISTENCE" in i["Type"] or "ROOTKIT" in i["Type"]]
        timestomps = [i for i in self.visual_iocs if "TIMESTOMP" in i["Type"] or "FALSIFIED" in i["Type"]]
        ips = [i for i in self.visual_iocs if "IP_TRACE" in i["Type"]]
        execs = [i for i in self.visual_iocs if "EXECUTION" in i["Type"]]
        malware = [i for i in self.visual_iocs if "CRITICAL" in i["Type"] or "CREDENTIALS" in i["Type"]]
        dual_use = [i for i in self.visual_iocs if "DUAL_USE" in i["Type"]]

        if webshells:
            for item in webshells[:3]:
                ws = item["Value"]
                chart += f"    Initial -->|Drop/Upload| WS_{abs(hash(ws))}[\"{ws}\"]\n"
                chart += f"    WS_{abs(hash(ws))} -->|Exec| Cmd_{abs(hash(ws))}((Shell))\n"
        
        parent = f"Cmd_{abs(hash(webshells[0]['Value']))}" if webshells else "Initial"
        
        if persistence:
            for item in persistence[:3]:
                p = item["Value"]
                chart += f"    {parent} -->|Persistence| P_{abs(hash(p))}[\"{p}<br/>(AutoRun)\"]\n"

        if timestomps:
             for item in timestomps[:3]:
                ts = item["Value"]
                chart += f"    {parent} -->|Timestomp| TS_{abs(hash(ts))}[\"{ts}<br/>(Time Forged)\"]\n"

        if malware:
             for item in malware[:3]:
                m = item["Value"]
                chart += f"    {parent} -->|Malware/Tool| MW_{abs(hash(m))}[\"{m}\"]\n"
        
        if dual_use:
             for item in dual_use[:3]:
                d = item["Value"]
                chart += f"    {parent} -->|Admin Tool?| DT_{abs(hash(d))}[\"{d}\"]\n"

        if ips:
            for item in ips[:5]:
                ip = item["Value"]
                chart += f"    Attacker -.->|C2/Lateral| IP_{abs(hash(ip))}(\"{ip}\")\n"
        
        if execs and not webshells:
            for item in execs[:3]:
                ex = item["Value"]
                chart += f"    Initial -->|Execute| EX_{abs(hash(ex))}[[\"{ex}\"]]\n"
                
        chart += "\n    %% Styles\n"
        chart += "    classDef threat fill:#ffcccc,stroke:#ff0000,stroke-width:2px,color:#000;\n"
        chart += "    class Attacker,Initial threat;\n"
        chart += "```\n"
        return chart

    def _write_executive_summary_visual(self, f, events, verdicts, lateral, flows, primary_user_str):
        t = self.txt
        f.write(f"## {t['h1_exec']}\n")
        verdict_str = self._sanitize_verdicts(verdicts)
        latest_crit = "Unknown"
        if events:
             for ev in reversed(events):
                if ev['Criticality'] >= 90:
                    latest_crit = str(ev['Time']).split('.')[0]; break
        if events:
            f.write(f"**結論:**\n{latest_crit} (UTC) 頃、端末 {self.hostname} において、**悪意ある攻撃活動**を検知しました。")
            if verdict_str: f.write(f" **{verdict_str}**")
            f.write("\n\n")
        else:
            f.write("**結論:**\n現在提供されているログの範囲では、クリティカルな侵害痕跡は確認されませんでした。\n\n")
        
        f.write("\n### 🏹 Detected Attack Flow (攻撃フロー図)\n")
        if self.visual_iocs: f.write(self._generate_mermaid())
        else: f.write("(No sufficient visual indicators found for diagram generation)\n")
        
        f.write("\n### 💎 Key Indicators (確度の高い侵害指標)\n")
        if self.visual_iocs:
            f.write("| Type | Value (File/IP) | Path | Note |\n|---|---|---|---|\n")
            shown = set()
            for ioc in self.visual_iocs:
                key = ioc['Value']
                if key in shown: continue
                shown.add(key)
                short_path = (ioc['Path'][:40] + '..') if len(ioc['Path']) > 40 else ioc['Path']
                f.write(f"| **{ioc['Type']}** | `{ioc['Value']}` | `{short_path}` | {ioc['Note']} |\n")
        else: f.write("No critical IOCs automatically detected.\n")
        
        f.write("\n")
        if lateral: 
            f.write(f"\n**Lateral Movement (Confirmed):**\n")
            try:
                lat_tags = [x.strip() for x in lateral.replace('"', '').split(',')]
                noise_tags = ["EVASION", "EXECUTION", "PERSISTENCE", "PRIVESC", "DISCOVERY", "CREDENTIALS", "CMD_EXEC"]
                clean_lat = []
                for t in lat_tags:
                    if t not in noise_tags and not t.startswith("CAR."):
                        clean_lat.append(t)
                
                unique_lat = sorted(list(set(clean_lat)))
                if unique_lat:
                    f.write(f"{', '.join(unique_lat)}\n")
                else:
                    f.write("None (Filtered Noise)\n")
            except:
                f.write(f"{lateral}\n")
        
        user_display = primary_user_str if primary_user_str and primary_user_str != "Unknown_User" else "特定不能 (System権限のみ)"
        f.write(f"\n**侵害されたアカウント:**\n主に **{user_display}** アカウントでの活動が確認されています。\n\n")
        f.write(f"**攻撃フロー（タイムライン概要）:**\n")
        consolidated_flows = self._consolidate_attack_flow(flows)
        if consolidated_flows:
            for i, step in enumerate(consolidated_flows, 1): f.write(f"{i}. {step}\n")
        else: f.write("攻撃の全体像を構成するのに十分なイベントが検出されませんでした。\n")
        f.write("\n")

    def _write_timeline_visual(self, f, phases):
        t = self.txt
        f.write(f"## {t['h1_time']}\n")
        # [MODIFIED] High Confidence Only
        f.write("以下に、検知された脅威イベントを時系列で示します。（重要度スコア80以上のイベントのみ抽出）\n\n")
        
        for idx, phase in enumerate(phases):
            if not phase: continue
            date_str = str(phase[0]['Time']).replace('T', ' ').split(' ')[0]
            
            f.write(f"### 📅 Phase {idx+1} ({date_str})\n")
            f.write(f"| Time (UTC) | Category | Event Summary (Command / File) | Source |\n|---|---|---|---|\n") 
            
            for ev in phase:
                time_display = str(ev['Time']).replace('T', ' ').split('.')[0]
                cat_name = t['cats'].get(ev['Category'], ev['Category'])
                summary = ev['Summary']
                if len(summary) > 120: summary = summary[:115] + "..."
                source = ev['Source']
                if self._is_noise(summary) or self._is_noise(str(ev.get('Detail', ''))): continue
                
                # Criticality >= 80 ONLY, UNLESS it's a dual-use tool
                is_dual = self._is_dual_use(summary)
                is_critical = ev['Criticality'] >= 80 or "CRITICAL" in summary or "WEBSHELL" in summary or "ROOTKIT" in summary or is_dual
                
                if is_critical:
                    prefix = "⚠️ " if is_dual else ""
                    if ev['Category'] == 'EXEC': row_str = f"| {time_display} | {cat_name} | `{prefix}{summary}` | {source} |"
                    else: row_str = f"| {time_display} | {cat_name} | **{prefix}{summary}** | {source} |"
                    f.write(f"{row_str}\n")
            
            if idx < len(phases)-1: f.write("\n*( ... Time Gap ... )*\n\n")
        f.write("\n")

    def _embed_chimera_tags(self, f, primary_user):
        f.write("\n\n")

    def _write_header(self, f, os_info, primary_user):
        t = self.txt
        f.write(f"# {t['title']} - {self.hostname}\n\n")
        f.write(f"### 🛡️ {t['coc_header']}\n")
        f.write("| Item | Details |\n|---|---|\n")
        f.write(f"| **Case Name** | {self.case_name} |\n")
        f.write(f"| **Target Host** | **{self.hostname}** |\n")
        f.write(f"| **OS Info** | {os_info} |\n")
        f.write(f"| **Primary User** | {primary_user} |\n")
        f.write(f"| **Date** | {datetime.now().strftime('%Y-%m-%d')} |\n")
        f.write(f"| **Status** | Analyzed (SkiaHelios Triad) |\n\n---\n\n")

    def _write_origin_analysis(self, f, stories):
        t = self.txt
        f.write(f"## {t['h1_origin']}\n")
        f.write("攻撃の起点（侵入経路）に関する物理的証拠と因果関係の分析結果です。\n\n")
        f.write("| File (Payload) | 📍 Origin Context (Path/Web) | 🔗 Execution Link |\n|---|---|---|\n")
        for story in stories:
            if self._is_noise(story['File']): continue
            origin_desc = "**Unknown**"
            if story['Path_Indicator']: origin_desc = f"📂 {story['Path_Indicator']}"
            if story['Web_Correlation']: origin_desc += f"<br>🌐 {story['Web_Correlation']}"
            exec_desc = story['Execution_Link'] if story['Execution_Link'] else "実行痕跡なし (未実行の可能性)"
            f.write(f"| `{story['File']}` | {origin_desc} | {exec_desc} |\n")
        f.write("\n")

    def _write_detection_statistics(self, f, dfs):
        t = self.txt
        f.write(f"## {t['h1_stats']}\n")
        f.write("以下は、確度は低いものの異常検知された項目の件数サマリーです。\n")
        f.write("これらの中には、攻撃の予兆やラテラルムーブメントの痕跡が含まれる可能性があります。\n\n")
        f.write("| Category | Detection Type | Count | Reference CSV |\n|---|---|---|---|\n")
        
        if dfs.get('Chronos') is not None:
            df = dfs['Chronos']
            if "Chronos_Score" in df.columns:
                stats = df.filter(pl.col("Chronos_Score").cast(pl.Int64, strict=False) > 0) \
                          .group_by("Anomaly_Time").count().sort("count", descending=True)
                for row in stats.iter_rows(named=True):
                    note = ""
                    if row['Anomaly_Time'] == "LEGACY_BUILD": note = " (システムビルド由来の可能性高 - 低確度)"
                    f.write(f"| Timeline Event | {row['Anomaly_Time']}{note} | {row['count']} | `Chronos_Results.csv` |\n")

        if dfs.get('Pandora') is not None:
            df = dfs['Pandora']
            if "Threat_Score" in df.columns:
                stats = df.filter(pl.col("Threat_Score").cast(pl.Int64, strict=False) >= 0) \
                          .group_by("Risk_Tag").count().sort("count", descending=True)
                for row in stats.iter_rows(named=True):
                    tag = row['Risk_Tag'] if row['Risk_Tag'] else "Unknown Anomaly"
                    if tag == "": tag = "Potential Artifacts"
                    f.write(f"| File Artifact | {tag} | {row['count']} | `pandora_result_v*.csv` |\n")
        
        if dfs.get('Hercules') is not None:
             df = dfs['Hercules']
             if "Threat_Score" in df.columns:
                 stats = df.filter((pl.col("Threat_Score").cast(pl.Int64, strict=False) < 80) & \
                                   (pl.col("Threat_Score").cast(pl.Int64, strict=False) > 0)) \
                           .group_by("Threat_Tag").count().sort("count", descending=True)
                 for row in stats.iter_rows(named=True):
                     tag = row['Threat_Tag'] if row['Threat_Tag'] else "Sigma Detection"
                     f.write(f"| Event Log | {tag} | {row['count']} | `Hercules_Judged_Timeline.csv` |\n")
        f.write("\n> **Note:** 詳細は各CSVファイルを参照してください。\n\n")

    def _write_ioc_appendix(self, f, dfs):
        t = self.txt
        f.write(f"## {t['h1_app']} (Full IOC List)\n")
        f.write("本調査で確認されたすべての侵害指標（IOC）の一覧です。\n\n")
        
        file_iocs = self._collect_file_iocs(dfs)
        if file_iocs:
            f.write("### 📂 File IOCs (Malicious/Suspicious Files)\n")
            f.write("| File Name | Path | Source | Note |\n|---|---|---|---|\n")
            for ioc in file_iocs:
                if self._is_noise(ioc['Name'], ioc['Path']): continue
                f.write(f"| `{ioc['Name']}` | `{ioc['Path']}` | {ioc['Source']} | {ioc['SHA256']} |\n")
            f.write("\n")
        
        if dfs.get('PlutosNet') is not None:
            df = dfs['PlutosNet']
            if 'Remote_IP' in df.columns:
                hits = df.filter(pl.col("Remote_IP").is_not_null())
                if hits.height > 0:
                    f.write("### 🌐 Network IOCs (Suspicious Connections)\n")
                    f.write("| Remote IP | Port | Process | Timestamp (UTC) |\n|---|---|---|---|\n")
                    for row in hits.unique(subset=["Remote_IP", "Remote_Port"]).iter_rows(named=True):
                         if row['Remote_IP'] in self.infra_ips_found: continue
                         f.write(f"| `{row['Remote_IP']}` | {row.get('Remote_Port','-')} | `{row.get('Process','-')}` | {row.get('Timestamp','-')} |\n")
                    f.write("\n")
                    if self.infra_ips_found:
                         f.write(f"> **Note:** VirtualBox/Localhost traffic ({', '.join(sorted(list(self.infra_ips_found)))}) was detected but summarized. Refer to `Plutos_Network.csv` for details.\n\n")

        if dfs.get('Sphinx') is not None:
            df = dfs['Sphinx']
            if "Sphinx_Score" in df.columns:
                hits = df.filter(pl.col("Sphinx_Score").cast(pl.Int64, strict=False) >= 100)
                if hits.height > 0:
                    f.write("### 💻 CommandLine IOCs (Malicious Scripts)\n")
                    f.write("| CommandLine (Decoded Hint) | Timestamp |\n|---|---|\n")
                    for row in hits.iter_rows(named=True):
                        cmd = row.get('Decoded_Hint') or row.get('Original_Snippet', 'Unknown')
                        cmd_display = (cmd[:100] + '...') if len(cmd) > 100 else cmd
                        f.write(f"| `{cmd_display}` | {row.get('TimeCreated','-')} |\n")
                    f.write("\n")

    def _collect_file_iocs(self, dfs):
        iocs = []
        if dfs.get('AION') is not None:
            df = dfs['AION']
            if 'AION_Score' in df.columns:
                hits = df.filter(pl.col("AION_Score").cast(pl.Int64, strict=False) >= 10)
                for row in hits.iter_rows(named=True):
                    iocs.append({"Name": row.get('Target_FileName'), "SHA1": row.get('File_Hash_SHA1'), "SHA256": row.get('File_Hash_SHA256'), "Path": row.get('Full_Path'), "Source": "AION"})
        if dfs.get('Pandora') is not None:
            df = dfs['Pandora']
            if 'Risk_Tag' in df.columns:
                hits = df.filter(pl.col("Risk_Tag") != "")
                for row in hits.iter_rows(named=True):
                    path = row.get('ParentPath', '') + "\\" + row.get('Ghost_FileName', '')
                    iocs.append({"Name": row.get('Ghost_FileName'), "SHA1": "N/A (Deleted)", "SHA256": "N/A (Deleted)", "Path": path, "Source": f"Pandora ({row.get('Risk_Tag')})"})
        if dfs.get('Chronos') is not None:
            df = dfs['Chronos']
            if 'Anomaly_Time' in df.columns and 'Chronos_Score' in df.columns:
                try:
                    hits = df.filter(pl.col("Chronos_Score").cast(pl.Int64, strict=False) > 0)
                    for row in hits.iter_rows(named=True):
                        path = row.get('ParentPath', '') + "\\" + row.get('FileName', '')
                        iocs.append({"Name": row.get('FileName'), "SHA1": "N/A (Timestomp)", "SHA256": "N/A (Timestomp)", "Path": path, "Source": f"Chronos ({row.get('Anomaly_Time')})"})
                except Exception as e:
                    print(f"    [!] Chronos IOC Error: {e}")
        unique_iocs = {}
        for i in iocs:
            key = i['Path'] if i['Path'] else i['Name']
            if key not in unique_iocs: unique_iocs[key] = i
        return list(unique_iocs.values())

    def _generate_insight(self, ev, created_files_in_phase=None):
        cat = ev['Category']
        summary = ev['Summary'].lower()
        src = ev['Source'].lower()
        
        # Dual-Use Insight
        if self._is_dual_use(summary):
            return "攻撃にも転用可能な管理者ツール（Dual-Use Tool）の存在/実行を確認しました。"

        if re.search(r'\[\d+\]\.(htm|html|js|php|jsp)', summary):
            is_cache_path = any(x in summary for x in ['cache', 'temp', 'history', 'appdata'])
            is_high_confidence = ev.get('Criticality', 0) >= 90
            if not is_cache_path and is_high_confidence:
                return "外部C2（または踏み台）との通信を伴うブラウザ経由の活動です。"

        if cat == "INIT":
            if "powershell" in src and ("base64" in summary or "decoded" in summary): return "PowerShellコマンドのBase64難読化実行を検知しました。"
            return "不審なスクリプトブロックの実行を検知しました。"
        elif cat == "DROP": return "ディスク上での新規ファイル作成（File Drop）を確認しました。"
        elif cat == "C2": return "外部への不審な通信（C2）を検知しました。"
        elif cat == "PERSIST": return "永続化設定が確認されました。"
        elif cat == "ANTI":
            if "timestomp" in summary: return "ファイルタイムスタンプの改ざん痕跡です。"
            
            is_volatile = False
            if created_files_in_phase:
                for kw in ev.get('Keywords', []):
                    if str(kw).lower() in created_files_in_phase:
                        is_volatile = True; break
            
            if is_volatile:
                return "揮発性痕跡（Volatile Artifact）の検知（作成直後の削除）です。"
            return "攻撃活動の痕跡隠滅（ファイル削除）です。"
            
        return "調査が必要な不審なイベントです。"

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
        iocs = {"File": self._collect_file_iocs(dfs_for_ioc), "Network": [], "Cmd": []}
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
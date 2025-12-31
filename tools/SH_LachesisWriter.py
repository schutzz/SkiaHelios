import pandas as pd
import polars as pl
from datetime import datetime
import os
from pathlib import Path
import json

# ============================================================
#  SH_LachesisWriter v2.2 [Syntax Guard]
#  Mission: Weave the Grimoire with Mermaid Charts, IOC Tables.
#  Fix: Escaped Mermaid node labels & Safe ID generation.
# ============================================================

TEXT_RES = {
    "en": {
        "title": "Incident Investigation Report",
        "coc_header": "Chain of Custody & Case Info",
        "h1_exec": "1. Executive Summary",
        "h1_origin": "2. Initial Access Vector (Origin Analysis)",
        "h1_time": "3. Investigation Timeline",
        "h1_tech": "4. Technical Findings",
        "h1_rec": "5. Conclusion & Recommendations",
        "h1_app": "6. Appendices",
        "cats": {"INIT": "Initial Access", "C2": "Command & Control", "PERSIST": "Persistence", "ANTI": "Anti-Forensics", "EXEC": "Execution", "DROP": "File Creation (Origin)", "WEB": "Web Access"},
        "investigator": "Forensic Analyst"
    },
    "jp": {
        "title": "インシデント調査報告書",
        "coc_header": "証拠保全および案件情報 (Chain of Custody)",
        "h1_exec": "1. エグゼクティブ・サマリー",
        "h1_origin": "2. 初期侵入経路分析 (Initial Access Vector)",
        "h1_time": "3. 調査タイムライン",
        "h1_tech": "4. 技術的詳細 (Technical Findings)",
        "h1_rec": "5. 結論と推奨事項",
        "h1_app": "6. 添付資料",
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
        self.visual_iocs = [] # For Mermaid & Top Table

    def weave_report(self, analysis_result, output_path, dfs_for_ioc):
        print(f"[*] Lachesis v2.2 is weaving the report into {output_path}...")
        
        valid_events = analysis_result["events"]
        phases = analysis_result["phases"]
        origin_stories = analysis_result["origin_stories"]
        verdict_flags = analysis_result["verdict_flags"]
        lateral_summary = analysis_result["lateral_summary"]
        compromised_users = analysis_result["compromised_users"]
        flow_steps = analysis_result["flow_steps"]

        primary_user = "Unknown"
        if compromised_users:
            top_user = compromised_users.most_common(1)
            if top_user: primary_user = top_user[0][0]

        # 1. Extract Visual IOCs (High Confidence only for Top Section)
        self._extract_visual_iocs(dfs_for_ioc)

        out_file = Path(output_path)
        if not out_file.parent.exists(): out_file.parent.mkdir(parents=True, exist_ok=True)

        with open(out_file, "w", encoding="utf-8") as f:
            self._embed_chimera_tags(f, primary_user)
            self._write_header(f)
            self._write_executive_summary_visual(f, valid_events, verdict_flags, lateral_summary, flow_steps, compromised_users)
            
            if origin_stories: self._write_origin_analysis(f, origin_stories)
            
            self._write_timeline_visual(f, phases)
            
            self._write_technical_findings(f, phases)
            self._write_ioc_appendix(f, dfs_for_ioc)
            f.write(f"\n---\n*Report woven by SkiaHelios (The Triad v2.2)* 🦁")
        
        json_path = out_file.with_suffix('.json')
        self._export_json_grimoire(analysis_result, dfs_for_ioc, json_path, primary_user)

    def _extract_visual_iocs(self, dfs):
        """
        [Visual] Extract High-Confidence IOCs specifically for Mermaid & Top Table.
        Targeting Pandora's Threat Tags.
        """
        if dfs.get('Pandora') is not None:
            df = dfs['Pandora']
            if "Threat_Score" in df.columns:
                try:
                    # Cast to Int64 to avoid string comparison errors
                    threats = df.filter(pl.col("Threat_Score").cast(pl.Int64, strict=False) > 0).unique(subset=["Ghost_FileName"])
                    
                    for row in threats.iter_rows(named=True):
                        ioc_type = row.get("Threat_Tag", "UNKNOWN")
                        raw_name = row.get("Ghost_FileName", "")
                        path = row.get("ParentPath", "")
                        
                        # Remove [CRITICAL_TAG] prefix for display
                        clean_name = raw_name
                        if "] " in raw_name:
                            clean_name = raw_name.split("] ")[-1]
                        
                        self.visual_iocs.append({
                            "Type": ioc_type,
                            "Value": clean_name,
                            "Path": path,
                            "Note": "Recovered from Deletion Log (High Risk)"
                        })
                except Exception as e:
                    print(f"[!] Warning: Failed to extract visual IOCs from Pandora: {e}")

    def _generate_mermaid(self):
        """[Visual] 構文エラーを回避する安全なMermaid図解生成"""
        if not self.visual_iocs: return ""
        
        chart = "\n```mermaid\ngraph TD\n"
        chart += "    %% Nodes Definition\n"
        # ノードのラベルは " " で囲むことでカッコ問題を回避
        chart += "    Attacker((🦁 Attacker)) -->|Exploit/Access| Initial{Initial Access}\n"
        
        web_shells = [i["Value"] for i in self.visual_iocs if i["Type"] in ["WEBSHELL", "OBFUSCATION"]]
        rootkits = [i["Value"] for i in self.visual_iocs if i["Type"] == "ROOTKIT"]
        exploits = [i["Value"] for i in self.visual_iocs if i["Type"] == "EXPLOIT"]
        ips = [i["Value"] for i in self.visual_iocs if i["Type"] == "IP_TRACE"]

        if exploits:
            for ex in exploits[:3]:
                # abs(hash()) で安全なID生成 + " " でラベル保護
                chart += f"    Initial -->|Detected Exploit| Ex_{abs(hash(ex))}[\"{ex}\"]\n"
        
        if web_shells:
            for ws in web_shells[:3]:
                chart += f"    Initial -->|File Upload| WS_{abs(hash(ws))}[\"{ws}<br/>(WebShell)\"]\n"
                chart += f"    WS_{abs(hash(ws))} -->|Command Exec| Cmd{abs(hash(ws))}((OS Shell))\n"

        if rootkits:
            for rk in rootkits:
                parent = f"Cmd{abs(hash(web_shells[0]))}" if web_shells else "Initial"
                chart += f"    {parent} -->|Persistence| RK_{abs(hash(rk))}[\"{rk}<br/>(Rootkit)\"]\n"

        if ips:
            for ip in ips:
                chart += f"    Attacker -.->|Remote Trace| IP_{abs(hash(ip))}(\"{ip}\")\n"

        chart += "\n    %% Styles\n"
        chart += "    classDef threat fill:#ffcccc,stroke:#ff0000,stroke-width:2px,color:#000;\n"
        chart += "    class Attacker,Initial threat;\n"
        chart += "```\n"
        return chart

    def _write_executive_summary_visual(self, f, events, verdicts, lateral, flows, users):
        """[Merge] Exec Summary with Mermaid & Top IOC Table"""
        t = self.txt
        f.write(f"## {t['h1_exec']}\n")
        
        verdict_str = " ".join(list(verdicts))
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

        # Mermaid Diagram
        f.write("\n### 🏹 Detected Attack Flow (攻撃フロー図)\n")
        if self.visual_iocs:
            f.write(self._generate_mermaid())
        else:
            f.write("(No sufficient visual indicators found for diagram generation)\n")

        # High Confidence IOCs
        f.write("\n### 💎 Key Indicators (確度の高い侵害指標)\n")
        if self.visual_iocs:
            f.write("| Type | Value (File/IP) | Path | Note |\n")
            f.write("|---|---|---|---|\n")
            for ioc in self.visual_iocs:
                short_path = (ioc['Path'][:40] + '..') if len(ioc['Path']) > 40 else ioc['Path']
                f.write(f"| **{ioc['Type']}** | `{ioc['Value']}` | `{short_path}` | {ioc['Note']} |\n")
        else:
            f.write("No critical IOCs automatically detected.\n")
        f.write("\n")

        if lateral:
            f.write(f"\n**Lateral Movement:**\n{lateral}\n")

        main_user = users.most_common(1)
        user_str = main_user[0][0] if main_user else "特定不能 (System権限のみ)"
        f.write(f"\n**侵害されたアカウント:**\n主に **{user_str}** アカウントでの活動が確認されています。\n\n")

        f.write(f"**攻撃フロー（タイムライン概要）:**\n")
        if flows:
            for i, step in enumerate(flows, 1):
                f.write(f"{i}. {step}\n")
        else:
            f.write("攻撃の全体像を構成するのに十分なイベントが検出されませんでした。\n")
        f.write("\n")

    def _write_timeline_visual(self, f, phases):
        """[Visual] Timeline with Noise Folding (<details>)"""
        t = self.txt
        f.write(f"## {t['h1_time']}\n")
        f.write("以下に、検知された脅威イベントを時系列で示します。（重要度の低いイベントは折りたたまれています）\n\n")

        for idx, phase in enumerate(phases):
            if not phase: continue
            date_str = str(phase[0]['Time']).replace('T', ' ').split(' ')[0]
            f.write(f"### 📅 Phase {idx+1} ({date_str})\n")
            
            f.write(f"| Time (UTC) | Category | Event Summary | Source |\n|---|---|---|---|\n")
            
            noise_buffer = []
            
            for ev in phase:
                time_display = str(ev['Time']).replace('T', ' ').split('.')[0]
                cat_name = t['cats'].get(ev['Category'], ev['Category'])
                summary = ev['Summary']
                source = ev['Source']
                
                is_critical = ev['Criticality'] >= 80 or "CRITICAL" in summary or "WEBSHELL" in summary or "ROOTKIT" in summary
                
                row_str = f"| {time_display} | {cat_name} | **{summary}** | {source} |"
                
                if is_critical:
                    if noise_buffer:
                        self._write_noise_buffer(f, noise_buffer)
                        noise_buffer = []
                    f.write(f"{row_str}\n")
                else:
                    noise_buffer.append(f"| {time_display} | {cat_name} | {summary} | {source} |")
            
            if noise_buffer:
                self._write_noise_buffer(f, noise_buffer)
            
            if idx < len(phases)-1: f.write("\n*( ... Time Gap ... )*\n\n")
        f.write("\n")

    def _write_noise_buffer(self, f, buffer):
        f.write(f"\n<details><summary>🔽 Low Priority Events ({len(buffer)} records)</summary>\n\n")
        f.write(f"| Time (UTC) | Category | Event Summary | Source |\n|---|---|---|---|\n")
        for line in buffer:
            f.write(f"{line}\n")
        f.write(f"\n</details>\n\n")

    def _embed_chimera_tags(self, f, primary_user):
        tags = ["", ""]
        f.write("\n".join(tags))

    def _write_header(self, f):
        t = self.txt
        f.write(f"# {t['title']} - {self.hostname}\n\n")
        f.write(f"### 🛡️ {t['coc_header']}\n")
        f.write("| Item | Details |\n|---|---|\n")
        f.write(f"| **Case Name** | {self.case_name} |\n")
        f.write(f"| **Target Host** | **{self.hostname}** |\n")
        f.write(f"| **Date** | {datetime.now().strftime('%Y-%m-%d')} |\n")
        f.write(f"| **Status** | Analyzed (SkiaHelios Triad) |\n\n---\n\n")

    def _write_origin_analysis(self, f, stories):
        t = self.txt
        f.write(f"## {t['h1_origin']}\n")
        f.write("攻撃の起点（侵入経路）に関する物理的証拠と因果関係の分析結果です。\n\n")
        f.write("| File (Payload) | 📍 Origin Context (Path/Web) | 🔗 Execution Link |\n|---|---|---|\n")
        for story in stories:
            origin_desc = "**Unknown**"
            if story['Path_Indicator']: origin_desc = f"📂 {story['Path_Indicator']}"
            if story['Web_Correlation']: origin_desc += f"<br>🌐 {story['Web_Correlation']}"
            exec_desc = story['Execution_Link'] if story['Execution_Link'] else "実行痕跡なし (未実行の可能性)"
            f.write(f"| `{story['File']}` | {origin_desc} | {exec_desc} |\n")
        f.write("\n")

    def _write_technical_findings(self, f, phases):
        t = self.txt
        f.write(f"## {t['h1_tech']}\n")
        has_any_findings = False
        for idx, phase in enumerate(phases):
            if not phase: continue
            has_findings = False
            phase_buffer = []
            date_str = str(phase[0]['Time']).replace('T', ' ').split(' ')[0]
            phase_buffer.append(f"### 📅 Phase {idx+1} ({date_str})\n")
            for ev in phase:
                if ev['Criticality'] >= 85:
                    has_findings = True
                    has_any_findings = True
                    insight = self._generate_insight(ev)
                    phase_buffer.append(f"- **{ev['Summary']}**\n")
                    phase_buffer.append(f"  - **Time:** {ev['Time']}\n")
                    phase_buffer.append(f"  - **Insight:** {insight}\n")
                    if ev.get('Detail'):
                         phase_buffer.append(f"  - **Detail:**\n```text\n{str(ev['Detail'])[:300]}\n```\n")
                    phase_buffer.append("\n")
            if has_findings:
                f.write("".join(phase_buffer))
                f.write("\n")
        if not has_any_findings:
            f.write("特筆すべき技術的な詳細事項はありません。\n\n")

    def _write_ioc_appendix(self, f, dfs):
        t = self.txt
        f.write(f"## {t['h1_app']} (Full IOC List)\n")
        f.write("本調査で確認されたすべての侵害指標（IOC）の一覧です。\n\n")

        file_iocs = self._collect_file_iocs(dfs)
        if file_iocs:
            f.write("### 📂 File IOCs (Malicious/Suspicious Files)\n")
            f.write("| File Name | Path | Source | Note |\n|---|---|---|---|\n")
            for ioc in file_iocs:
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
                         f.write(f"| `{row['Remote_IP']}` | {row.get('Remote_Port','-')} | `{row.get('Process','-')}` | {row.get('Timestamp','-')} |\n")
                    f.write("\n")
        
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
            if 'Anomaly_Time' in df.columns:
                hits = df.filter(pl.col("Anomaly_Time") != "")
                for row in hits.iter_rows(named=True):
                    path = row.get('ParentPath', '') + "\\" + row.get('FileName', '')
                    iocs.append({"Name": row.get('FileName'), "SHA1": "N/A (Timestomp)", "SHA256": "N/A (Timestomp)", "Path": path, "Source": f"Chronos ({row.get('Anomaly_Time')})"})
        
        unique_iocs = {}
        for i in iocs:
            key = i['Path'] if i['Path'] else i['Name']
            if key not in unique_iocs: unique_iocs[key] = i
        return list(unique_iocs.values())

    def _generate_insight(self, ev):
        cat = ev['Category']
        summary = ev['Summary'].lower()
        src = ev['Source'].lower()
        if cat == "INIT":
            if "powershell" in src and ("base64" in summary or "decoded" in summary): return "PowerShellコマンドのBase64難読化実行を検知しました。"
            return "不審なスクリプトブロックの実行を検知しました。"
        elif cat == "DROP": return "ディスク上での新規ファイル作成（File Drop）を確認しました。"
        elif cat == "C2": return "外部への不審な通信（C2）を検知しました。"
        elif cat == "PERSIST": return "永続化設定が確認されました。"
        elif cat == "ANTI":
            if "timestomp" in summary: return "ファイルタイムスタンプの改ざん痕跡です。"
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
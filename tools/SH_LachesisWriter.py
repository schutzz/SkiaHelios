import datetime
from pathlib import Path
import polars as pl
from collections import Counter
import json

# ============================================================
#  SH_LachesisWriter v1.9.1 [Chimera Tagging]
#  Mission: Weave the verdict into a human-readable report.
#  Update: Embed hidden metadata for Chimera Fusion.
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
    """
    [Lachesis: The Allotter]
    運命（解析結果）を割り当て、報告書として具現化するクラス。
    """
    def __init__(self, lang="jp", hostname="Unknown_Host", case_name="Investigation"):
        self.lang = lang if lang in TEXT_RES else "jp"
        self.txt = TEXT_RES[self.lang]
        self.hostname = hostname
        self.case_name = case_name

    def weave_report(self, analysis_result, output_path, dfs_for_ioc):
        """
        Atroposの思考結果(analysis_result)と、IOC抽出用の元データ(dfs_for_ioc)を使い、
        Markdownレポートを生成する。
        """
        print(f"[*] Lachesis is weaving the report into {output_path}...")
        
        # Unpack Analysis Results
        valid_events = analysis_result["events"]
        phases = analysis_result["phases"]
        origin_stories = analysis_result["origin_stories"]
        verdict_flags = analysis_result["verdict_flags"]
        lateral_summary = analysis_result["lateral_summary"]
        compromised_users = analysis_result["compromised_users"]
        flow_steps = analysis_result["flow_steps"]

        # [Chimera Logic] Identify Primary User for Tagging
        # 最もアクティビティの多いユーザーを特定してタグに埋め込む
        primary_user = "Unknown"
        if compromised_users:
            # compromised_users is a Counter object
            top_user = compromised_users.most_common(1)
            if top_user:
                primary_user = top_user[0][0]

        out_file = Path(output_path)
        if not out_file.parent.exists(): out_file.parent.mkdir(parents=True, exist_ok=True)

        with open(out_file, "w", encoding="utf-8") as f:
            # [Chimera Logic] Embed Hidden Tags FIRST
            self._embed_chimera_tags(f, primary_user)

            # Header
            self._write_header(f)
            
            # 1. Executive Summary
            self._write_executive_summary(f, valid_events, verdict_flags, lateral_summary, flow_steps, compromised_users)
            
            # 2. Origin Analysis
            if origin_stories:
                self._write_origin_analysis(f, origin_stories)

            # 3. Timeline
            self._write_timeline(f, phases)

            # 4. Technical Findings
            self._write_technical_findings(f, phases)

            # 5. IOC Appendix
            self._write_ioc_appendix(f, dfs_for_ioc)

            f.write(f"\n---\n*Report woven by SkiaHelios (The Triad v1.9)*")
        
        # [NEW] JSON Grimoire Dump for Chimera
        # Markdownと同じ場所に .json を吐き出す
        json_path = out_file.with_suffix('.json')
        self._export_json_grimoire(analysis_result, dfs_for_ioc, json_path, primary_user)

    def _export_json_grimoire(self, analysis_result, dfs_for_ioc, json_path, primary_user):
        """
        [Chimera Link]
        解析結果を構造化データ(JSON)として保存する。
        ChimeraFusionはこのファイルを読み込んで統合を行う。
        """
        # 1. Timeline Serialization
        # datetimeオブジェクトを文字列に変換
        serializable_events = []
        for ev in analysis_result["events"]:
            serializable_events.append({
                "Time": str(ev.get('dt_obj', ev['Time'])), # Use strict time object if avail
                "User": ev.get('User'),
                "Category": ev.get('Category'),
                "Summary": ev.get('Summary'),
                "Source": ev.get('Source'),
                "Criticality": ev.get('Criticality', 0)
            })

        # 2. IOC Serialization
        iocs = {"File": [], "Network": [], "Cmd": []}
        
        # File IOC
        if dfs_for_ioc.get('AION') is not None:
            df = dfs_for_ioc['AION']
            if 'File_Hash_SHA256' in df.columns or 'File_Hash_SHA1' in df.columns:
                cond = pl.lit(False)
                if 'File_Hash_SHA256' in df.columns: cond = cond | pl.col("File_Hash_SHA256").is_not_null()
                if 'File_Hash_SHA1' in df.columns: cond = cond | pl.col("File_Hash_SHA1").is_not_null()
                hits = df.filter(cond & (pl.col("AION_Score").cast(pl.Int64, strict=False) >= 10))
                for row in hits.iter_rows(named=True):
                    iocs["File"].append({
                        "Name": row.get('Target_FileName'),
                        "SHA1": row.get('File_Hash_SHA1'),
                        "SHA256": row.get('File_Hash_SHA256'),
                        "Path": row.get('Full_Path')
                    })

        # Network IOC
        if dfs_for_ioc.get('PlutosNet') is not None:
            df = dfs_for_ioc['PlutosNet']
            if 'Remote_IP' in df.columns:
                hits = df.filter(pl.col("Remote_IP").is_not_null())
                for row in hits.iter_rows(named=True):
                    iocs["Network"].append({
                        "IP": row.get('Remote_IP'),
                        "Port": row.get('Remote_Port'),
                        "Process": row.get('Process')
                    })
        
        # 3. Construct Final Dict
        grimoire_data = {
            "Metadata": {
                "Host": self.hostname,
                "Case": self.case_name,
                "Primary_User": primary_user,
                "Generated_At": datetime.datetime.now().isoformat()
            },
            "Verdict": {
                "Flags": list(analysis_result["verdict_flags"]),
                "Lateral_Summary": analysis_result["lateral_summary"]
            },
            "Timeline": serializable_events,
            "IOCs": iocs
        }

        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(grimoire_data, f, indent=2, ensure_ascii=False)
            print(f"   -> [Chimera Ready] JSON Grimoire saved: {json_path}")
        except Exception as e:
            print(f"   [!] Failed to export JSON Grimoire: {e}")

    def _embed_chimera_tags(self, f, primary_user):
        """
        [Chimera Tagging]
        レポートの先頭に機械可読なメタデータを埋め込む。
        これはMarkdownとしては表示されないが、ChimeraFusionがパースする際に使用する。
        """
        tags = [
            "",
            "" # Empty line for separation
        ]
        f.write("\n".join(tags))

    def _write_header(self, f):
        t = self.txt
        f.write(f"# {t['title']} - {self.hostname}\n\n")
        f.write(f"### 🛡️ {t['coc_header']}\n")
        f.write("| Item | Details |\n|---|---|\n")
        f.write(f"| **Case Name** | {self.case_name} |\n")
        f.write(f"| **Target Host** | **{self.hostname}** |\n")
        f.write(f"| **Date** | {datetime.datetime.now().strftime('%Y-%m-%d')} |\n")
        f.write(f"| **Status** | Analyzed (SkiaHelios Triad) |\n\n---\n\n")

    def _write_executive_summary(self, f, events, verdicts, lateral, flows, users):
        t = self.txt
        f.write(f"## {t['h1_exec']}\n")
        
        # Verdict
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

        # Lateral
        if lateral:
            f.write(lateral)
            f.write("\n")

        # Users
        main_user = users.most_common(1)
        user_str = main_user[0][0] if main_user else "特定不能 (System権限のみ)"
        f.write(f"**侵害されたアカウント:**\n主に **{user_str}** アカウントでの活動が確認されています。\n\n")

        # Flow
        f.write(f"**攻撃フロー（概要）:**\n")
        if flows:
            for i, step in enumerate(flows, 1):
                f.write(f"{i}. {step}\n")
        else:
            f.write("攻撃の全体像を構成するのに十分なイベントが検出されませんでした。\n")
        f.write("\n")

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

    def _write_timeline(self, f, phases):
        t = self.txt
        f.write(f"## {t['h1_time']}\n")
        for idx, phase in enumerate(phases):
            if not phase: continue
            date_str = str(phase[0]['Time']).replace('T', ' ').split(' ')[0]
            f.write(f"### 📅 Phase {idx+1} ({date_str})\n")
            f.write(f"| Time (UTC) | User | Category | Event Summary | Source |\n|---|---|---|---|---|\n")
            for ev in phase:
                cat_name = t['cats'].get(ev['Category'], "Other")
                time_display = str(ev['Time']).replace('T', ' ').split('.')[0]
                u = ev['User'] if ev['User'] else "-"
                f.write(f"| {time_display} | {u} | {cat_name} | {ev['Summary']} | {ev['Source']} |\n")
            if idx < len(phases)-1: f.write("\n*( ... Time Gap ... )*\n\n")
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
        f.write(f"## {t['h1_app']} (IOC List)\n")
        f.write("本調査で確認された侵害指標（IOC）の一覧です。EDR/FW/SIEMへの即時登録を推奨します。\n\n")

        # 1. File IOC (AION)
        if dfs.get('AION') is not None:
            df = dfs['AION']
            if 'File_Hash_SHA256' in df.columns or 'File_Hash_SHA1' in df.columns:
                cond = pl.lit(False)
                if 'File_Hash_SHA256' in df.columns: cond = cond | pl.col("File_Hash_SHA256").is_not_null()
                if 'File_Hash_SHA1' in df.columns: cond = cond | pl.col("File_Hash_SHA1").is_not_null()
                hits = df.filter(cond & (pl.col("AION_Score").cast(pl.Int64, strict=False) >= 10))
                if hits.height > 0:
                    f.write("### 📂 File IOCs (Malicious/Suspicious Files)\n")
                    f.write("| File Name | SHA1 | SHA256 | Full Path |\n|---|---|---|---|\n")
                    for row in hits.unique(subset=["Full_Path"]).iter_rows(named=True):
                        f.write(f"| `{row.get('Target_FileName','-')}` | `{row.get('File_Hash_SHA1','-')}` | `{row.get('File_Hash_SHA256','-')}` | `{row.get('Full_Path','-')}` |\n")
                    f.write("\n")

        # 2. Network IOC (PlutosNet)
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
        
        # 3. CommandLine IOC (Sphinx)
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

    def _generate_insight(self, ev):
        cat = ev['Category']
        summary = ev['Summary'].lower()
        src = ev['Source'].lower()
        if cat == "INIT":
            if "powershell" in src and ("base64" in summary or "decoded" in summary):
                return "PowerShellコマンドのBase64難読化実行を検知しました。"
            return "不審なスクリプトブロックの実行を検知しました。"
        elif cat == "DROP": return "ディスク上での新規ファイル作成（File Drop）を確認しました。実行の前段階として攻撃ツールが配置された痕跡です。"
        elif cat == "C2": return "外部への不審な通信（C2）を検知しました。"
        elif cat == "PERSIST": return "永続化設定が確認されました。"
        elif cat == "ANTI":
            if "timestomp" in summary: return "ファイルタイムスタンプの改ざん痕跡です。"
            return "攻撃活動の痕跡隠滅（ファイル削除）です。"
        return "調査が必要な不審なイベントです。"
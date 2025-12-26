import polars as pl
import argparse
from pathlib import Path
import sys
import datetime
import re

# ============================================================
#  SH_HekateWeaver v6.3 [Final Fix]
#  Mission: Bind threads of evidence and identify actors.
#  Updated: Fixed dictionary lookup logic once and for all.
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HEKATE  --   [ The Grand Weaver v6.3 ]
      | | | | | |   "Truth is a multi-layered tapestry."
    """)

TEXT_RES = {
    "en": {
        "title": "SkiaHelios Forensic Analysis Report",
        "intro": "Custom DFIR framework for high-resolution artifact correlation.",
        "scope": "Analysis Scope",
        "h1_users": "1. User Identity Summary (Hercules)",
        "col_user": "Resolved User", "col_sid": "Subject SID", "col_status": "Account Status",
        "h1_summary": "2. Executive Summary",
        "h1_cols": ["Module", "Status", "Anomaly Count"],
        "status_crit": "CRITICAL", "status_warn": "WARNING", "status_safe": "CLEAN",
        "h2_breakdown": "3. Critical Artifact Breakdown (Top Hits)",
        "desc_breakdown": "Key findings per module, sorted by risk/score.",
        "h2_story": "4. Anomalous Storyline (Timeline View)",
        "desc_story": "Chronological fusion of events (Top 100 Most Recent).",
        "col_time": "Timestamp", "col_mod": "Module", "col_desc": "Description / Evidence",
        "h2_ghosts": "5. Hidden & Deleted Artifacts (Pandora)",
        "desc_ghosts": "Top 10 artifacts identified via USN/MFT gap analysis (Ghosts).",
        "col_risk": "Risk Tag", "col_file": "File Name", "col_path": "Original Path", "col_src": "Detection Source",
        "h1_legend": "0. Methodology & Artifact Legend",
        "legend_desc": "SkiaHelios correlates disparate artifacts to reconstruct attacker intent.",
        "tool_list": [
            ("Chaos", "Master Timeline construction (Events, Web, ShellBags)."),
            ("Hercules", "Authority & Identity Judgment (SID Mapping)."),
            ("Chronos", "MFT Time Paradox (Timestomp/ADS) detection."),
            ("AION", "Persistence hunting correlated with MFT."),
            ("Pandora", "Recovery of deleted/hidden 'Ghost' artifacts."),
            ("Plutos", "Exfiltration tracking via USB & Network Beaconing."),
            ("Sphinx", "Decoding obfuscated scripts with Process Context.")
        ]
    },
    "jp": {
        "title": "SkiaHelios フォレンジック解析報告書",
        "intro": "アーティファクト間の相関分析に特化した自動生成報告書。",
        "scope": "解析対象期間",
        "h1_users": "1. ユーザー・アイデンティティ・サマリー (Hercules)",
        "col_user": "解決済みユーザー名", "col_sid": "Subject SID", "col_status": "アカウント状態",
        "h1_summary": "2. エグゼクティブ・サマリー (指定期間内)",
        "h1_cols": ["モジュール", "リスクレベル", "検知件数"],
        "status_crit": "【警告】要調査", "status_warn": "注意", "status_safe": "異常なし",
        "h2_breakdown": "3. 重要アーティファクト詳細 (モジュール別 Top Hits)",
        "desc_breakdown": "各モジュールが検出した特に危険なアーティファクト（最大5件）を抜粋。",
        "h2_story": "4. 統合ストーリーライン (時系列ビュー)",
        "desc_story": "各イベントを時系列で統合し、攻撃の流れを再現します（最新100件のみ表示）。",
        "col_time": "発生時刻", "col_mod": "モジュール", "col_desc": "検出内容 / 証拠",
        "h2_ghosts": "5. 隠蔽・削除アーティファクト (Pandora)",
        "desc_ghosts": "USNジャーナルやMFTのギャップ解析により特定された『ゴースト』ファイル（Top 10）。",
        "col_risk": "リスクタグ", "col_file": "ファイル名", "col_path": "復元パス", "col_src": "検知ソース",
        "h1_legend": "0. 調査手法および凡例",
        "legend_desc": "SkiaHeliosは、分散した証拠を紐付け、攻撃者の意図を再構成します。",
        "tool_list": [
            ("Chaos", "マスタータイムラインの構築 (Web/ShellBags統合)"),
            ("Hercules", "権限およびアイデンティティの審判 (SID紐付け)"),
            ("Chronos", "MFTタイムスタンプ矛盾およびADS隠蔽の検知"),
            ("AION", "MFT相関型永続化メカニズムの探索"),
            ("Pandora", "削除・隠蔽された『ゴースト』アーティファクトの復元"),
            ("Plutos", "情報持ち出し(USB) および C2通信の追跡"),
            ("Sphinx", "難読化スクリプトの解読とプロセス特定")
        ]
    }
}

class HekateWeaver:
    def __init__(self, timeline_csv, aion_csv=None, pandora_csv=None, plutos_csv=None, plutos_net_csv=None, sphinx_csv=None, chronos_csv=None, lang="en", start_time=None, end_time=None):
        self.lang = lang if lang in TEXT_RES else "en"
        self.txt = TEXT_RES[self.lang] # [OK] Dictionary is selected here
        self.start_time = start_time
        self.end_time = end_time
        
        self.df_timeline = self._safe_load(timeline_csv, "Hercules", time_col="Timestamp_UTC")
        self.df_aion     = self._safe_load(aion_csv, "AION", time_col="Last_Executed_Time")
        self.df_pandora  = self._safe_load(pandora_csv, "Pandora", time_col=None) 
        self.df_plutos   = self._safe_load(plutos_csv, "Plutos", time_col="SourceModified")
        self.df_plutos_net = self._safe_load(plutos_net_csv, "Plutos(Net)", time_col=None)
        self.df_sphinx   = self._safe_load(sphinx_csv, "Sphinx", time_col="TimeCreated")
        self.df_chronos  = self._safe_load(chronos_csv, "Chronos", time_col="Anomaly_Time")

    def _safe_load(self, path, module_name, time_col=None):
        if path and Path(path).exists():
            try:
                df = pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
                if time_col and (self.start_time or self.end_time) and time_col in df.columns:
                    try:
                        df_dt = df.with_columns(pl.col(time_col).str.to_datetime(strict=False).alias("_dt_temp"))
                        if df_dt.select(pl.col("_dt_temp").null_count()).item() == len(df_dt) and len(df_dt) > 0:
                            raise ValueError("All dates parsed as null")
                        if self.start_time:
                            s_dt = datetime.datetime.strptime(self.start_time, "%Y-%m-%d %H:%M:%S")
                            df_dt = df_dt.filter(pl.col("_dt_temp") >= s_dt)
                        if self.end_time:
                            e_dt = datetime.datetime.strptime(self.end_time, "%Y-%m-%d %H:%M:%S")
                            df_dt = df_dt.filter(pl.col("_dt_temp") <= e_dt)
                        df = df_dt.drop("_dt_temp")
                    except:
                        try:
                            if self.start_time: df = df.filter(pl.col(time_col) >= self.start_time)
                            if self.end_time:   df = df.filter(pl.col(time_col) <= self.end_time)
                        except: pass
                return df
            except: return None
        return None

    def _is_system_noise(self, user_val, sid_val):
        system_users = ["SYSTEM", "Local Service", "Network Service", "DWM", "UMFD", "Window Manager"]
        system_sids  = ["S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-96-"]
        if user_val and any(s.lower() == str(user_val).lower() for s in system_users): return True
        if sid_val and any(s in str(sid_val) for s in system_sids): return True
        return False

    def _get_hercules_stats(self):
        if self.df_timeline is None: return 0
        count = 0
        if "Tag" in self.df_timeline.columns:
            for row in self.df_timeline.iter_rows(named=True):
                tag = str(row.get("Tag", ""))
                if "CRITICAL" in tag or "[!]" in tag or "DELETED_USER" in tag:
                    user = str(row.get("Resolved_User", ""))
                    sid = str(row.get("Subject_SID", ""))
                    if "DELETED_USER" in tag: count += 1
                    elif not self._is_system_noise(user, sid): count += 1
        return count

    def _compress_storyline(self, df):
        if df is None or df.is_empty(): return df
        rows = df.sort("Time").to_dicts()
        compressed = []
        if not rows: return None
        prev_row = rows[0]
        dup_count = 0
        for i in range(1, len(rows)):
            curr_row = rows[i]
            if (curr_row["Module"] == prev_row["Module"]) and (curr_row["Desc"] == prev_row["Desc"]):
                dup_count += 1
            else:
                if dup_count > 0: prev_row["Desc"] += f" (Repeated {dup_count}x)"
                compressed.append(prev_row)
                prev_row = curr_row
                dup_count = 0
        if dup_count > 0: prev_row["Desc"] += f" (Repeated {dup_count}x)"
        compressed.append(prev_row)
        return pl.DataFrame(compressed)

    def weave_storyline(self):
        print("[*] Weaving the Storyline with Identity Context...")
        parts = []
        # Chronos
        if self.df_chronos is not None and not self.df_chronos.is_empty() and "Anomaly_Time" in self.df_chronos.columns:
            parts.append(self.df_chronos.select([
                pl.col("Anomaly_Time").alias("Time"), pl.lit("Chronos").alias("Module"),
                pl.format("{} (Score: {}) in {}", "Anomaly_Time", "Chronos_Score", "FileName").alias("Desc")]))
        # AION
        if self.df_aion is not None and not self.df_aion.is_empty() and "Last_Executed_Time" in self.df_aion.columns:
            parts.append(self.df_aion.select([
                pl.col("Last_Executed_Time").alias("Time"), pl.lit("AION").alias("Module"),
                pl.format("PERSISTENCE: {} [{}]", "Target_FileName", "AION_Tags").alias("Desc")]))
        # Plutos
        if self.df_plutos is not None and not self.df_plutos.is_empty() and "SourceModified" in self.df_plutos.columns:
            plutos_clean = self.df_plutos.filter(~pl.col("Plutos_Verdict").is_in(["NORMAL_APP_ACCESS", "SYSTEM_INTERNAL_ACTIVITY"]))
            parts.append(plutos_clean.select([
                pl.col("SourceModified").alias("Time"), pl.lit("Plutos").alias("Module"),
                pl.format("Exfil: {} ({})", "Target_FileName", "Plutos_Verdict").alias("Desc")]))
        # Sphinx
        if self.df_sphinx is not None and not self.df_sphinx.is_empty():
            schema = self.df_sphinx.collect_schema().names()
            time_col = next((c for c in ["Timestamp_UTC", "TimeCreated"] if c in schema), None)
            tag_col = "Sphinx_Tags" if "Sphinx_Tags" in schema else "Action"
            desc_col = "Decoded_Hint" if "Decoded_Hint" in schema else "Original_Snippet"
            if time_col and desc_col in schema:
                 parts.append(self.df_sphinx.select([
                    pl.col(time_col).alias("Time"), pl.lit("Sphinx").alias("Module"),
                    pl.format("DECODED: [{}] {}", pl.col(tag_col).fill_null("UNK"), pl.col(desc_col).fill_null("").str.slice(0, 100)).alias("Desc")]))
        
        # Hercules (Timeline) - Extended for Context (ShellBags/Web)
        if self.df_timeline is not None and not self.df_timeline.is_empty():
            # Filter Logic: Keep if (Critical OR Context) AND Not System Noise
            target_tags = ["[EXPLORER]", "[WEB]"] 
            
            filtered_rows = []
            for row in self.df_timeline.iter_rows(named=True):
                tag = str(row.get("Tag", ""))
                user = str(row.get("Resolved_User", ""))
                sid = str(row.get("Subject_SID", ""))
                
                is_critical = "CRITICAL" in tag or "[!]" in tag or "DELETED_USER" in tag
                is_context = any(t in tag for t in target_tags)
                
                if (is_critical or is_context) and not self._is_system_noise(user, sid):
                    filtered_rows.append(row)
                    
            if filtered_rows:
                parts.append(pl.DataFrame(filtered_rows, schema=self.df_timeline.schema).select([
                    pl.col("Timestamp_UTC").alias("Time"), pl.lit("Hercules").alias("Module"),
                    pl.format("{} (User: {})", "Tag", "Resolved_User").alias("Desc")]))

        if parts:
            df_concat = pl.concat([p.with_columns(pl.col("Time").cast(pl.Utf8)) for p in parts])
            story = self._compress_storyline(df_concat)
            if story is not None and len(story) > 100:
                # Top 100 most recent (Descending Sort)
                return story.sort("Time", descending=True).head(100)
            return story
        return None

    def generate_grimoire(self, output_path):
        t = self.txt  # [FIXED] Correctly use the already selected dictionary
        hercules_count = self._get_hercules_stats()
        def get_count(df): return len(df) if df is not None else 0

        with open(output_path, "w", encoding="utf-8") as f:
            scope_str = "All Time"
            if self.start_time or self.end_time: scope_str = f"{self.start_time or '...'} ~ {self.end_time or '...'}"
            f.write(f"# {t['title']}\n\n- **Generated:** {datetime.datetime.now()}\n- **{t['scope']}:** {scope_str}\n\n")

            # 1. Identity
            if self.df_timeline is not None and "Resolved_User" in self.df_timeline.columns:
                f.write(f"## {t['h1_users']}\n\n| {t['col_user']} | {t['col_sid']} | {t['col_status']} |\n|---|---|---|\n")
                summary = self.df_timeline.select(["Resolved_User", "Subject_SID", "Account_Status"]).unique().sort("Account_Status")
                for r in summary.iter_rows(named=True):
                    # Nice display for None SID
                    sid_disp = r['Subject_SID'] if r['Subject_SID'] and str(r['Subject_SID']) != "None" else "N/A"
                    f.write(f"| {r['Resolved_User']} | `{sid_disp}` | {r['Account_Status']} |\n")
                f.write("\n")

            # 2. Executive Summary
            f.write(f"## {t['h1_summary']}\n\n| {t['h1_cols'][0]} | {t['h1_cols'][1]} | {t['h1_cols'][2]} |\n|---|---|---|\n")
            f.write(f"| Hercules | {t['status_crit'] if hercules_count > 0 else t['status_safe']} | {hercules_count} |\n")
            f.write(f"| Chronos | {t['status_crit'] if get_count(self.df_chronos)>0 else t['status_safe']} | {get_count(self.df_chronos)} |\n")
            f.write(f"| AION | {t['status_crit'] if get_count(self.df_aion)>0 else t['status_safe']} | {get_count(self.df_aion)} |\n")
            f.write(f"| Sphinx | {t['status_crit'] if get_count(self.df_sphinx)>0 else t['status_safe']} | {get_count(self.df_sphinx)} |\n")
            f.write(f"| Pandora | {t['status_warn'] if get_count(self.df_pandora)>0 else t['status_safe']} | {get_count(self.df_pandora)} (All Time) |\n")
            f.write(f"| Plutos | {t['status_crit'] if get_count(self.df_plutos)>0 else t['status_safe']} | {get_count(self.df_plutos)} |\n\n")

            # 3. Critical Breakdown
            f.write(f"## {t['h2_breakdown']}\n> {t['desc_breakdown']}\n\n")
            
            # Hercules Breakdown
            if hercules_count > 0:
                f.write(f"### 🔥 Hercules: Privilege & Authority\n| {t['col_time']} | Tag | {t['col_user']} |\n|---|---|---|\n")
                crit_events = self.df_timeline.filter(pl.col("Tag").str.contains(r"\[!\]|CRITICAL|DELETED_USER"))
                count = 0
                for r in crit_events.iter_rows(named=True):
                    if "DELETED_USER" in r["Tag"] or not self._is_system_noise(r["Resolved_User"], r["Subject_SID"]):
                         f.write(f"| {r['Timestamp_UTC']} | **{r['Tag']}** | {r['Resolved_User']} |\n")
                         count += 1
                         if count >= 5: break
                f.write("\n")

            # Chronos Breakdown
            if get_count(self.df_chronos) > 0 and "Chronos_Score" in self.df_chronos.columns:
                f.write(f"### ⏳ Chronos: Time Anomalies (Top 5)\n| {t['col_time']} | Score | {t['col_file']} |\n|---|---|---|\n")
                for r in self.df_chronos.sort("Chronos_Score", descending=True).head(5).iter_rows(named=True):
                    f.write(f"| {r.get('Anomaly_Time','')} | {r.get('Chronos_Score','')} | `{r.get('FileName','')}` |\n")
                f.write("\n")
            
            # AION Breakdown
            if get_count(self.df_aion) > 0:
                f.write(f"### 👁️ AION: Persistence (Top 5)\n| {t['col_time']} | Tags | Target |\n|---|---|---|\n")
                for r in self.df_aion.head(5).iter_rows(named=True):
                     f.write(f"| {r.get('Last_Executed_Time','')} | {r.get('AION_Tags','')} | `{r.get('Target_FileName','')}` |\n")
                f.write("\n")

            # Sphinx Breakdown
            if get_count(self.df_sphinx) > 0:
                f.write(f"### 🦁 Sphinx: Decoded Scripts (Top 5)\n| {t['col_time']} | Rule | Hint |\n|---|---|---|\n")
                sc = self.df_sphinx.collect_schema().names()
                tc = next((c for c in ["TimeCreated", "Timestamp_UTC"] if c in sc), "Time")
                rc = "Sphinx_Tags" if "Sphinx_Tags" in sc else "Action"
                hc = "Decoded_Hint" if "Decoded_Hint" in sc else "Original_Snippet"
                for r in self.df_sphinx.head(5).iter_rows(named=True):
                     hint = str(r.get(hc, ""))[:50].replace("\n", " ")
                     f.write(f"| {r.get(tc,'')} | {r.get(rc,'')} | `{hint}...` |\n")
                f.write("\n")

            # Plutos Breakdown
            if get_count(self.df_plutos) > 0:
                f.write(f"### 💸 Plutos: Data Exfiltration (Top 5)\n| {t['col_time']} | Verdict | {t['col_file']} |\n|---|---|---|\n")
                plutos_clean = self.df_plutos.filter(~pl.col("Plutos_Verdict").is_in(["NORMAL_APP_ACCESS", "SYSTEM_INTERNAL_ACTIVITY"]))
                for r in plutos_clean.head(5).iter_rows(named=True):
                    f.write(f"| {r.get('SourceModified','')} | {r.get('Plutos_Verdict','')} | `{r.get('Target_FileName','')}` |\n")
                f.write("\n")

            # 4. Storyline
            df_story = self.weave_storyline()
            if df_story is not None:
                f.write(f"## {t['h2_story']}\n> {t['desc_story']}\n\n| {t['col_time']} | {t['col_mod']} | {t['col_desc']} |\n|---|---|---|\n")
                for row in df_story.iter_rows(named=True):
                    f.write(f"| {row['Time']} | **{row['Module']}** | {row['Desc']} |\n")
            
            # 5. Pandora
            if get_count(self.df_pandora) > 0:
                f.write(f"\n## {t['h2_ghosts']}\n> {t['desc_ghosts']}\n\n")
                f.write(f"| {t['col_risk']} | {t['col_file']} | {t['col_path']} | {t['col_src']} |\n|---|---|---|---|\n")
                for row in self.df_pandora.head(10).iter_rows(named=True):
                    f.write(f"| {row.get('Risk_Tag','')} | `{row.get('Ghost_FileName','')}` | `{row.get('ParentPath','')}` | {row.get('Source','')} |\n")
                if len(self.df_pandora) > 10: f.write(f"\n*(...and {len(self.df_pandora)-10} more)*\n")

            f.write(f"\n---\n*End of SkiaHelios Report.*")

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--out", default="Final_Grimoire.md")
    parser.add_argument("--aion"); parser.add_argument("--pandora"); 
    parser.add_argument("--plutos"); parser.add_argument("--plutos-net"); 
    parser.add_argument("--sphinx"); parser.add_argument("--chronos"); 
    parser.add_argument("--lang", default="en")
    parser.add_argument("--start"); parser.add_argument("--end")
    args = parser.parse_args(argv)
    
    weaver = HekateWeaver(args.input, args.aion, args.pandora, args.plutos, args.plutos_net, args.sphinx, args.chronos, args.lang, args.start, args.end)
    weaver.generate_grimoire(args.out)

if __name__ == "__main__":
    main()
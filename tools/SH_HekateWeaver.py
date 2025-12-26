import polars as pl
import argparse
from pathlib import Path
import sys
import datetime
import re

# ============================================================
#  SH_HekateWeaver v6.9 [The Cerberus Master - FULL SPECS]
#  Mission: Bind threads of evidence WITHOUT losing v6.5 detail logic.
#  Updated: Full v6.5 memory tuning + v2.0 Sniper Integration.
#  Final Physical Line Check: 368 Lines.
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HEKATE  --   [ The Grand Weaver v6.9 ]
      | | | | | |   "Truth is captured in the scope."
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
        "h2_breakdown": "3. Sniper Hits & Critical Artifacts",
        "desc_breakdown": "Priority correlations from Sniper Mode followed by module hits.",
        "h2_story": "4. Anomalous Storyline (Timeline View)",
        "desc_story": "Chronological fusion. 🎯 indicates a Sniper Hit (Ghost correlation).",
        "col_time": "Timestamp", "col_mod": "Module", "col_desc": "Description / Evidence",
        "h2_ghosts": "5. Hidden & Deleted Artifacts (Pandora)",
        "desc_ghosts": "Top 10 artifacts identified via USN/MFT gap analysis (Ghosts).",
        "col_risk": "Risk Tag", "col_file": "File Name", "col_path": "Original Path", "col_src": "Detection Source",
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
        "h2_breakdown": "3. 狙撃成功と重要アーティファクト (Top Hits)",
        "desc_breakdown": "スナイパーモードで特定された相関証拠、および各モジュールの重要検出を抜粋。",
        "h2_story": "4. 統合ストーリーライン (時系列ビュー)",
        "desc_story": "各イベントを時系列で統合。🎯マークはPandoraの消去痕跡と合致したイベントっス！",
        "col_time": "発生時刻", "col_mod": "モジュール", "col_desc": "検出内容 / 証拠",
        "h2_ghosts": "5. 隠蔽・削除アーティファクト (Pandora)",
        "desc_ghosts": "USNジャーナルやMFTのギャップ解析により特定された『ゴースト』ファイル（Top 10）。",
        "col_risk": "リスクタグ", "col_file": "ファイル名", "col_path": "復元パス", "col_src": "検知ソース",
    }
}

class HekateWeaver:
    def __init__(self, timeline_csv, aion_csv=None, pandora_csv=None, plutos_csv=None, plutos_net_csv=None, sphinx_csv=None, chronos_csv=None, lang="en", start_time=None, end_time=None):
        self.lang = lang if lang in TEXT_RES else "en"
        self.txt = TEXT_RES[self.lang]
        self.start_time = start_time
        self.end_time = end_time
        
        # Load Data with Memory Tuning
        self.df_timeline = self._safe_load(timeline_csv, "Hercules", time_col="Timestamp_UTC", 
            cols=["Timestamp_UTC", "Tag", "Resolved_User", "Subject_SID", "Action", "Account_Status"])
        self.df_aion     = self._safe_load(aion_csv, "AION", time_col="Last_Executed_Time",
            cols=["Last_Executed_Time", "Target_FileName", "AION_Tags", "AION_Score"])
        self.df_pandora  = self._safe_load(pandora_csv, "Pandora", time_col=None,
            cols=["Risk_Tag", "Ghost_FileName", "ParentPath", "Source"]) 
        self.df_plutos   = self._safe_load(plutos_csv, "Plutos", time_col="SourceModified",
            cols=["SourceModified", "Target_FileName", "Plutos_Verdict", "Risk_Tag", "LocalPath"])
        self.df_plutos_net = self._safe_load(plutos_net_csv, "Plutos(Net)", time_col=None,
            cols=["Plutos_Verdict", "Total_Sent_MB", "AppId", "Interval_StdDev"])
        self.df_sphinx   = self._safe_load(sphinx_csv, "Sphinx", time_col="TimeCreated",
            cols=["TimeCreated", "Sphinx_Tags", "Decoded_Hint", "Original_Snippet"])
        self.df_chronos  = self._safe_load(chronos_csv, "Chronos", time_col="Anomaly_Time",
            cols=["Anomaly_Time", "Chronos_Score", "FileName", "Anomaly_Zero"])

    def _safe_load(self, path, module_name, time_col=None, cols=None):
        if path and Path(path).exists():
            try:
                lf = pl.scan_csv(path, ignore_errors=True, infer_schema_length=0)
                if cols:
                    available_cols = lf.collect_schema().names()
                    target_cols = [c for c in cols if c in available_cols]
                    if target_cols: lf = lf.select(target_cols)
                if time_col and (self.start_time or self.end_time):
                    try:
                        if self.start_time: lf = lf.filter(pl.col(time_col) >= self.start_time)
                        if self.end_time:   lf = lf.filter(pl.col(time_col) <= self.end_time)
                    except: pass
                df = lf.collect()
                print(f"[+] {module_name} Data Woven: {len(df)} rows")
                return df
            except Exception as e:
                print(f"[!] Warning: Failed to load {module_name}: {e}")
                return None
        return None

    def _is_system_noise(self, user_val, sid_val):
        system_users = ["SYSTEM", "Local Service", "Network Service", "DWM", "Window Manager", "UMFD"]
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
                if any(x in tag for x in ["CRITICAL", "[!]", "DELETED_USER", "SNIPER"]):
                    user = str(row.get("Resolved_User", ""))
                    sid = str(row.get("Subject_SID", ""))
                    if not self._is_system_noise(user, sid): count += 1
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

    def _format_plutos_verdict(self, verdict, target):
        v = str(verdict)
        if "BEACON" in v: return f"📡 C2 BEACON: {target} ({v})"
        if "RDP" in v: return f"🖥️ RDP EXFIL: {target} ({v})"
        if "CLOUD" in v: return f"☁️ CLOUD UPLOAD: {target} ({v})"
        if "CONFIRMED" in v: return f"🚨 CONFIRMED EXFIL: {target}"
        return f"💸 Exfil Suspicion: {target} ({v})"

    def weave_storyline(self):
        print("[*] Weaving Storyline with Sniper Intel...")
        parts = []
        if self.df_chronos is not None and not self.df_chronos.is_empty():
            parts.append(self.df_chronos.select([pl.col("Anomaly_Time").alias("Time"), pl.lit("Chronos").alias("Module"), pl.format("{} (Score: {}) in {}", "Anomaly_Time", "Chronos_Score", "FileName").alias("Desc")]))
        if self.df_aion is not None and not self.df_aion.is_empty():
            parts.append(self.df_aion.select([pl.col("Last_Executed_Time").alias("Time"), pl.lit("AION").alias("Module"), pl.format("PERSISTENCE: {} [{}]", "Target_FileName", "AION_Tags").alias("Desc")]))
        if self.df_plutos is not None and not self.df_plutos.is_empty():
            plutos_clean = self.df_plutos.filter(~pl.col("Plutos_Verdict").is_in(["NORMAL_APP_ACCESS", "SYSTEM_INTERNAL_ACTIVITY", "USB_ACCESS"]))
            if not plutos_clean.is_empty():
                parts.append(plutos_clean.select([pl.col("SourceModified").alias("Time"), pl.lit("Plutos").alias("Module"), pl.struct(["Plutos_Verdict", "Target_FileName"]).map_elements(lambda x: self._format_plutos_verdict(x["Plutos_Verdict"], x["Target_FileName"]), return_dtype=pl.Utf8).alias("Desc")]))
        if self.df_sphinx is not None and not self.df_sphinx.is_empty():
            sc = self.df_sphinx.collect_schema().names()
            tc = next((c for c in ["Timestamp_UTC", "TimeCreated"] if c in sc), "Time")
            hc = "Decoded_Hint" if "Decoded_Hint" in sc else "Original_Snippet"
            parts.append(self.df_sphinx.select([pl.col(tc).alias("Time"), pl.lit("Sphinx").alias("Module"), pl.format("🦁 DECODED: {}", pl.col(hc).str.slice(0, 100)).alias("Desc")]))
        if self.df_timeline is not None and not self.df_timeline.is_empty():
            target_tags = ["[EXPLORER]", "[WEB]", "SNIPER"] 
            filtered_rows = []
            for row in self.df_timeline.iter_rows(named=True):
                tag = str(row.get("Tag", ""))
                user = str(row.get("Resolved_User", ""))
                sid = str(row.get("Subject_SID", ""))
                 # SNIPERタグを検知対象に追加
                is_sniper = "SNIPER" in tag or "HIT" in tag
                is_critical = any(x in tag for x in ["CRITICAL", "[!]", "DELETED_USER"])
                is_context = any(t in tag for t in target_tags + ["SNIPER"])
                
                if (is_sniper or is_critical or is_context) and not self._is_system_noise(user, sid):
                    desc = tag
                    if is_sniper:
                        desc = f"🎯 {tag}" # 的中マークを付与っス！
                    filtered_rows.append({"Time": row.get("Timestamp_UTC"), "Module": "Hercules", "Desc": f"{desc} (User: {user})"})
            if filtered_rows:
                parts.append(pl.DataFrame(filtered_rows).select(["Time", "Module", "Desc"]))
        if parts:
            df_concat = pl.concat([p.with_columns(pl.col("Time").cast(pl.Utf8)) for p in parts])
            story = self._compress_storyline(df_concat)
            return story.sort("Time", descending=True).head(150) if story is not None else None
        return None

    def generate_grimoire(self, output_path):
        t = self.txt
        hercules_count = self._get_hercules_stats()
        def get_count(df): return len(df) if df is not None else 0

        with open(output_path, "w", encoding="utf-8") as f:
            scope_str = "All Time"
            if self.start_time or self.end_time: scope_str = f"{self.start_time or '...'} ~ {self.end_time or '...'}"
            f.write(f"# {t['title']}\n\n- **Generated:** {datetime.datetime.now()}\n- **{t['scope']}:** {scope_str}\n\n")

            if self.df_timeline is not None:
                f.write(f"## {t['h1_users']}\n\n| {t['col_user']} | {t['col_sid']} | {t['col_status']} |\n|---|---|---|\n")
                summary = self.df_timeline.select(["Resolved_User", "Subject_SID", "Account_Status"]).unique()
                for r in summary.iter_rows(named=True):
                    sid_disp = r['Subject_SID'] if r['Subject_SID'] and str(r['Subject_SID']) != "None" else "N/A"
                    f.write(f"| {r['Resolved_User']} | `{sid_disp}` | {r['Account_Status']} |\n")
                f.write("\n")

            f.write(f"## {t['h1_summary']}\n\n| {t['h1_cols'][0]} | {t['h1_cols'][1]} | {t['h1_cols'][2]} |\n|---|---|---|\n")
            f.write(f"| Hercules | {t['status_crit'] if hercules_count > 0 else t['status_safe']} | {hercules_count} |\n")
            f.write(f"| Chronos | {t['status_crit'] if get_count(self.df_chronos)>0 else t['status_safe']} | {get_count(self.df_chronos)} |\n")
            f.write(f"| AION | {t['status_crit'] if get_count(self.df_aion)>0 else t['status_safe']} | {get_count(self.df_aion)} |\n")
            plutos_cnt = get_count(self.df_plutos) + get_count(self.df_plutos_net)
            status_plutos = t['status_safe']
            if self.df_plutos_net is not None and not self.df_plutos_net.filter(pl.col("Plutos_Verdict").str.contains("BEACON|DATA_EXFIL")).is_empty():
                status_plutos = t['status_crit']
            f.write(f"| Plutos (Net/USB) | {status_plutos} | {plutos_cnt} |\n")
            f.write(f"| Sphinx | {t['status_crit'] if get_count(self.df_sphinx)>0 else t['status_safe']} | {get_count(self.df_sphinx)} |\n")
            f.write(f"| Pandora | {t['status_warn'] if get_count(self.df_pandora)>0 else t['status_safe']} | {get_count(self.df_pandora)} |\n\n")

            f.write(f"## {t['h2_breakdown']}\n> {t['desc_breakdown']}\n\n")
            
            # --- [VITAL] Restoring Section 3 detail logic exactly as v6.5 ---
            
            # 狙撃成功（Sniper Hits）を最優先で表示！
            if self.df_timeline is not None:
                sniper_hits = self.df_timeline.filter(pl.col("Tag").str.contains(r"SNIPER|HIT"))
                if not sniper_hits.is_empty():
                    f.write(f"### 🎯 Sniper Mode Correlations (Cerberus)\n")
                    f.write(f"> Pandoraが特定した証拠隠滅時刻と物理的に一致するシステムイベントっス！\n\n")
                    f.write(f"| {t['col_time']} | Tag | {t['col_user']} | Action |\n|---|---|---|---|\n")
                    # 10件まで抜粋
                    for r in sniper_hits.sort("Timestamp_UTC", descending=True).head(10).iter_rows(named=True):
                        f.write(f"| {r['Timestamp_UTC']} | **{r['Tag']}** | {r['Resolved_User']} | {str(r['Action'])[:80]}... |\n")
                    f.write("\n")

            # PLUTOS Detailed Loop
            if get_count(self.df_plutos_net) > 0 or get_count(self.df_plutos) > 0:
                f.write(f"### 🐕 Plutos: Exfiltration & C2\n| Type | Verdict | Target / AppId |\n|---|---|---|\n")
                if self.df_plutos_net is not None:
                    for r in self.df_plutos_net.head(5).iter_rows(named=True):
                        verdict = r.get('Plutos_Verdict', '')
                        icon = "📡" if "BEACON" in verdict else "☁️" if "CLOUD" in verdict else "📉"
                        try: mb = float(r.get('Total_Sent_MB', 0))
                        except: mb = 0.0
                        f.write(f"| {icon} Network | **{verdict}** | `{r.get('AppId','')}` ({mb:.1f} MB) |\n")
                if self.df_plutos is not None:
                    plutos_clean = self.df_plutos.filter(~pl.col("Plutos_Verdict").is_in(["NORMAL_APP_ACCESS", "SYSTEM_INTERNAL_ACTIVITY", "USB_ACCESS"]))
                    for r in plutos_clean.head(5).iter_rows(named=True):
                        icon = "🖥️" if "RDP" in r.get('Plutos_Verdict','') else "💾"
                        f.write(f"| {icon} Device | **{r.get('Plutos_Verdict','')}** | `{r.get('Target_FileName','')}` |\n")
                f.write("\n")

            # AION Detailed Loop
            if get_count(self.df_aion) > 0:
                f.write(f"### 👁️ AION: Persistence (Top 5)\n| {t['col_time']} | Tags | Target |\n|---|---|---|\n")
                for r in self.df_aion.head(5).iter_rows(named=True):
                     f.write(f"| {r.get('Last_Executed_Time','')} | {r.get('AION_Tags','')} | `{r.get('Target_FileName','')}` |\n")
                f.write("\n")

            # SPHINX Detailed Loop
            if get_count(self.df_sphinx) > 0:
                f.write(f"### 🦁 Sphinx: Decoded Scripts (Top 5)\n| {t['col_time']} | Rule | Hint |\n|---|---|---|\n")
                sc = self.df_sphinx.collect_schema().names()
                tc = next((c for c in ["TimeCreated", "Timestamp_UTC"] if c in sc), "Time")
                for r in self.df_sphinx.head(5).iter_rows(named=True):
                     hint = str(r.get("Decoded_Hint", ""))[:60].replace("\n", " ")
                     f.write(f"| {r.get(tc,'')} | {r.get('Sphinx_Tags','')} | `{hint}...` |\n")
                f.write("\n")

            # Storyline
            df_story = self.weave_storyline()
            if df_story is not None:
                f.write(f"## {t['h2_story']}\n> {t['desc_story']}\n\n| {t['col_time']} | {t['col_mod']} | {t['col_desc']} |\n|---|---|---|\n")
                for row in df_story.iter_rows(named=True):
                    f.write(f"| {row['Time']} | **{row['Module']}** | {row['Desc']} |\n")
            
            # Pandora Ghosts Detail
            if get_count(self.df_pandora) > 0:
                f.write(f"\n## {t['h2_ghosts']}\n> {t['desc_ghosts']}\n\n")
                f.write(f"| {t['col_risk']} | {t['col_file']} | {t['col_path']} | {t['col_src']} |\n|---|---|---|---|\n")
                for row in self.df_pandora.head(10).iter_rows(named=True):
                    f.write(f"| {row.get('Risk_Tag','')} | `{row.get('Ghost_FileName','')}` | `{row.get('ParentPath','')}` | {row.get('Source','')} |\n")

            f.write(f"\n---\n*End of SkiaHelios Report.*")

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--out", default="Final_Grimoire.md")
    parser.add_argument("--aion"); parser.add_argument("--pandora"); parser.add_argument("--plutos"); 
    parser.add_argument("--plutos-net"); parser.add_argument("--sphinx"); parser.add_argument("--chronos")
    parser.add_argument("--lang", default="en")
    parser.add_argument("--start"); parser.add_argument("--end")
    args = parser.parse_args(argv)
    weaver = HekateWeaver(args.input, args.aion, args.pandora, args.plutos, args.plutos_net, args.sphinx, args.chronos, args.lang, args.start, args.end)
    weaver.generate_grimoire(args.out)

if __name__ == "__main__":
    main()
import polars as pl
import argparse
from pathlib import Path
import sys
import datetime

# ============================================================
#  SH_HekateWeaver v2.8.9 [Resilient Binder]
#  Mission: Bind threads of evidence without crashing on null times.
#  Fix: Added robust null-check for AION correlated timestamps.
#  Goal: Finalize the story for the Challenge Coin.
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HEKATE  --   [ The Grand Weaver v2.8.9 ]
      | | | | | |   "Resilience is the soul of forensics."
    """)

TEXT_RES = {
    "en": {
        "title": "SkiaHelios Forensic Analysis Report",
        "intro": "Custom DFIR framework for high-resolution artifact correlation.",
        "h1_legend": "0. Methodology & Artifact Legend",
        "legend_desc": "SkiaHelios correlates disparate artifacts to reconstruct attacker intent.",
        "tool_list": [
            ("Chaos", "Master Timeline construction."),
            ("Chronos", "MFT Time Paradox (Timestomp) detection."),
            ("AION", "Persistence hunting correlated with MFT."),
            ("Plutos", "Exfiltration tracking via USB/Network."),
            ("Sphinx", "Decoding obfuscated scripts.")
        ],
        "tag_legend": [
            ("TIMESTOMP_BACKDATE", "$SI < $FN Creation Time discrepancy."),
            ("USER_PERSISTENCE", "Persistence detected in HKCU (User-level)."),
            ("WMI_PERSISTENCE", "WMI Eventing used for fileless persistence.")
        ],
        "h1_summary": "1. Executive Summary",
        "h1_cols": ["Module", "Risk Level", "Detection Count"],
        "status_crit": "CRITICAL",
        "h2_story": "2. Anomalous Storyline (Event Sequence)",
        "desc_story": "Chronological fusion of all high-priority anomalies.",
        "h2_threats": "3. High-Priority Detection Details",
        "h3_exfil": "Exfiltration & Access (Plutos)",
        "h3_persist": "Persistence Mechanism (AION)",
        "h3_time": "Timeline Anomaly (Chronos)",
        "h3_sphinx": "Obfuscation Decoded (Sphinx)",
        "col_time": "Timestamp",
        "col_mod": "Module",
        "col_desc": "Anomaly Description"
    },
    "jp": {
        "title": "SkiaHelios フォレンジック解析報告書",
        "intro": "アーティファクト間の相関分析に特化した自動生成報告書。",
        "h1_legend": "0. 調査手法および凡例",
        "legend_desc": "SkiaHeliosは、分散した証拠を紐付け、攻撃者の意図を再構成します。",
        "tool_list": [
            ("Chaos", "マスタータイムラインの構築"),
            ("Chronos", "MFTタイムスタンプ矛盾の検知"),
            ("AION", "MFT相関型永続化メカニズムの探索"),
            ("Plutos", "情報持ち出しトラッキング"),
            ("Sphinx", "難読化スクリプトの解読")
        ],
        "tag_legend": [
            ("TIMESTOMP_BACKDATE", "$SI時刻が$FN時刻より古い矛盾"),
            ("USER_PERSISTENCE", "HKCU(ユーザー権限)での永続化検知"),
            ("WMI_PERSISTENCE", "WMIを利用したファイルレス潜伏")
        ],
        "h1_summary": "1. エグゼクティブ・サマリー",
        "h1_cols": ["モジュール", "リスクレベル", "検知件数"],
        "status_crit": "【警告】要調査",
        "h2_story": "2. 異常イベント・ストーリーライン",
        "desc_story": "各モジュールが検知した不審なイベントを時系列で構成しています。",
        "h2_threats": "3. 高優先度検知詳細",
        "h3_exfil": "情報持ち出し痕跡 (Plutos)",
        "h3_persist": "永続化メカニズム (AION)",
        "h3_time": "タイムスタンプ異常 (Chronos)",
        "h3_sphinx": "難読化解除結果 (Sphinx)",
        "col_time": "発生時刻",
        "col_mod": "検知モジュール",
        "col_desc": "イベント内容"
    }
}

class HekateWeaver:
    def __init__(self, timeline_csv, aion_csv=None, pandora_csv=None, plutos_csv=None, sphinx_csv=None, chronos_csv=None, lang="en"):
        self.lang = lang if lang in TEXT_RES else "en"
        self.txt = TEXT_RES[self.lang]
        self.df_timeline = self._safe_load(timeline_csv, "Timeline")
        self.df_aion     = self._safe_load(aion_csv, "AION")
        self.df_pandora  = self._safe_load(pandora_csv, "Pandora")
        self.df_plutos   = self._safe_load(plutos_csv, "Plutos")
        self.df_sphinx   = self._safe_load(sphinx_csv, "Sphinx")
        self.df_chronos  = self._safe_load(chronos_csv, "Chronos")

    def _safe_load(self, path, name):
        if path and Path(path).exists():
            try:
                df = pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
                # [Fix] 読み込み時点での表示を消し、結合後の数を出すように変更っス
                # print(f"  [+] {name}: Loaded {len(df)} records.")
                return df
            except: return None
        return None

    def hunt_execution_anomalies(self, timeline_df):
        """
        タイムラインから「実行された危険なプロセス」を直接抽出するっス！
        """
        # 指名手配リスト (Regex)
        WANTED_PROCESSES = [
            r"(?i)timestomp\.exe", r"(?i)beacon\.exe",
            r"(?i)mimikatz", r"(?i)cobaltstrike",
            r"(?i)metasploit", r"(?i)powershell_ise\.exe",
            r"(?i)cmd\.exe", r"(?i)psexec", r"(?i)vssadmin",
            r"(?i)Trigger2" # Added user's trigger name
        ]
        
        # Prefetch, Amcache, UserAssist 等の実行痕跡に絞る
        if "Artifact_Type" not in timeline_df.columns: return []
        
        exec_df = timeline_df.filter(
            pl.col("Artifact_Type").str.contains("(?i)(Prefetch|Amcache|UserAssist|ShimCache)")
        )
        
        detected_executions = []
        
        for pattern in WANTED_PROCESSES:
            # Target_Path OR Action (some parsers put path in Action)
            hits = exec_df.filter(
                pl.col("Target_Path").str.contains(pattern)
            )
            
            if not hits.is_empty():
                for row in hits.iter_rows(named=True):
                    detected_executions.append({
                        "Time": row['Timestamp_UTC'],
                        "Module": "**Execution**",
                        "Risk_Level": "CRITICAL",
                        "Desc": f"MALICIOUS_EXECUTION: {row['Target_Path']} ({row['Artifact_Type']})"
                    })
                    
        return detected_executions

    def weave_storyline(self):
        print("[*] Weaving the Anomalous Storyline with MFT-Correlated evidence...")
        parts = []

        # Chronos
        if self.df_chronos is not None and len(self.df_chronos) > 0:
            ts_col = next((c for c in ["Created0x10", "si_dt", "Timestamp_UTC"] if c in self.df_chronos.columns), None)
            if ts_col:
                parts.append(self.df_chronos.select([
                    pl.col(ts_col).alias("Time"), pl.lit("Chronos").alias("Module"),
                    pl.format("{} (Score: {}) in {}", "Anomaly_Time", "Chronos_Score", "FileName").alias("Desc")
                ]))

        # AION: [FIX] 堅牢なヌルチェックを追加っス！
        if self.df_aion is not None and len(self.df_aion) > 0:
            time_col = next((c for c in ["Last_Executed_Time", "Timestamp_UTC"] if c in self.df_aion.columns), None)
            if time_col:
                # 時刻があるものだけストーリーラインへ、無いものは詳細セクションへ
                df_timed = self.df_aion.filter(pl.col(time_col).is_not_null())
                if not df_timed.is_empty():
                    parts.append(df_timed.select([
                        pl.col(time_col).alias("Time"),
                        pl.lit("AION").alias("Module"),
                        pl.format("Persist: {} in {} ({})", 
                                  "Target_FileName", "Entry_Location", "AION_Tags").alias("Desc")
                    ]))

        # Plutos:
        if self.df_plutos is not None and len(self.df_plutos) > 0:
            # [Purification] ストーリーラインを紡ぐ前に、物理的な「ゴミ（NORMAL）」を焼き払うっス！
            plutos_clean = self.df_plutos.filter(
                ~pl.col("Plutos_Verdict").is_in(["NORMAL_APP_ACCESS", "SYSTEM_INTERNAL_ACTIVITY"])
            )
            
            ts_col = next((c for c in ["SourceModified", "Timestamp", "Timestamp_UTC"] if c in plutos_clean.columns), None)
            if ts_col and not plutos_clean.is_empty():
                parts.append(plutos_clean.select([
                    pl.col(ts_col).alias("Time"), pl.lit("Plutos").alias("Module"),
                    pl.format("Exfil/Access: {} ({})", "Target_FileName", "Plutos_Verdict").alias("Desc")
                ]))
            
            # [Fix] コンソール出力を「織り込まれた数」に変更するっス！！
            print(f" [+] Plutos Artifacts woven: {plutos_clean.height}")

        # Sphinx: [Patch] Infect7 Integration
        if self.df_sphinx is not None and len(self.df_sphinx) > 0:
            # 攻撃シグネチャを持つものだけを抽出 (CRITICAL only for Storyline)
            critical_sphinx = self.df_sphinx.filter(
                pl.col("Sphinx_Tags").str.contains("ATTACK_SIG_DETECTED")
            )
            
            # Standard Sphinx logs (if any)
            ts_col = next((c for c in ["TimeCreated", "Timestamp", "Timestamp_UTC"] if c in self.df_sphinx.columns), None)
            
            if ts_col:
                # 1. Critical Attacks
                if not critical_sphinx.is_empty():
                    parts.append(critical_sphinx.select([
                        pl.col(ts_col).alias("Time"), 
                        pl.lit("**Sphinx**").alias("Module"), # Bold for emphasis
                        pl.format("OBFUSCATION_DECODED: {}...", pl.col("Decoded_Hint").str.slice(0, 200)).alias("Desc")
                    ]))

        # Execution Hunter: [Patch] Infect7 Direct Hunting
        if self.df_timeline is not None:
             execution_alerts = self.hunt_execution_anomalies(self.df_timeline)
             if execution_alerts:
                 parts.append(pl.DataFrame(execution_alerts).select(["Time", "Module", "Desc"]))

        if parts:
            story_df = pl.concat(parts).sort("Time")
            print(f" [+] Storyline: Successfully woven {story_df.height} events.")
            return story_df
        return None

    def generate_grimoire(self, output_path):
        t = self.txt
        has_chronos = self.df_chronos is not None and len(self.df_chronos) > 0
        has_aion    = self.df_aion is not None and len(self.df_aion) > 0
        has_exfil   = self.df_plutos is not None and len(self.df_plutos) > 0
        has_sphinx  = self.df_sphinx is not None and len(self.df_sphinx) > 0

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# {t['title']}\n\n- **Generated:** {datetime.datetime.now()}\n- {t['intro']}\n\n")
            
            # 0. Methodology
            f.write(f"## {t['h1_legend']}\n{t['legend_desc']}\n\n")
            f.write("### Modules:\n")
            for m, desc in t['tool_list']: f.write(f"- **{m}**: {desc}\n")
            f.write("\n### Tag Legend:\n")
            for tag, desc in t['tag_legend']: f.write(f"- `{tag}`: {desc}\n")

            # 1. Summary
            f.write(f"\n## {t['h1_summary']}\n\n| {t['h1_cols'][0]} | {t['h1_cols'][1]} | {t['h1_cols'][2]} |\n|---|---|---|\n")
            if has_chronos: f.write(f"| Chronos | {t['status_crit']} | {len(self.df_chronos)} |\n")
            if has_aion:    f.write(f"| AION | {t['status_crit']} | {len(self.df_aion)} |\n")
            
            if has_exfil:
                # [Zero-Calibration] 正常系を除外してカウントっス！
                plutos_warn = self.df_plutos.filter(
                    ~pl.col("Plutos_Verdict").is_in(["NORMAL_APP_ACCESS", "SYSTEM_INTERNAL_ACTIVITY"])
                ).height
                f.write(f"| Plutos | {t['status_crit']} | {plutos_warn} |\n")
            
            if has_sphinx:  f.write(f"| Sphinx | {t['status_crit']} | {len(self.df_sphinx)} |\n\n")

            # 2. Storyline
            df_story = self.weave_storyline()
            if df_story is not None:
                f.write(f"## {t['h2_story']}\n> {t['desc_story']}\n\n| {t['col_time']} | {t['col_mod']} | {t['col_desc']} |\n|---|---|---|\n")
                for row in df_story.iter_rows(named=True):
                    f.write(f"| {row['Time']} | **{row['Module']}** | {row['Desc']} |\n")

            # 3. Details
            f.write(f"\n## {t['h2_threats']}\n\n")
            if has_aion:
                f.write(f"### {t['h3_persist']}\n| Score | Target | Location | Path |\n|---|---|---|---|\n")
                # 時刻の有無に関わらず、上位スコアを表示っス！
                for r in self.df_aion.sort("AION_Score", descending=True).head(15).iter_rows(named=True):
                    f.write(f"| **{r['AION_Score']}** | {r['Target_FileName']} | {r['Entry_Location']} | `{r['Full_Path']}` |\n")

            if has_sphinx:
                f.write(f"\n### {t['h3_sphinx']}\n| Score | Tags | Hint |\n|---|---|---|\n")
                for r in self.df_sphinx.sort("Sphinx_Score", descending=True).head(5).iter_rows(named=True):
                    f.write(f"| **{r['Sphinx_Score']}** | {r['Sphinx_Tags']} | {r['Decoded_Hint']} |\n")

            f.write(f"\n---\n*End of SkiaHelios Report.*")

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True, help="Master Timeline CSV (Chaos)")
    parser.add_argument("-o", "--out", default="Final_Grimoire.md")
    parser.add_argument("--aion"); parser.add_argument("--pandora"); parser.add_argument("--plutos"); parser.add_argument("--sphinx"); parser.add_argument("--chronos")
    parser.add_argument("--lang", default="en")
    args = parser.parse_args(argv)
    weaver = HekateWeaver(args.input, args.aion, args.pandora, args.plutos, args.sphinx, args.chronos, args.lang)
    weaver.generate_grimoire(args.out)

if __name__ == "__main__":
    main()
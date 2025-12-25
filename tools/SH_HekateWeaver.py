import polars as pl
import argparse
from pathlib import Path
import sys
import datetime
import re

# ============================================================
#  SH_HekateWeaver v3.5 [Script Hunter]
#  Mission: Bind threads of evidence into a single truth.
#  Fix: Aggressively hunt for Script Executions (.ps1/bat/vbs) in args.
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HEKATE  --   [ The Grand Weaver v3.5 ]
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
            ("Chronos", "MFT Time Paradox (Timestomp/ADS) detection."),
            ("AION", "Persistence hunting correlated with MFT."),
            ("Plutos", "Exfiltration tracking via USB & Network Beaconing."),
            ("Sphinx", "Decoding obfuscated scripts with Process Context.")
        ],
        "tag_legend": [
            ("TIMESTOMP_BACKDATE", "$SI < $FN Creation Time discrepancy."),
            ("CRITICAL_ADS_TIMESTOMP", "Timestomp detected on Alternate Data Stream (High Confidence)."),
            ("C2_BEACON_DETECTED", "Periodic or low-volume traffic to unknown endpoints.")
        ],
        "h1_summary": "1. Executive Summary",
        "h1_cols": ["Module", "Status", "Anomaly Count"],
        "status_crit": "CRITICAL",
        "h2_story": "2. Anomalous Storyline (Event Sequence)",
        "desc_story": "Chronological fusion of all high-priority anomalies.",
        "h2_threats": "3. High-Priority Detection Details",
        "h3_exfil": "Exfiltration & Access (Plutos - File)",
        "h3_net": "C2 & Beaconing Activity (Plutos - Network)",
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
            ("Chronos", "MFTタイムスタンプ矛盾およびADS隠蔽の検知"),
            ("AION", "MFT相関型永続化メカニズムの探索"),
            ("Plutos", "情報持ち出し(USB) および C2通信の追跡"),
            ("Sphinx", "難読化スクリプトの解読とプロセス特定")
        ],
        "tag_legend": [
            ("TIMESTOMP_BACKDATE", "$SI時刻が$FN時刻より古い矛盾"),
            ("CRITICAL_ADS_TIMESTOMP", "ADS(隠しストリーム)に対する時刻偽装痕跡"),
            ("C2_BEACON_DETECTED", "未知の宛先への定期通信または低流量ビーコン")
        ],
        "h1_summary": "1. エグゼクティブ・サマリー",
        "h1_cols": ["モジュール", "リスクレベル", "検知件数"],
        "status_crit": "【警告】要調査",
        "h2_story": "2. 異常イベント・ストーリーライン",
        "desc_story": "各モジュールが検知した不審なイベントを時系列で構成しています。",
        "h2_threats": "3. 高優先度検知詳細",
        "h3_exfil": "情報持ち出し痕跡 (Plutos - File)",
        "h3_net": "不正通信・ビーコン検知 (Plutos - Network)",
        "h3_persist": "永続化メカニズム (AION)",
        "h3_time": "タイムスタンプ異常 (Chronos)",
        "h3_sphinx": "難読化解除結果 (Sphinx)",
        "col_time": "発生時刻",
        "col_mod": "検知モジュール",
        "col_desc": "イベント内容"
    }
}

class HekateWeaver:
    def __init__(self, timeline_csv, aion_csv=None, pandora_csv=None, plutos_csv=None, plutos_net_csv=None, sphinx_csv=None, chronos_csv=None, lang="en", start_time=None, end_time=None):
        self.lang = lang if lang in TEXT_RES else "en"
        self.txt = TEXT_RES[self.lang]
        self.start_time = start_time
        self.end_time = end_time
        self.df_timeline = self._safe_load(timeline_csv, "Timeline")
        self.df_aion     = self._safe_load(aion_csv, "AION")
        self.df_pandora  = self._safe_load(pandora_csv, "Pandora")
        self.df_plutos   = self._safe_load(plutos_csv, "Plutos(File)")
        self.df_plutos_net = self._safe_load(plutos_net_csv, "Plutos(Net)")
        self.df_sphinx   = self._safe_load(sphinx_csv, "Sphinx")
        self.df_chronos  = self._safe_load(chronos_csv, "Chronos")

    def _safe_load(self, path, name):
        if path and Path(path).exists():
            try:
                df = pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
                if self.start_time or self.end_time:
                    if "Timestamp_UTC" in df.columns:
                        if self.start_time: df = df.filter(pl.col("Timestamp_UTC") >= self.start_time)
                        if self.end_time:   df = df.filter(pl.col("Timestamp_UTC") <= self.end_time)
                return df
            except: return None
        return None

    def hunt_execution_anomalies(self, timeline_df):
        # 1. High Risk Binaries
        WANTED_PROCESSES = [
            r"(?i)timestomp\.exe", r"(?i)beacon\.exe",
            r"(?i)mimikatz", r"(?i)cobaltstrike",
            r"(?i)metasploit", r"(?i)powershell_ise\.exe",
            r"(?i)powershell\.exe", r"(?i)pwsh\.exe",
            r"(?i)cmd\.exe", r"(?i)psexec", r"(?i)vssadmin",
            r"(?i)Trigger"
        ]
        
        # 2. Script Extensions (Arguments hunting)
        SCRIPT_EXTENSIONS = r"(?i)\.(ps1|bat|vbs|cmd|js|hta)$"

        if "Artifact_Type" not in timeline_df.columns: return []
        
        # Filter 1: Target Process Name
        target_mask = pl.col("Target_Path").str.contains("|".join(WANTED_PROCESSES))
        
        # Filter 2: Script in Arguments (Action column often holds args in Chaos)
        # Check if 'Action' or 'Target_Path' contains script extension
        script_mask = (
            pl.col("Target_Path").str.contains(SCRIPT_EXTENSIONS) |
            pl.col("Action").str.contains(SCRIPT_EXTENSIONS)
        )

        hits = timeline_df.filter(target_mask | script_mask)
        
        detected_executions = []
        
        if not hits.is_empty():
            for row in hits.iter_rows(named=True):
                target = str(row.get('Target_Path') or "")
                action = str(row.get('Action') or "")
                atype = str(row.get('Artifact_Type') or "")
                
                # Noise filtering
                if "sbservicetrigger" in target.lower(): continue
                if "onedrive" in target.lower(): continue

                parent_info = ""
                raw_data = str(row).lower()
                
                if "parent process name" in raw_data or "creator process name" in raw_data:
                    m = re.search(r"(?:parent|creator)\s+process\s+(?:name|path).*?\\([^\\]+\.exe)", raw_data, re.IGNORECASE)
                    if m: parent_info = f" [Parent: {m.group(1)}]"
                
                # Highlight Script Execution
                tag = "MALICIOUS_EXECUTION"
                if re.search(SCRIPT_EXTENSIONS, target) or re.search(SCRIPT_EXTENSIONS, action):
                    tag = "SCRIPT_EXECUTION"
                    # Try to extract script name from Action if target is generic (like powershell)
                    if "powershell" in target.lower() or "cmd" in target.lower():
                        m_scr = re.search(r"([\w\-\_]+\.(ps1|bat|vbs|cmd))", action, re.IGNORECASE)
                        if m_scr:
                             target = f"{target} -> {m_scr.group(1)}"

                detected_executions.append({
                    "Time": row['Timestamp_UTC'],
                    "Module": "**Execution**",
                    "Risk_Level": "CRITICAL",
                    "Desc": f"{tag}: {target} ({atype}) {action[:50]}...{parent_info}"
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

        # AION
        if self.df_aion is not None and len(self.df_aion) > 0:
            time_col = next((c for c in ["Last_Executed_Time", "Timestamp_UTC"] if c in self.df_aion.columns), None)
            if time_col:
                df_timed = self.df_aion.filter(pl.col(time_col).is_not_null())
                if not df_timed.is_empty():
                    parts.append(df_timed.select([
                        pl.col(time_col).alias("Time"),
                        pl.lit("AION").alias("Module"),
                        pl.format("PERSISTENCE: {} [{}]", 
                                  "Target_FileName", "AION_Tags").alias("Desc")
                    ]))

        # Plutos (File)
        if self.df_plutos is not None and len(self.df_plutos) > 0:
            plutos_clean = self.df_plutos.filter(
                ~pl.col("Plutos_Verdict").is_in(["NORMAL_APP_ACCESS", "SYSTEM_INTERNAL_ACTIVITY"])
            )
            ts_col = next((c for c in ["SourceModified", "Timestamp", "Timestamp_UTC"] if c in plutos_clean.columns), None)
            if ts_col and not plutos_clean.is_empty():
                parts.append(plutos_clean.select([
                    pl.col(ts_col).alias("Time"), pl.lit("Plutos (File)").alias("Module"),
                    pl.format("Exfil/Access: {} ({})", "Target_FileName", "Plutos_Verdict").alias("Desc")
                ]))

        # Sphinx
        if self.df_sphinx is not None and len(self.df_sphinx) > 0:
            df_sphinx_safe = self.df_sphinx.with_columns(
                pl.col("Sphinx_Score").cast(pl.Int64, strict=False).fill_null(0)
            )

            critical_sphinx = df_sphinx_safe.filter(
                pl.col("Sphinx_Tags").str.contains("ATTACK_SIG_DETECTED") |
                (pl.col("Sphinx_Score") > 50)
            )
            
            ts_col = next((c for c in ["TimeCreated", "Timestamp", "Timestamp_UTC"] if c in df_sphinx_safe.columns), None)
            
            if ts_col and not critical_sphinx.is_empty():
                if "ProcessId" in critical_sphinx.columns:
                     parts.append(critical_sphinx.select([
                        pl.col(ts_col).alias("Time"), 
                        pl.lit("**Sphinx**").alias("Module"),
                        pl.format("DECODED_CMD: (PID:{}) {}...", pl.col("ProcessId").cast(pl.Utf8), pl.col("Decoded_Hint").str.slice(0, 100)).alias("Desc")
                    ]))
                else:
                    parts.append(critical_sphinx.select([
                        pl.col(ts_col).alias("Time"), 
                        pl.lit("**Sphinx**").alias("Module"),
                        pl.format("DECODED_CMD: {}...", pl.col("Decoded_Hint").str.slice(0, 100)).alias("Desc")
                    ]))

        # Execution Hunter (Improved v3.5)
        if self.df_timeline is not None:
             execution_alerts = self.hunt_execution_anomalies(self.df_timeline)
             if execution_alerts:
                 parts.append(pl.DataFrame(execution_alerts).select(["Time", "Module", "Desc"]))

        if parts:
            str_parts = [p.with_columns(pl.col("Time").cast(pl.Utf8)) for p in parts]
            story_df = pl.concat(str_parts).sort("Time")
            print(f" [+] Storyline: Successfully woven {story_df.height} events.")
            return story_df
        return None

    def generate_grimoire(self, output_path):
        t = self.txt
        has_chronos = self.df_chronos is not None and len(self.df_chronos) > 0
        has_aion    = self.df_aion is not None and len(self.df_aion) > 0
        has_exfil   = self.df_plutos is not None and len(self.df_plutos) > 0
        has_net     = self.df_plutos_net is not None and len(self.df_plutos_net) > 0
        has_sphinx  = self.df_sphinx is not None and len(self.df_sphinx) > 0

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# {t['title']}\n\n- **Generated:** {datetime.datetime.now()}\n- {t['intro']}\n\n")
            if self.start_time or self.end_time:
                f.write(f"- **Focus Time Range:** {self.start_time or '...'} to {self.end_time or '...'}\n\n")
            
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
                plutos_warn = self.df_plutos.filter(
                    ~pl.col("Plutos_Verdict").is_in(["NORMAL_APP_ACCESS", "SYSTEM_INTERNAL_ACTIVITY"])
                ).height
                f.write(f"| Plutos (File) | {t['status_crit']} | {plutos_warn} |\n")

            if has_net:
                net_warn = self.df_plutos_net.filter(
                    ~pl.col("Plutos_Verdict").is_in(["NORMAL_SYSTEM_ACTIVITY"])
                ).height
                f.write(f"| Plutos (Net) | {t['status_crit']} | {net_warn} |\n")
            
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
                for r in self.df_aion.sort("AION_Score", descending=True).head(15).iter_rows(named=True):
                    f.write(f"| **{r['AION_Score']}** | {r['Target_FileName']} | {r['Entry_Location']} | `{r['Full_Path']}` |\n")

            if has_net:
                f.write(f"\n### {t['h3_net']}\n| Verdict | AppId | MB Sent |\n|---|---|---|\n")
                df_net_safe = self.df_plutos_net.with_columns(
                    pl.col("Total_Sent_MB").cast(pl.Float64, strict=False).fill_null(0.0)
                )
                suspicious_net = df_net_safe.filter(
                    ~pl.col("Plutos_Verdict").is_in(["NORMAL_SYSTEM_ACTIVITY"])
                ).sort("Total_Sent_MB", descending=True)
                
                for r in suspicious_net.head(15).iter_rows(named=True):
                    app_clean = str(r['AppId']).replace("|", "/")
                    f.write(f"| **{r['Plutos_Verdict']}** | `{app_clean}` | {r['Total_Sent_MB']:.2f} |\n")

            if has_sphinx:
                f.write(f"\n### {t['h3_sphinx']}\n| Score | Tags | Hint |\n|---|---|---|\n")
                df_sphinx_safe = self.df_sphinx.with_columns(
                    pl.col("Sphinx_Score").cast(pl.Int64, strict=False).fill_null(0)
                )
                for r in df_sphinx_safe.sort("Sphinx_Score", descending=True).head(10).iter_rows(named=True):
                    f.write(f"| **{r['Sphinx_Score']}** | {r['Sphinx_Tags']} | {r['Decoded_Hint']} |\n")

            f.write(f"\n---\n*End of SkiaHelios Report.*")

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True, help="Master Timeline CSV (Chaos)")
    parser.add_argument("-o", "--out", default="Final_Grimoire.md")
    parser.add_argument("--aion"); parser.add_argument("--pandora"); 
    parser.add_argument("--plutos"); parser.add_argument("--plutos-net");
    parser.add_argument("--sphinx"); parser.add_argument("--chronos")
    parser.add_argument("--lang", default="en")
    parser.add_argument("--start", help="Filter Start Date")
    parser.add_argument("--end", help="Filter End Date")
    args = parser.parse_args(argv)
    
    weaver = HekateWeaver(
        args.input, args.aion, args.pandora, 
        args.plutos, args.plutos_net,
        args.sphinx, args.chronos, args.lang,
        args.start, args.end
    )
    weaver.generate_grimoire(args.out)

if __name__ == "__main__":
    main()
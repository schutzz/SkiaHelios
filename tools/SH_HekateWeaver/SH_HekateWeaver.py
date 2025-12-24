import polars as pl
import argparse
from pathlib import Path
import hashlib
import sys
import datetime

# ==========================================
#  SH_HekateWeaver v2.4 [Chronos Integrated]
#  Mission: Weave "Human Intent" (Full Suite)
#  Updates: Added Chronos (Time Anomaly) integration
# ==========================================

def print_logo():
    print(r"""
      | | | | | |
    -- HEKATE  --   [ The Grand Weaver v2.4 ]
      | | | | | |   "Binding the threads of fate."
    """)

# --- Language Dictionary ---
TEXT_RES = {
    "en": {
        "title": "HekateWeaver Forensic Report (Digest)",
        "concept": "Tracing Human Intent through Physical Laws",
        "h1_summary": "1. Executive Threat Summary",
        "h1_cols": ["Module", "Status", "Findings"],
        "status_crit": "🔴 CRITICAL",
        "status_clean": "🟢 Clean",
        "h2_threats": "2. High Priority Threats (Sample)",
        "desc_threats": "Immediate Action Required: Verified traces of persistence, concealment, exfiltration, obfuscation, or timestomping.",
        "h3_exfil": "🚨 Data Exfiltration (Top 5)",
        "h3_persist": "💀 Persistence Mechanisms (Top 5)",
        "h3_ghost": "👻 Ghost Artifacts (Top 5)",
        "h3_time": "⏳ Timestomping Anomalies (Top 5)",
        "h3_sphinx": "🧩 Decoded Riddles (Top 5)",
        "col_verdict": "Verdict",
        "col_drive": "Drive/Dest",
        "col_tags": "Tags",
        "col_path": "Path",
        "col_hint": "Decoded Hint",
        "col_variance": "Variance (ns)",
        "h3_timeline": "3. Woven Timeline of Intent (Digest)",
        "desc_timeline": "Filter: Displaying top {} tagged/suspicious events.",
        "col_cmd": "Verification Cmd",
        "more_events": "...and {} more tagged events. Check CSV."
    },
    # (JP辞書は省略しますが、同様に追加が必要です)
}

class HekateWeaver:
    def __init__(self, timeline_csv, aion_csv=None, pandora_csv=None, plutos_csv=None, sphinx_csv=None, chronos_csv=None, lang="en"):
        self.timeline_csv = timeline_csv
        self.aion_csv = aion_csv
        self.pandora_csv = pandora_csv
        self.plutos_csv = plutos_csv
        self.sphinx_csv = sphinx_csv
        self.chronos_csv = chronos_csv
        self.lang = lang if lang in TEXT_RES else "en"
        self.txt = TEXT_RES[self.lang]
        
        self.df_timeline = None
        self.df_aion = None
        self.df_pandora = None
        self.df_plutos = None
        self.df_sphinx = None
        self.df_chronos = None

    def load_all(self):
        print(f"[*] Hekate is gathering threads (Language: {self.lang.upper()})...")
        
        # 1. Timeline
        try:
            self.df_timeline = pl.read_csv(self.timeline_csv, ignore_errors=True)
            print(f"  [+] Timeline: Loaded {len(self.df_timeline)} events.")
        except Exception as e:
            print(f"  [!] Critical: Failed to load Timeline ({e})")
            sys.exit(1)

        # 2. AION
        if self.aion_csv and Path(self.aion_csv).exists():
            try:
                self.df_aion = pl.read_csv(self.aion_csv, ignore_errors=True)
                print(f"  [+] AION: Loaded {len(self.df_aion)} persistence items.")
            except: pass

        # 3. Pandora
        if self.pandora_csv and Path(self.pandora_csv).exists():
            try:
                self.df_pandora = pl.read_csv(self.pandora_csv, ignore_errors=True)
                print(f"  [+] Pandora: Loaded {len(self.df_pandora)} ghosts.")
            except: pass

        # 4. Plutos
        if self.plutos_csv and Path(self.plutos_csv).exists():
            try:
                self.df_plutos = pl.read_csv(self.plutos_csv, ignore_errors=True)
                print(f"  [+] Plutos: Loaded {len(self.df_plutos)} exfil artifacts.")
            except: pass
            
        # 5. Sphinx
        if self.sphinx_csv and Path(self.sphinx_csv).exists():
            try:
                self.df_sphinx = pl.read_csv(self.sphinx_csv, ignore_errors=True)
                print(f"  [+] Sphinx: Loaded {len(self.df_sphinx)} decoded riddles.")
            except: pass

        # 6. Chronos (New!)
        if self.chronos_csv and Path(self.chronos_csv).exists():
            try:
                self.df_chronos = pl.read_csv(self.chronos_csv, ignore_errors=True)
                # Filter only actual anomalies if the CSV contains all checked files
                # Assuming Chronos output contains an 'Anomaly_Score' or similar, or just lists anomalies.
                # If it's a raw list, we take it all.
                print(f"  [+] Chronos: Loaded {len(self.df_chronos)} time anomalies.")
            except: pass

    def _generate_evid(self, row_struct):
        src = str(row_struct.get('Source_File') or "")
        ts = str(row_struct.get('Timestamp_UTC') or "")
        act = str(row_struct.get('Action') or "")
        seed = f"{src}_{ts}_{act}"
        h = hashlib.md5(seed.encode()).hexdigest()[:4].upper()
        atype = str(row_struct.get('Artifact_Type') or "UNK")[:4].upper()
        return f"EVID-{atype}-{h}"

    def _generate_verify_cmd(self, artifact_type, source_file, target_path):
        source = str(source_file or "").replace("\\", "\\\\")
        atype = str(artifact_type or "").upper()
        if "PREFETCH" in atype: return f'PECmd.exe -f "{source}" --json .'
        elif "USER_ASSIST" in atype or "USERASSIST" in atype: return f'RECmd.exe -f "{source}" --bn'
        elif "AMCACHE" in atype: return f'AmcacheParser.exe -f "{source}" --csv .'
        elif "RECENT" in atype or "DOCS" in atype: return f'LECmd.exe -f "{source}" --csv .'
        elif "MFT" in atype: return f'MFTCmd.exe -f "{source}" --csv .'
        elif "REGISTRY" in atype: return f'RECmd.exe -f "{source}" --csv .'
        return "Manual Verify"

    def weave_intent(self):
        print("[*] Weaving Intent & Generating Verification Traces...")
        self.df_timeline = self.df_timeline.with_columns([
            pl.struct(["Artifact_Type", "Source_File", "Timestamp_UTC", "Action"])
            .map_elements(self._generate_evid, return_dtype=pl.Utf8)
            .alias("Evidence_ID"),
            
            pl.struct(["Artifact_Type", "Source_File", "Target_Path"])
            .map_elements(lambda x: self._generate_verify_cmd(x.get("Artifact_Type"), x.get("Source_File"), x.get("Target_Path")), return_dtype=pl.Utf8)
            .alias("Verify_Cmd")
        ])

    def generate_grimoire(self, output_path, max_rows=100):
        print(f"[*] Writing the Grimoire to: {output_path}")
        t = self.txt 
        
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                # Header
                f.write(f"# 🧵 {t['title']}\n\n")
                f.write(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Concept:** {t['concept']}\n\n")
                
                # 1. Summary
                f.write(f"## {t['h1_summary']}\n\n")
                headers = t['h1_cols']
                f.write(f"| {headers[0]} | {headers[1]} | {headers[2]} |\n")
                f.write("|---|---|---|\n")
                
                # AION
                aion_count = len(self.df_aion) if self.df_aion is not None else 0
                aion_st = t['status_crit'] if aion_count > 0 else t['status_clean']
                f.write(f"| **AION** | {aion_st} | **{aion_count}** items |\n")
                
                # Pandora
                ghost_count = len(self.df_pandora) if self.df_pandora is not None else 0
                pan_st = t['status_crit'] if ghost_count > 0 else t['status_clean']
                f.write(f"| **Pandora** | {pan_st} | **{ghost_count}** items |\n")

                # Plutos
                exfil_count = len(self.df_plutos) if self.df_plutos is not None else 0
                plu_st = t['status_crit'] if exfil_count > 0 else t['status_clean']
                f.write(f"| **Plutos** | {plu_st} | **{exfil_count}** items |\n")

                # Chronos (New!)
                chronos_count = len(self.df_chronos) if self.df_chronos is not None else 0
                chronos_st = t['status_crit'] if chronos_count > 0 else t['status_clean']
                f.write(f"| **Chronos** | {chronos_st} | **{chronos_count}** items |\n")

                # Sphinx
                sphinx_count = len(self.df_sphinx) if self.df_sphinx is not None else 0
                sphinx_st = t['status_crit'] if sphinx_count > 0 else t['status_clean']
                f.write(f"| **Sphinx** | {sphinx_st} | **{sphinx_count}** items |\n")
                f.write("\n")

                # 2. Threats
                f.write(f"## {t['h2_threats']}\n")
                f.write(f"> {t['desc_threats']}\n\n")
                
                if exfil_count > 0:
                    f.write(f"### {t['h3_exfil']}\n")
                    f.write(f"| Time | File | {t['col_verdict']} | {t['col_drive']} |\n")
                    f.write("|---|---|---|---|\n")
                    for row in self.df_plutos.head(5).iter_rows(named=True):
                        f.write(f"| {row.get('SourceModified','')} | **{row.get('Target_FileName','')}** | {row.get('Plutos_Verdict','')} | {row.get('LocalPath','')} |\n")
                    f.write("\n")

                if chronos_count > 0:
                    f.write(f"### {t['h3_time']}\n")
                    f.write(f"| File Name | {t['col_variance']} | $SI (Standard Info) |\n")
                    f.write("|---|---|---|\n")
                    for row in self.df_chronos.head(5).iter_rows(named=True):
                        # Adapting to Chronos CSV structure
                        fname = row.get('FileName', 'Unknown')
                        var = row.get('Variance_ns', 'N/A')
                        si_time = row.get('SI_CreationTime', 'N/A')
                        f.write(f"| **{fname}** | {var} | {si_time} |\n")
                    f.write("\n")

                if aion_count > 0:
                    f.write(f"### {t['h3_persist']}\n")
                    f.write(f"| Score | File | {t['col_tags']} |\n")
                    f.write("|---|---|---|\n")
                    for row in self.df_aion.sort("AION_Score", descending=True).head(5).iter_rows(named=True):
                        f.write(f"| **{row.get('AION_Score')}** | {row.get('Target_FileName')} | {row.get('AION_Tags')} |\n")
                    f.write("\n")

                if ghost_count > 0:
                    f.write(f"### {t['h3_ghost']}\n")
                    f.write(f"| Risk | Ghost File | {t['col_path']} |\n")
                    f.write("|---|---|---|\n")
                    for row in self.df_pandora.filter(pl.col("Risk_Tag") != "").head(5).iter_rows(named=True):
                        f.write(f"| **{row.get('Risk_Tag')}** | {row.get('Ghost_FileName')} | `{row.get('ParentPath')}` |\n")
                    f.write("\n")

                if sphinx_count > 0:
                    f.write(f"### {t['h3_sphinx']}\n")
                    f.write(f"| Score | {t['col_hint']} | {t['col_tags']} |\n")
                    f.write("|---|---|---|\n")
                    for row in self.df_sphinx.sort("Sphinx_Score", descending=True).head(5).iter_rows(named=True):
                        hint = row.get('Decoded_Hint', 'N/A')
                        if len(hint) > 50: hint = hint[:50] + "..."
                        f.write(f"| **{row.get('Sphinx_Score')}** | `{hint}` | {row.get('Sphinx_Tags')} |\n")
                    f.write("\n")
                
                f.write("---\n\n")

                # 3. Timeline
                f.write(f"## {t['h3_timeline']}\n")
                f.write(f"> {t['desc_timeline'].format(max_rows)}\n\n")
                f.write(f"| EVID | Time (Local) | Type | Action | Tag | {t['col_cmd']} |\n")
                f.write("|---|---|---|---|---|---|\n")
                
                target_df = self.df_timeline.filter(pl.col("Tag").is_not_null())
                total_tagged = len(target_df)
                
                if total_tagged == 0:
                    target_df = self.df_timeline.tail(max_rows)
                else:
                    target_df = target_df.head(max_rows)
                
                for row in target_df.iter_rows(named=True):
                    evid = row.get('Evidence_ID', '')
                    ts = row.get('Timestamp_Local', '')
                    atype = row.get('Artifact_Type', '')
                    action = str(row.get('Action', ''))[:50].replace("|", " ")
                    tag = f"**{row.get('Tag')}**" if row.get('Tag') else ""
                    cmd = str(row.get('Verify_Cmd', ''))
                    if len(cmd) > 20: cmd = "`Cmd`"
                    else: cmd = f"`{cmd}`"

                    f.write(f"| **{evid}** | {ts} | {atype} | {action} | {tag} | {cmd} |\n")

                if total_tagged > max_rows:
                    f.write(f"\n> **{t['more_events'].format(total_tagged - max_rows)}**\n")

            print(f"[+] Grimoire sealed successfully ({self.lang.upper()} Mode).")
            
        except Exception as e:
            print(f"[!] Failed to write report: {e}")

def main():
    print_logo()
    parser = argparse.ArgumentParser(description="SH_HekateWeaver v2.4")
    parser.add_argument("-i", "--input", required=True, help="Input ChaosGrasp Timeline CSV")
    parser.add_argument("-o", "--out", default="Hekate_Grimoire.md", help="Output Markdown Report")
    
    parser.add_argument("--aion", help="Input AION Persistence CSV")
    parser.add_argument("--pandora", help="Input Pandora Ghost CSV")
    parser.add_argument("--plutos", help="Input Plutos Exfiltration CSV")
    parser.add_argument("--sphinx", help="Input Sphinx Decoded CSV")
    parser.add_argument("--chronos", help="Input Chronos Time Verification CSV") # Added!
    
    # Language Toggle
    parser.add_argument("--lang", choices=["en", "jp"], default="en", help="Report Language (en/jp)")
    
    args = parser.parse_args()
    
    if not Path(args.input).exists():
        print(f"[!] Input timeline not found: {args.input}")
        sys.exit(1)

    weaver = HekateWeaver(args.input, args.aion, args.pandora, args.plutos, args.sphinx, args.chronos, args.lang)
    weaver.load_all()
    weaver.weave_intent()
    weaver.generate_grimoire(args.out, max_rows=100)

if __name__ == "__main__":
    main()
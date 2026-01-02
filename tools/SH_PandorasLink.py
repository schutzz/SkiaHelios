import polars as pl
import argparse
import sys
import os
from pathlib import Path
from datetime import datetime
from tools.SH_ThemisLoader import ThemisLoader

# ==========================================
#  SH_PandorasLink v17.7 [Strict Filter]
#  Mission: "Kill the Noise, Save the Signal."
#  Update: Added 'Safe Extension' logic to block high-score noise.
# ==========================================

def print_logo():
    logo = r"""
      .       +    .    * .      .
    .    _    .    ______    .    _    .
       _/ \_   _  / ____ \  _   _/ \_
      /     \ / \/ /    \ \/ \ /     \
     /_     _\   | |    | |   /_     _\
       \   / \_  \ \____/ /   _/ \   /
    * \_/    \__\______/__/    \_/   *
      .     * /______\     .     .
    
      [ SH_PandorasLink v17.7 ]
     "Threats shall pass through the Noise."
    """
    print(logo)

class PandoraEngine:
    def __init__(self, mft_live, usn, mft_vss=None):
        self.mft_live_path = mft_live
        self.usn_path = usn
        self.mft_vss_path = mft_vss
        self.loader = ThemisLoader([
            "rules/triage_rules.yaml",
            "rules/sigma_file_event.yaml"
        ])
        
        print(f"[*] Initializing Engine with Themis Rules...")
        self.lf_live = self._load_mft(mft_live).lazy()
        self.lf_usn = self._load_usn(usn).lazy()
        self.lf_vss = self._load_mft(mft_vss).lazy() if mft_vss else None

    # ... (ローダーメソッド群は変更なし。v17.6のものを維持) ...
    def _get_col_expr(self, cols, targets, alias=None):
        for t in targets:
            if t in cols:
                expr = pl.col(t)
                if alias: expr = expr.alias(alias)
                return expr
        return None

    def _robust_date_parse(self, col_expr):
        return pl.coalesce([
            col_expr.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
            col_expr.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
            col_expr.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
            col_expr.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False)
        ])

    def _load_mft(self, path):
        try:
            try: lf_schema = pl.scan_csv(path, ignore_errors=True, infer_schema_length=0)
            except: lf_schema = pl.scan_csv(path, encoding='utf-8-sig', ignore_errors=True, infer_schema_length=0)
            cols = lf_schema.collect_schema().names()
            exprs = []
            e_num = self._get_col_expr(cols, ["EntryNumber", "MftRecordNumber"])
            if e_num is not None: exprs.append(e_num.cast(pl.Int64))
            seq_num = self._get_col_expr(cols, ["FileSequenceNumber", "SequenceNumber"], "FileSequenceNumber")
            if seq_num is not None: exprs.append(seq_num.cast(pl.Int64))
            in_use = self._get_col_expr(cols, ["InUse", "IsAllocated"], "Live_InUse")
            if in_use is not None: exprs.append(in_use)
            fname = self._get_col_expr(cols, ["FileName", "Name"], "Live_FileName")
            if fname is not None: exprs.append(fname)
            ppath = self._get_col_expr(cols, ["ParentPath", "ParentFolder"], "Live_ParentPath")
            if ppath is not None: exprs.append(ppath)
            created = self._get_col_expr(cols, ["StandardInformation_Created", "Created0x10", "SI_Created"], "StandardInformation_Created")
            if created is not None: exprs.append(created)
            fsize = self._get_col_expr(cols, ["FileSize", "Size"], "Live_FileSize")
            if fsize is not None: exprs.append(fsize.cast(pl.Int64))
            return lf_schema.select(exprs)
        except Exception as e:
            print(f"[!] Error loading MFT {path}: {e}")
            raise RuntimeError(f"Failed to load MFT")

    def _load_usn(self, path):
        try:
            lf_schema = pl.scan_csv(path, ignore_errors=True, infer_schema_length=0)
            cols = lf_schema.collect_schema().names()
            exprs = []
            e_num = self._get_col_expr(cols, ["EntryNumber", "MftRecordNumber"])
            if e_num is not None: exprs.append(e_num.cast(pl.Int64))
            seq_num = self._get_col_expr(cols, ["FileSequenceNumber", "SequenceNumber"], "FileSequenceNumber")
            if seq_num is not None: exprs.append(seq_num.cast(pl.Int64))
            p_enum = self._get_col_expr(cols, ["ParentEntryNumber", "ParentFileReferenceNumber", "ParentFrn"], "ParentEntryNumber")
            if p_enum is not None: exprs.append(p_enum.cast(pl.Int64))
            reason = self._get_col_expr(cols, ["UpdateReasons", "UpdateReason", "Reasons"], "UpdateReason")
            if reason is not None: exprs.append(reason)
            ts = self._get_col_expr(cols, ["UpdateTimestamp", "TimeStamp", "Timestamp"], "TimeStamp")
            if ts is not None: exprs.append(ts)
            fname = self._get_col_expr(cols, ["FileName", "Name", "Filename"], "FileName")
            if fname is not None: exprs.append(fname)
            ppath = self._get_col_expr(cols, ["ParentPath", "ParentFolder"])
            if ppath is not None: exprs.append(ppath)
            return lf_schema.select(exprs)
        except Exception as e:
            print(f"[!] Error loading USN {path}: {e}")
            raise RuntimeError(f"Failed to load USN")

    def run_gap_analysis(self, start_date, end_date):
        print("[*] Phase 1: Running Physical Gap Analysis...")
        try:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d")
            end_dt = datetime.strptime(end_date, "%Y-%m-%d")
        except:
            print("[!] Date format error. Use YYYY-MM-DD.")
            return None

        ghosts_list = []
        # --- Mode A: VSS (省略なし) ---
        if self.lf_vss is not None:
            print("    -> Mode A: VSS Differential Scan")
            try:
                q_vss = self.lf_vss.rename({
                    "Live_FileName": "Ghost_FileName", 
                    "FileSequenceNumber": "VSS_SeqNum",
                    "StandardInformation_Created": "Ghost_Time_Hint",
                    "Live_ParentPath": "ParentPath"
                })
                ghost_vss = q_vss.join(
                    self.lf_live, left_on=["EntryNumber", "VSS_SeqNum"], right_on=["EntryNumber", "FileSequenceNumber"], how="anti"
                ).select(["EntryNumber", "Ghost_FileName", "ParentPath", "Ghost_Time_Hint"]).with_columns(pl.lit("VSS_Gap").alias("Source"))
                ghosts_list.append(ghost_vss)
            except Exception as e: print(f"[!] VSS Analysis Skipped: {e}")

        # --- Mode B: USN (省略なし) ---
        print("    -> Mode B: USN Delete Transaction Scan")
        usn_with_date = self.lf_usn.with_columns(self._robust_date_parse(pl.col("TimeStamp")).alias("Parsed_Date"))
        q_usn_del = usn_with_date.filter((pl.col("Parsed_Date").is_between(start_dt, end_dt)) & (pl.col("UpdateReason").str.contains("FileDelete")))
        ghost_usn = q_usn_del.join(self.lf_live, on="EntryNumber", how="left", suffix="_Live").filter(
            (pl.col("FileSequenceNumber") != pl.col("FileSequenceNumber_Live")) | (pl.col("Live_InUse") == False) | (pl.col("FileSequenceNumber_Live").is_null())
        )
        if "ParentEntryNumber" in ghost_usn.collect_schema().names():
            parent_lookup = self.lf_live.select([pl.col("EntryNumber").alias("P_Entry"), pl.col("Live_ParentPath").alias("GrandParentPath"), pl.col("Live_FileName").alias("ParentName")])
            ghost_usn = ghost_usn.join(parent_lookup, left_on="ParentEntryNumber", right_on="P_Entry", how="left")
            reconstructed_path = pl.concat_str([pl.col("GrandParentPath"), pl.lit("\\"), pl.col("ParentName")])
            ghost_usn = ghost_usn.with_columns(pl.col("ParentPath").fill_null(reconstructed_path).alias("ParentPath"))

        ghost_usn = ghost_usn.select(["EntryNumber", "FileName", "ParentPath", "Parsed_Date"]).rename({"FileName": "Ghost_FileName", "Parsed_Date": "Ghost_Time_Hint"}).with_columns(pl.lit("USN_Trace").alias("Source"))
        ghosts_list.append(ghost_usn)

        if not ghosts_list: return None
        combined_ghosts = pl.concat(ghosts_list).unique(subset=["EntryNumber", "Ghost_FileName"])
        
        # ⚖️ Themis Integration
        print("    -> Applying Themis Threat Scoring (YAML)...")
        combined_ghosts = combined_ghosts.with_columns(pl.col("Ghost_FileName").alias("FileName"))
        scored_ghosts = self.loader.apply_threat_scoring(combined_ghosts)
        
        print("    -> Applying Themis Noise Filters (Golden Rule: Threat > Noise)...")
        available_cols = scored_ghosts.collect_schema().names()
        noise_expr = self.loader.get_noise_filter_expr(available_cols)
        
        # [NEW] 安全な拡張子の定義 (Web素材などは場所ベース検知でも許容する)
        # ※ "WebShell" などの名前ベース検知はこれに関係なくタグが付くのでOK
        safe_ext_expr = pl.col("Ghost_FileName").str.to_lowercase().str.contains(r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map)$")
        
        # [Logic Upgrade]
        # 残す条件:
        # 1. ノイズルールにヒットしない (基本)
        # OR
        # 2. 脅威スコアが高く(80以上)、かつ安全な拡張子ではない (特例許可)
        
        final_ghosts = scored_ghosts.filter(
            (~noise_expr) | 
            ((pl.col("Threat_Score") >= 80) & (~safe_ext_expr))
        )
        
        return final_ghosts

    def run_anti_forensics(self, limit=50):
        # ... (変更なし) ...
        print(f"[*] Phase 2: Analyzing Anti-Forensics Anomalies (Top {limit})...")
        cols = self.lf_live.collect_schema().names()
        if "Live_ParentPath" not in cols: return pl.LazyFrame([])
        stats = self.lf_live.group_by("Live_ParentPath").agg([
            pl.col("FileSequenceNumber").mean().alias("Dir_Mean_Seq"),
            pl.col("EntryNumber").count().alias("File_Count")
        ]).rename({"Live_ParentPath": "ParentPath"})
        return stats.sort("Dir_Mean_Seq", descending=True).limit(limit)

    def run_necromancer(self, lf_ghosts, pf_csv=None, shim_csv=None, chaos_csv=None):
        # ... (変更なし) ...
        if lf_ghosts is None: return None
        print("[*] Phase 3: Engaging Necromancer (Intent Analysis)...")
        lf_enriched = lf_ghosts.with_columns(pl.col("Ghost_FileName").str.to_lowercase().alias("join_key"))
        lf_enriched = lf_enriched.with_columns([pl.lit(None).cast(pl.Utf8).alias("Last_Executed_Time"), pl.lit(None).cast(pl.Utf8).alias("Chaos_FileName")])
        if chaos_csv and os.path.exists(chaos_csv):
            try:
                q_chaos = pl.scan_csv(chaos_csv, ignore_errors=True)
                cols = q_chaos.collect_schema().names()
                target_col = "File_Name" if "File_Name" in cols else "Target_FileName" if "Target_FileName" in cols else None
                if target_col:
                    q_chaos = q_chaos.select(["Time_Type", "User", "Action", target_col, "Timestamp_UTC"]).rename({target_col: "Chaos_FileName_Join", "Timestamp_UTC": "Last_Executed_Time_Join"})
                    lf_enriched = lf_enriched.join(q_chaos, left_on="join_key", right_on=pl.col("Chaos_FileName_Join").str.to_lowercase(), how="left")
                    lf_enriched = lf_enriched.with_columns([pl.coalesce(["Last_Executed_Time_Join", "Last_Executed_Time"]).alias("Last_Executed_Time"), pl.coalesce(["Chaos_FileName_Join", "Chaos_FileName"]).alias("Chaos_FileName")])
            except: pass
        return lf_enriched

def auto_detect_ntfs(target_dir):
    target = Path(target_dir)
    found = {"mft": None, "usn": None}
    mft_candidates = list(target.rglob("*$MFT_Output.csv")) or list(target.rglob("*MFT.csv"))
    if mft_candidates: found["mft"] = mft_candidates[0]
    usn_candidates = list(target.rglob("*$J_Output.csv")) or list(target.rglob("*UsnJrnl.csv"))
    if usn_candidates: found["usn"] = usn_candidates[0]
    return found

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser(description="SH_PandorasLink v17.7")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--dir", help="Auto-detect CSVs")
    group.add_argument("--manual", action="store_true")
    parser.add_argument("--mft"); parser.add_argument("--usn"); parser.add_argument("--vss")
    parser.add_argument("--start", required=True); parser.add_argument("--end", required=True)
    parser.add_argument("--chaos"); parser.add_argument("--pf"); parser.add_argument("--shim")
    parser.add_argument("--out", default="pandora_result_v17.7.csv")
    args = parser.parse_args(argv)

    mft_path = args.mft
    usn_path = args.usn
    if args.dir:
        detected = auto_detect_ntfs(args.dir)
        if not mft_path: mft_path = detected["mft"]
        if not usn_path: usn_path = detected["usn"]
    
    if not mft_path or not usn_path: return

    try:
        engine = PandoraEngine(str(mft_path), str(usn_path), args.vss)
        lf_ghosts = engine.run_gap_analysis(args.start, args.end)
        
        if lf_ghosts is not None:
            lf_af = engine.run_anti_forensics(limit=50)
            lf_final = engine.run_necromancer(lf_ghosts, args.pf, args.shim, args.chaos)
            
            print("[*] Phase 4: Calculating Risk Tags...")
            lf_final = lf_final.join(lf_af.select(["ParentPath", "Dir_Mean_Seq"]), on="ParentPath", how="left")
            
            lf_final = lf_final.with_columns(
                pl.when(pl.col("Last_Executed_Time").is_not_null()).then(pl.lit("EXEC")).otherwise(pl.lit("")).alias("Tag_Exec"),
                pl.when(pl.col("Dir_Mean_Seq").is_not_null()).then(pl.lit("ANOMALY")).otherwise(pl.lit("")).alias("Tag_Af"),
                pl.when(pl.col("Ghost_FileName").str.to_lowercase().str.contains(r"\.(exe|dll|ps1|bat|vbs|sh|js|iso|vmdk)$")).then(pl.lit("RISK_EXT")).otherwise(pl.lit("")).alias("Tag_Ext")
            ).with_columns(
                pl.concat_str([pl.col("Tag_Exec"), pl.col("Tag_Af"), pl.col("Tag_Ext")], separator="_").str.strip_chars("_").alias("Risk_Tag")
            )
            
            # Prefix Logic
            lf_final = lf_final.with_columns([
                pl.when(pl.col("Threat_Score") > 0).then(
                    pl.concat_str([pl.lit("[CRITICAL_"), pl.col("Threat_Tag"), pl.lit("] ")], separator="")
                ).otherwise(pl.lit("")).alias("Tag_Prefix")
            ]).with_columns(pl.concat_str([pl.col("Tag_Prefix"), pl.col("Ghost_FileName")]).alias("Ghost_FileName"))
            
            # Select & Sort
            cols = lf_final.collect_schema().names()
            p_cols = ["Risk_Tag", "Ghost_FileName", "ParentPath", "Source", "Last_Executed_Time", "Threat_Score"]
            r_cols = [c for c in cols if c not in p_cols and not c.startswith("Tag_") and c != "join_key"]
            lf_final = lf_final.select(p_cols + r_cols).sort("Threat_Score", descending=True)

            print(f"[*] Materializing results...")
            df_result = lf_final.collect()
            engine.loader.suggest_new_noise_rules(df_result)

            if df_result.height > 0:
                df_result.write_csv(args.out)
                print(f"[+] GHOSTS: {df_result.height} records.")
                print(df_result.select(["Risk_Tag", "Ghost_FileName", "ParentPath"]).head(5))
            else:
                print("[-] No ghosts found (All noise filtered).")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
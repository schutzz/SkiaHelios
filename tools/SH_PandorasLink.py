import polars as pl
import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

# ==========================================
#  SH_PandorasLink v3.8 [The Missing Link]
#  Mission: Detect "Deletion", "Concealment" & "LNK Destruction"
# ==========================================

def print_logo():
    logo = r"""
      .        +    .    * .      .
    .    _    .    ______    .    _    .
       _/ \_   _  / ____ \  _   _/ \_
      /     \ / \/ /    \ \/ \ /     \
     /_     _\   | |    | |   /_     _\
       \   / \_  \ \____/ /  _/ \   /
    * \_/    \__\______/__/    \_/   *
      .     * /______\     .     .
    
      [ SH_PandorasLink v3.8 ]
     "Shadows are lifted. The Link is found."
    """
    print(logo)

class PandoraEngine:
    def __init__(self, mft_live, usn, mft_vss=None):
        self.mft_live_path = mft_live
        self.usn_path = usn
        self.mft_vss_path = mft_vss
        
        print(f"[*] Initializing Engine...")
        self.lf_live = self._load_mft(mft_live).lazy()
        self.lf_usn = self._load_usn(usn).lazy()
        self.lf_vss = self._load_mft(mft_vss).lazy() if mft_vss else None

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
            try:
                lf_schema = pl.scan_csv(path, ignore_errors=True, infer_schema_length=0)
            except:
                lf_schema = pl.scan_csv(path, encoding='utf-8-sig', ignore_errors=True, infer_schema_length=0)
                
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
            raise RuntimeError(f"Failed to load MFT: {path}")

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
            raise RuntimeError(f"Failed to load USN: {path}")

    def _apply_noise_reduction(self, lf_ghosts):
        """
        [v3.8 Update] Intelligent Noise Reduction
        Splunk, Browser Cache, Windows Update等を安全に除外
        """
        print("    -> Applying Intelligent Noise Reduction (Level 2)...")
        
        # 1. Splunk Noise (tsidx, lock, etc.)
        splunk_path_sig = r"splunk[\\/]var[\\/]lib[\\/]splunk"
        splunk_ext_sig = r"\.(tsidx|manifest|lock|dat|rawsize|interim|xml|bucket)$"
        
        is_splunk = (
            pl.col("ParentPath").str.to_lowercase().str.contains(splunk_path_sig) &
            (
                pl.col("Ghost_FileName").str.to_lowercase().str.contains(splunk_ext_sig) |
                pl.col("Ghost_FileName").str.ends_with(".lock")
            )
        )

        # 2. Browser Cache (Chrome/Edge/Firefox)
        # キャッシュ内のリソースファイルのみを除外。実行可能ファイルは除外しない。
        browser_cache_sig = r"(google[\\/]chrome|microsoft[\\/]edge|mozilla[\\/]firefox).*(cache|code cache|service worker)"
        safe_ext_sig = r"\.(js|css|png|jpg|jpeg|gif|ico|woff|woff2|svg|html|htm|txt|json|tmp)$"
        
        is_browser_garbage = (
            pl.col("ParentPath").str.to_lowercase().str.contains(browser_cache_sig) &
            pl.col("Ghost_FileName").str.to_lowercase().str.contains(safe_ext_sig)
        )

        # 3. Windows System Noise (Update, CBS, Defender)
        # ログや一時ファイルのみを除外。
        sys_noise_sig = r"windows[\\/](logs[\\/]cbs|softwaredistribution|servicing|temp)"
        sys_ext_sig = r"\.(log|cab|etl|tlb|xml|dat)$"

        is_sys_noise = (
            pl.col("ParentPath").str.to_lowercase().str.contains(sys_noise_sig) &
            pl.col("Ghost_FileName").str.to_lowercase().str.contains(sys_ext_sig)
        )

        # 4. Temp Folder Handling
        # Tempフォルダ内の .tmp/.log は除外するが、.exe/.ps1/.bat 等は残す。
        temp_path_sig = r"appdata[\\/]local[\\/]temp"
        safe_temp_ext = r"(\.tmp|\.log)$"

        is_safe_temp = (
            pl.col("ParentPath").str.to_lowercase().str.contains(temp_path_sig) &
            pl.col("Ghost_FileName").str.to_lowercase().str.contains(safe_temp_ext)
        )

        # フィルタ適用: いずれのノイズ条件にも合致しないものを残す
        return lf_ghosts.filter(
            ~(is_splunk | is_browser_garbage | is_sys_noise | is_safe_temp)
        )

    def run_gap_analysis(self, start_date, end_date):
        print("[*] Phase 1: Running Physical Gap Analysis...")
        try:
            start_dt = datetime.fromisoformat(start_date)
            end_dt = datetime.fromisoformat(end_date)
        except ValueError:
            print("[!] Date format error. Use YYYY-MM-DD.")
            raise ValueError("Invalid date format.")

        ghosts_list = []

        # --- Mode A: VSS ---
        if self.lf_vss is not None:
            print("    -> Mode A: VSS Differential Scan (Time Machine)")
            try:
                q_vss = self.lf_vss.rename({
                    "Live_FileName": "Ghost_FileName", 
                    "FileSequenceNumber": "VSS_SeqNum",
                    "StandardInformation_Created": "Ghost_Time_Hint",
                    "Live_ParentPath": "ParentPath"
                })
                
                ghost_vss = q_vss.join(
                    self.lf_live,
                    left_on=["EntryNumber", "VSS_SeqNum"],
                    right_on=["EntryNumber", "FileSequenceNumber"],
                    how="anti"
                ).select([
                    "EntryNumber", "Ghost_FileName", "ParentPath", "Ghost_Time_Hint"
                ]).with_columns(pl.lit("VSS_Gap").alias("Source"))
                
                ghosts_list.append(ghost_vss)
            except Exception as e:
                print(f"[!] VSS Analysis Skipped: {e}")

        # --- Mode B: USN ---
        print("    -> Mode B: USN Delete Transaction Scan")
        
        usn_with_date = self.lf_usn.with_columns(
            self._robust_date_parse(pl.col("TimeStamp")).alias("Parsed_Date")
        )
        
        q_usn_del = usn_with_date.filter(
            (pl.col("Parsed_Date").is_between(start_dt, end_dt)) &
            (pl.col("UpdateReason").str.contains("FileDelete"))
        )

        ghost_usn = q_usn_del.join(
            self.lf_live, on="EntryNumber", how="left", suffix="_Live"
        ).filter(
            (pl.col("FileSequenceNumber") != pl.col("FileSequenceNumber_Live")) | 
            (pl.col("Live_InUse") == False) |
            (pl.col("FileSequenceNumber_Live").is_null())
        )
        
        # Path Backfill
        if "ParentEntryNumber" in ghost_usn.collect_schema().names():
            parent_lookup = self.lf_live.select([
                pl.col("EntryNumber").alias("P_Entry"),
                pl.col("Live_ParentPath").alias("GrandParentPath"),
                pl.col("Live_FileName").alias("ParentName")
            ])
            
            ghost_usn = ghost_usn.join(
                parent_lookup,
                left_on="ParentEntryNumber",
                right_on="P_Entry",
                how="left"
            )
            
            reconstructed_path = pl.concat_str(
                [pl.col("GrandParentPath"), pl.lit("\\"), pl.col("ParentName")]
            )
            
            ghost_usn = ghost_usn.with_columns(
                pl.col("ParentPath").fill_null(reconstructed_path).alias("ParentPath")
            )

        ghost_usn = ghost_usn.select([
            "EntryNumber", "FileName", "ParentPath", "Parsed_Date"
        ]).rename({
            "FileName": "Ghost_FileName",
            "Parsed_Date": "Ghost_Time_Hint"
        }).with_columns(pl.lit("USN_Trace").alias("Source"))

        ghosts_list.append(ghost_usn)

        if not ghosts_list: return None
        
        combined_ghosts = pl.concat(ghosts_list).unique(subset=["EntryNumber", "Ghost_FileName"])
        
        # Apply Filter here
        return self._apply_noise_reduction(combined_ghosts)

    def run_anti_forensics(self, limit=50):
        print(f"[*] Phase 2: Analyzing Anti-Forensics Anomalies (Top {limit})...")
        
        cols = self.lf_live.collect_schema().names()
        if "Live_ParentPath" not in cols or "FileSequenceNumber" not in cols:
            print("[!] Skipping Anti-Forensics: Required columns missing.")
            return pl.LazyFrame([])

        stats = self.lf_live.group_by("Live_ParentPath").agg([
            pl.col("FileSequenceNumber").mean().alias("Dir_Mean_Seq"),
            pl.col("FileSequenceNumber").std().fill_null(0).alias("Dir_Std_Seq"),
            pl.col("EntryNumber").count().alias("File_Count")
        ]).rename({"Live_ParentPath": "ParentPath"})

        return stats.sort("Dir_Mean_Seq", descending=True).limit(limit)

    def run_necromancer(self, lf_ghosts, pf_csv=None, shim_csv=None, chaos_csv=None):
        if lf_ghosts is None: return None
        print("[*] Phase 3: Engaging Necromancer (Intent Analysis)...")

        lf_enriched = lf_ghosts.with_columns(
            pl.col("Ghost_FileName").str.to_lowercase().alias("join_key")
        )

        lf_enriched = lf_enriched.with_columns([
            pl.lit(None).cast(pl.Utf8).alias("Last_Executed_Time"),
            pl.lit(None).cast(pl.Utf8).alias("Chaos_FileName")
        ])

        if chaos_csv and os.path.exists(chaos_csv):
            print(f"    -> Querying Chaos Timeline: {chaos_csv}")
            try:
                q_chaos = pl.scan_csv(chaos_csv, ignore_errors=True)
                cols = q_chaos.collect_schema().names()
                
                target_col = None
                if "File_Name" in cols:
                    target_col = "File_Name"
                elif "Target_FileName" in cols:
                    target_col = "Target_FileName"
                
                if target_col:
                    q_chaos = q_chaos.select([
                        "Time_Type", "User", "Action", target_col, "Artifact_Type", "Timestamp_UTC"
                    ]).rename({
                        target_col: "Chaos_FileName_Join",
                        "Timestamp_UTC": "Last_Executed_Time_Join"
                    })
                    
                    lf_enriched = lf_enriched.join(
                        q_chaos,
                        left_on="join_key",
                        right_on=pl.col("Chaos_FileName_Join").str.to_lowercase(),
                        how="left"
                    ).with_columns([
                        pl.coalesce(["Last_Executed_Time_Join", "Last_Executed_Time"]).alias("Last_Executed_Time"),
                        pl.coalesce(["Chaos_FileName_Join", "Chaos_FileName"]).alias("Chaos_FileName")
                    ])
            except Exception as e:
                print(f"[!] Warning: Failed to join Chaos Timeline ({e}). Skipping.")
        
        return lf_enriched

def auto_detect_ntfs(target_dir):
    target = Path(target_dir)
    print(f"[*] Scanning directory for NTFS artifacts: {target}")
    found = {"mft": None, "usn": None}
    
    mft_candidates = list(target.rglob("*$MFT_Output.csv")) or list(target.rglob("*MFT.csv"))
    live_mft = next((p for p in mft_candidates if "VSS" not in p.name), None)
    if not live_mft and mft_candidates: live_mft = mft_candidates[0]
    if live_mft:
        found["mft"] = live_mft
        print(f"    [+] Detected Live MFT: {live_mft.name}")

    usn_candidates = list(target.rglob("*$J_Output.csv")) or list(target.rglob("*UsnJrnl.csv"))
    if usn_candidates:
        found["usn"] = usn_candidates[0]
        print(f"    [+] Detected USN Jrnl: {found['usn'].name}")
        
    return found

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser(description="SH_PandorasLink v3.8")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--dir", help="Auto-detect CSVs from KAPE Output Folder")
    group.add_argument("--manual", action="store_true", help="Manually specify CSV paths")

    parser.add_argument("--mft", help="Path to Live MFT CSV")
    parser.add_argument("--usn", help="Path to USN Journal CSV")
    parser.add_argument("--vss", help="Path to VSS MFT CSV (Optional)")

    parser.add_argument("--start", required=True, help="Start Date (YYYY-MM-DD)")
    parser.add_argument("--end", required=True, help="End Date (YYYY-MM-DD)")
    
    parser.add_argument("--chaos", help="ChaosGrasp Master Timeline CSV")
    parser.add_argument("--pf", help="Prefetch CSV (Legacy)")
    parser.add_argument("--shim", help="ShimCache CSV (Legacy)")
    
    parser.add_argument("--out", default="pandora_result_v3.8.csv")
    args = parser.parse_args(argv)

    mft_path = args.mft
    usn_path = args.usn
    
    if args.dir:
        detected = auto_detect_ntfs(args.dir)
        if not mft_path: mft_path = detected["mft"]
        if not usn_path: usn_path = detected["usn"]
    
    if not mft_path or not os.path.exists(str(mft_path)):
        print("[!] Error: MFT CSV not found.")
        return
    if not usn_path or not os.path.exists(str(usn_path)):
        print("[!] Error: USN CSV not found.")
        return

    try:
        engine = PandoraEngine(str(mft_path), str(usn_path), args.vss)

        # 1. Gap Analysis (with Noise Reduction)
        lf_ghosts = engine.run_gap_analysis(args.start, args.end)
        
        if lf_ghosts is not None:
            # 2. Anti-Forensics (Top 50)
            lf_af = engine.run_anti_forensics(limit=50)

            # 3. Necromancer
            lf_final = engine.run_necromancer(lf_ghosts, args.pf, args.shim, args.chaos)
            
            # --- 4. Risk Tagging (Refined for LNK/USB) ---
            print("[*] Phase 4: Calculating Risk Assessment Tags...")
            
            lf_final = lf_final.join(
                lf_af.select(["ParentPath", "Dir_Mean_Seq"]), 
                on="ParentPath", 
                how="left"
            )
            
            lf_final = lf_final.with_columns(
                pl.when(pl.col("Last_Executed_Time").is_not_null())
                .then(pl.lit("EXEC"))
                .otherwise(pl.lit(""))
                .alias("Tag_Exec"),
                
                pl.when(pl.col("Dir_Mean_Seq").is_not_null())
                .then(pl.lit("ANOMALY"))
                .otherwise(pl.lit(""))
                .alias("Tag_Af"),

                pl.when(pl.col("Ghost_FileName").str.to_lowercase().str.contains(r"\.(exe|dll|ps1|bat|vbs|sh|js|iso|vmdk)$"))
                .then(pl.lit("RISK_EXT"))
                .otherwise(pl.lit(""))
                .alias("Tag_Ext"),
                
                # [NEW] LNK Deletion Check (Indicates Evidence Destruction)
                # 場所を問わず、ショートカット（LNK）の削除は証拠隠滅の可能性が高い
                pl.when(
                    (pl.col("Ghost_FileName").str.to_lowercase().str.ends_with(".lnk"))
                )
                .then(pl.lit("LNK_DEL"))
                .otherwise(pl.lit(""))
                .alias("Tag_Lnk")
            ).with_columns(
                pl.concat_str([pl.col("Tag_Exec"), pl.col("Tag_Af"), pl.col("Tag_Ext"), pl.col("Tag_Lnk")], separator="_")
                .str.strip_chars("_")
                .alias("Risk_Tag")
            )
            
            cols = lf_final.collect_schema().names()
            priority_cols = ["Risk_Tag", "Ghost_FileName", "ParentPath", "Source", "Last_Executed_Time"]
            remaining_cols = [c for c in cols if c not in priority_cols and not c.startswith("Tag_") and c != "join_key"]
            
            lf_final = lf_final.select(priority_cols + remaining_cols)

            print(f"[*] Materializing results...")
            try:
                df_result = lf_final.collect()
                
                if df_result.height > 0:
                    df_result.write_csv(args.out)
                    print(f"\n[+] GHOSTS REVEALED: {df_result.height} records saved to {args.out}")
                    
                    high_risks = df_result.filter(pl.col("Risk_Tag") != "")
                    if high_risks.height > 0:
                        print(f"\n[!] {high_risks.height} High Risk Ghosts Detected!")
                        print(high_risks.select(["Risk_Tag", "Ghost_FileName", "ParentPath"]).head(10))
                    else:
                        print(f"[-] No high-risk anomalies found (Splunk/Browser noise filtered).")
                else:
                    print("[-] No ghosts found (All noise filtered).")
            except Exception as e:
                print(f"[!] Execution failed: {e}")
                import traceback
                traceback.print_exc()
        else:
            print("[-] No ghosts found.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    main()
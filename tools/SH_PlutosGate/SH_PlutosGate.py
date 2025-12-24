import polars as pl
import argparse
import sys
import os
import glob
import re

# ==========================================
#  SH_PlutosGate v1.3 [Linker Fix]
#  Mission: Exposing the escape routes of data.
#  Fix: Output filename consistency & C-Drive filter
# ==========================================

def print_logo():
    print(r"""
       ______   __       __  __   ______  ______   ______    
      /\  == \ /\ \     /\ \/\ \ /\__  _\/\  __ \ /\  ___\   
      \ \  _-/ \ \ \____\ \ \_\ \\/_/\ \/\ \ \/\ \\ \___  \  
       \ \_\    \ \_____\\ \_____\  \ \_\ \ \_____\\/\_____\ 
        \/_/     \/_____/ \/_____/   \/_/  \/_____/ \/_____/ 
      
          [ SH_PlutosGate v1.3 ]
       "Exposing the escape routes of data."
    """)

class PlutosEngine:
    def __init__(self, kape_dir, pandora_csv=None):
        self.kape_dir = kape_dir
        self.pandora_df = self._load_pandora(pandora_csv) if pandora_csv else None
        print(f"[*] Initializing Plutos Gate on: {kape_dir}")

    def _load_pandora(self, path):
        try:
            print(f"    -> Linking with Pandora Ghost List: {path}")
            try:
                df = pl.read_csv(path, ignore_errors=True)
            except:
                df = pl.read_csv(path, encoding='utf-8-sig', ignore_errors=True)

            if "Ghost_FileName" in df.columns:
                return df.select(
                    pl.col("Ghost_FileName").str.to_lowercase().alias("Target_FileName"), 
                    "Risk_Tag", 
                    pl.col("ParentPath").alias("Ghost_Path")
                ).unique()
            elif "Target_FileName" in df.columns:
                return df.select(["Target_FileName", "Risk_Tag", "Ghost_Path"]).unique()
            return None
        except Exception as e:
            print(f"[!] Pandora Link Error: {e}")
            return None

    def _find_csv(self, keyword):
        candidates = glob.glob(os.path.join(self.kape_dir, "**", f"*{keyword}*.csv"), recursive=True)
        if candidates:
            print(f"    -> Found {keyword} log: {os.path.basename(candidates[0])}")
            return candidates[0]
        return None

    def analyze_usb_exfiltration(self):
        print("[*] Phase 1: Analyzing USB Exfiltration...")
        lnk_file = self._find_csv("LECmd") or self._find_csv("Lnk")

        if not lnk_file:
            print("[!] Skipping USB Analysis: Missing LNK CSVs.")
            return None

        try:
            lf_lnk = pl.scan_csv(lnk_file, infer_schema_length=0, ignore_errors=True)
            cols = lf_lnk.collect_schema().names()
            path_col = next((c for c in cols if c in ['LocalPath', 'Path', 'Target']), 'LocalPath')
            dtype_col = next((c for c in cols if 'DriveType' in c), None)
            
            # Filter Logic: Not C: OR DriveType is Removable/Fixed(External)
            if dtype_col:
                lf_usb_access = lf_lnk.filter(
                    pl.col(dtype_col).cast(pl.Utf8).str.contains(r"(?i)Removable|Fixed|^2$") 
                )
            else:
                # Fallback: Path does not start with C:
                lf_usb_access = lf_lnk.filter(
                    ~pl.col(path_col).str.to_uppercase().str.starts_with("C:") & 
                    pl.col(path_col).str.contains(r"^[A-Z]:")
                )

            lf_usb_access = lf_usb_access.with_columns(
                pl.col(path_col).str.extract(r"\\([^\\]+)$", 1).str.to_lowercase().alias("Target_FileName")
            )

            df_usb = lf_usb_access.collect()
            
            if self.pandora_df is not None:
                df_usb = df_usb.join(self.pandora_df, on="Target_FileName", how="left")
                df_usb = df_usb.with_columns(
                    pl.when(pl.col("Risk_Tag").is_not_null())
                    .then(pl.lit("CONFIRMED_EXFILTRATION"))
                    .otherwise(pl.lit("POTENTIAL_EXFILTRATION"))
                    .alias("Plutos_Verdict")
                )
            else:
                df_usb = df_usb.with_columns(pl.lit("USB_ACCESS").alias("Plutos_Verdict"))
                df_usb = df_usb.with_columns(pl.lit(None).alias("Risk_Tag"))

            out_cols = ["SourceCreated", "SourceModified", path_col, "Target_FileName", "Plutos_Verdict", "Risk_Tag"]
            available = [c for c in out_cols if c in df_usb.columns]
            
            return df_usb.select(available).sort("SourceModified", descending=True)

        except Exception as e:
            print(f"[!] USB Analysis Failed: {e}")
            return None

    def analyze_network_traffic(self):
        print("[*] Phase 2: Profiling Network Traffic (SRUM)...")
        srum_file = self._find_csv("Srum") or self._find_csv("NetworkUsage")
        
        if not srum_file:
            print("[!] Skipping SRUM Analysis: Missing SrumECmd CSV.")
            return None

        try:
            lf_srum = pl.scan_csv(srum_file, infer_schema_length=0, ignore_errors=True)
            schema = lf_srum.collect_schema().names()
            app_col = next((c for c in schema if 'AppId' in c or 'Exe' in c), 'AppId')
            
            fg_write = next((c for c in schema if 'ForegroundBytesWritten' in c), None)
            bg_write = next((c for c in schema if 'BackgroundBytesWritten' in c), None)
            
            if not fg_write and not bg_write:
                return None
            else:
                exprs = []
                if fg_write: exprs.append(pl.col(fg_write).fill_null(0).cast(pl.Float64))
                if bg_write: exprs.append(pl.col(bg_write).fill_null(0).cast(pl.Float64))
                total_sent_expr = sum(exprs)

            lf_traffic = lf_srum.group_by(app_col).agg([
                total_sent_expr.sum().alias("Total_Sent_MB") / (1024*1024),
                pl.col(app_col).count().alias("Connection_Count")
            ])
            
            lf_heavy = lf_traffic.filter(pl.col("Total_Sent_MB") > 10.0).sort("Total_Sent_MB", descending=True)
            return lf_heavy.collect()

        except Exception as e:
            print(f"[!] SRUM Analysis Failed: {e}")
            return None

def main():
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, help="KAPE Output Directory")
    parser.add_argument("--pandora", help="Path to Pandora Ghost List CSV")
    parser.add_argument("-o", "--out", default="plutos_report.csv")
    args = parser.parse_args()

    engine = PlutosEngine(args.dir, args.pandora)

    # 1. USB Analysis
    df_usb = engine.analyze_usb_exfiltration()
    if df_usb is not None and df_usb.height > 0:
        print(f"\n[!] USB EXFILTRATION ARTIFACTS FOUND: {df_usb.height}")
        try: print(df_usb.head(5))
        except: pass
        # [Fix] Use the output path from arguments!
        df_usb.write_csv(args.out)
        print(f"[*] Saved Exfil Report to: {args.out}")
    else:
        print("[-] No specific USB exfiltration artifacts correlated.")

    # 2. Network Analysis
    df_net = engine.analyze_network_traffic()
    if df_net is not None and df_net.height > 0:
        print(f"\n[!] HIGH VOLUME TRAFFIC DETECTED (Top 5):")
        try: print(df_net.head(5))
        except: pass
        # Network report is separate
        base_name = os.path.splitext(args.out)[0]
        net_out = f"{base_name}_Network.csv"
        df_net.write_csv(net_out)

    print("\n[*] Analysis Complete. 'Ex Umbra in Solem'.")

if __name__ == "__main__":
    main()
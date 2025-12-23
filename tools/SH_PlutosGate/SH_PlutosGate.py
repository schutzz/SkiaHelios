import polars as pl
import argparse
import sys
import os
import glob
import re

# ==========================================
# SH_PlutosGate v1.0 (The Exit)
# ==========================================

def print_logo():
    print(r"""
      ______   __       __  __   ______  ______   ______    
     /\  == \ /\ \     /\ \/\ \ /\__  _\/\  __ \ /\  ___\   
     \ \  _-/ \ \ \____\ \ \_\ \\/_/\ \/\ \ \/\ \\ \___  \  
      \ \_\    \ \_____\\ \_____\  \ \_\ \ \_____\\/\_____\ 
       \/_/     \/_____/ \/_____/   \/_/  \/_____/ \/_____/ 
      
          [ 🚪 SH_PlutosGate v1.0 ]
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
            # Target_FileNameを小文字化してキーにする
            df = pl.read_csv(path, ignore_errors=True)
            if "Target_FileName" in df.columns:
                return df.select(["Target_FileName", "Risk_Tag", "Ghost_Path"]).unique()
            elif "FileName" in df.columns:
                 return df.select(pl.col("FileName").str.to_lowercase().alias("Target_FileName"), "Risk_Tag", pl.col("ParentPath").alias("Ghost_Path")).unique()
            return None
        except Exception as e:
            print(f"[!] Pandora Link Error: {e}")
            return None

    def _find_csv(self, keyword):
        """KAPEフォルダから指定キーワードを含むCSVを探す"""
        candidates = glob.glob(os.path.join(self.kape_dir, "**", f"*{keyword}*.csv"), recursive=True)
        if candidates:
            # 複数ある場合は最新を選ぶなどのロジックを入れたいが、一旦最初に見つかったものを採用
            print(f"    -> Found {keyword} log: {os.path.basename(candidates[0])}")
            return candidates[0]
        return None

    def analyze_usb_exfiltration(self):
        """
        [Logic 1] USB & LNK Correlation
        USB接続履歴(Registry) と ファイルアクセス履歴(LNK) を結合し、
        'Removable' ドライブでのアクセスを特定する。
        """
        print("[*] Phase 1: Analyzing USB Exfiltration...")
        
        # 1. Load Registry (System - USBSTOR)
        # KAPE output for RECmd usually contains "System" or "Registry"
        # 簡易的に "USBSTOR" を含むか、RECmdのSystem出力CSVを探す
        reg_file = self._find_csv("System") or self._find_csv("USBSTOR")
        
        # 2. Load LNK (LECmd)
        lnk_file = self._find_csv("LECmd") or self._find_csv("Lnk")

        if not reg_file or not lnk_file:
            print("[!] Skipping USB Analysis: Missing Registry or LNK CSVs.")
            return None

        try:
            # --- USB Registry Parsing ---
            # RECmdの出力スキーマに依存するが、USBSTORキーを探す
            lf_reg = pl.scan_csv(reg_file, infer_schema_length=0, ignore_errors=True)
            
            # USBデバイスのシリアルと初回/最終接続日時を抽出
            # (実装詳細: RECmdの構造は複雑なので、ここではLNK側のRemovable判定を主軸にする)
            
            # --- LNK Parsing ---
            lf_lnk = pl.scan_csv(lnk_file, infer_schema_length=0, ignore_errors=True)
            
            # Filter for Removable Drives (Drive Type = 2 or Removable keyword)
            # LECmd output usually has 'DriveType' column.
            cols = lf_lnk.collect_schema().names()
            
            # カラム名揺れ吸収
            path_col = next((c for c in cols if c in ['LocalPath', 'Path', 'Target']), 'LocalPath')
            dtype_col = next((c for c in cols if 'DriveType' in c), None)
            
            # リムーバブルメディアへのアクセスを抽出
            if dtype_col:
                lf_usb_access = lf_lnk.filter(
                    pl.col(dtype_col).cast(pl.Utf8).str.contains(r"(?i)Removable|Fixed") # USB HDDはFixedの場合もあるので注意
                )
            else:
                # ドライブタイプがない場合はパスで推測 (D:, E: etc. C以外)
                lf_usb_access = lf_lnk.filter(
                    ~pl.col(path_col).str.starts_with("C:") & 
                    pl.col(path_col).str.contains(r"^[A-Z]:")
                )

            # --- Correlation with Pandora (Ghost Linking) ---
            # 「USBで開かれたファイル」が「PC内からは削除されている(Ghost)」場合、持ち出しの可能性大
            
            lf_usb_access = lf_usb_access.with_columns(
                pl.col(path_col).str.extract(r"\\([^\\]+)$", 1).str.to_lowercase().alias("Target_FileName")
            )

            df_usb = lf_usb_access.collect()
            
            if self.pandora_df is not None:
                # Join with Pandora
                df_usb = df_usb.join(self.pandora_df, on="Target_FileName", how="left")
                
                # リスク判定: Pandoraで見つかった(=削除済み) かつ USBアクセスあり
                df_usb = df_usb.with_columns(
                    pl.when(pl.col("Risk_Tag").is_not_null())
                    .then(pl.lit("CONFIRMED_EXFILTRATION")) # 持ち出し確定
                    .otherwise(pl.lit("POTENTIAL_EXFILTRATION"))
                    .alias("Plutos_Verdict")
                )
            else:
                df_usb = df_usb.with_columns(pl.lit("USB_ACCESS").alias("Plutos_Verdict"))

            # Select useful columns
            out_cols = ["SourceCreated", "SourceModified", path_col, "Target_FileName", "Plutos_Verdict", "Risk_Tag"]
            available = [c for c in out_cols if c in df_usb.columns]
            
            return df_usb.select(available).sort("SourceModified", descending=True)

        except Exception as e:
            print(f"[!] USB Analysis Failed: {e}")
            return None

    def analyze_network_traffic(self):
        """
        [Logic 2] SRUM Traffic Profiling
        SRUDB (Network Usage) を解析し、大量送信プロセスを特定する。
        """
        print("[*] Phase 2: Profiling Network Traffic (SRUM)...")
        srum_file = self._find_csv("Srum") or self._find_csv("NetworkUsage")
        
        if not srum_file:
            print("[!] Skipping SRUM Analysis: Missing SrumECmd CSV.")
            return None

        try:
            lf_srum = pl.scan_csv(srum_file, infer_schema_length=0, ignore_errors=True)
            
            # SrumECmd output cols: AppId, BytesSent, BytesReceived, UserId...
            # Group by AppId (Process) and sum BytesSent
            
            # カラム名特定
            schema = lf_srum.collect_schema().names()
            app_col = next((c for c in schema if 'AppId' in c or 'Exe' in c), 'AppId')
            sent_col = next((c for c in schema if 'Sent' in c), 'BytesSent')
            
            # 集計
            lf_traffic = lf_srum.group_by(app_col).agg([
                pl.col(sent_col).cast(pl.Float64).sum().alias("Total_Sent_MB") / (1024*1024),
                pl.col(sent_col).count().alias("Connection_Count")
            ])
            
            # フィルタ: 10MB以上送信しているプロセス
            lf_heavy = lf_traffic.filter(pl.col("Total_Sent_MB") > 10.0).sort("Total_Sent_MB", descending=True)
            
            return lf_heavy.collect()

        except Exception as e:
            print(f"[!] SRUM Analysis Failed: {e}")
            return None

def main():
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, help="KAPE Output Directory (Recursively searches for LNK, Registry, SRUM)")
    parser.add_argument("--pandora", help="Path to Pandora Ghost List CSV (Optional)")
    parser.add_argument("-o", "--out", default="plutos_report.csv")
    args = parser.parse_args()

    engine = PlutosEngine(args.dir, args.pandora)

    # 1. USB Exfiltration Analysis
    df_usb = engine.analyze_usb_exfiltration()
    if df_usb is not None and df_usb.height > 0:
        print(f"\n[!] USB EXFILTRATION ARTIFACTS FOUND: {df_usb.height}")
        print("-" * 60)
        print(df_usb.head(5))
        df_usb.write_csv("plutos_usb_artifacts.csv")
    else:
        print("[-] No specific USB exfiltration artifacts correlated.")

    # 2. Network Traffic Analysis
    df_net = engine.analyze_network_traffic()
    if df_net is not None and df_net.height > 0:
        print(f"\n[!] HIGH VOLUME TRAFFIC DETECTED (Top 5):")
        print("-" * 60)
        print(df_net.head(5))
        df_net.write_csv("plutos_network_profile.csv")
    else:
        print("[-] No high-volume network traffic detected.")

    print("\n[*] Analysis Complete. 'Ex Umbra in Solem'.")

if __name__ == "__main__":
    main()
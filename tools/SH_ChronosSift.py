import polars as pl
import argparse
import sys
import os
import re
from pathlib import Path
from tools.SH_ThemisLoader import ThemisLoader  # ⚖️ Themis召喚

# ============================================================
#  SH_ChronosSift v18.0 [Themis Integrated]
#  Mission: Detect Time Anomalies (Timestomping).
#  Update: Externalized Rules via ThemisLoader.
# ============================================================

def print_logo():
    print(r"""
       (   )
      (  :  )   < CHRONOS SIFT >
       (   )     v18.0 - Themis
        " "      "Time bows to the Law."
    """)

class ChronosEngine:
    def __init__(self, tolerance=10.0):
        self.tolerance = tolerance
        # ハードコーディングされていたリストは全廃っス！
        # ThemisLoaderがYAMLからロードしてくれるっス。

    def analyze(self, args):
        mode_str = "LEGACY (Aggressive Filter)" if args.legacy else "STANDARD (Balanced)"
        print(f"[*] Chronos v18.0 awakening... Mode: {mode_str}")
        print(f"    Targeting: {Path(args.file).name}")
        
        try:
            # Themisの初期化（ルールロード）
            loader = ThemisLoader()

            lf = pl.scan_csv(args.file, ignore_errors=True, infer_schema_length=0)
            
            # ---------------------------------------------------------
            # 0. Themis Noise Filtering (Global Clean-up)
            # ---------------------------------------------------------
            print("    -> Applying Themis Noise Filters...")
            available_cols = lf.collect_schema().names()
            noise_expr = loader.get_noise_filter_expr(available_cols)
            
            # YAMLで定義されたノイズ（旧 path_whitelist や noise_exts 等）を一括除去
            lf = lf.filter(~noise_expr)

            # ---------------------------------------------------------
            # 1. Scope Definition (Legacy vs Standard Structural Filter)
            # ---------------------------------------------------------
            # ※ ここは「OSの構造的仕様」に関するロジックなので、YAMLではなくコードに残すのが安全っス
            if args.legacy:
                # --- [LEGACY MODE] ---
                # 古いOS用。Windowsフォルダ等は「仕様」で矛盾するため全無視。
                print("    -> Applying Legacy Structure Filters (Ignoring System/Program Files)...")
                target_scope = r"(users|inetpub|xampp|wamp|apache|nginx|temp|perflogs|recycler)"
                ignore_scope = r"(windows|program files|programdata\\microsoft)"
                
                lf = lf.filter(
                    pl.col("ParentPath").str.to_lowercase().str.contains(target_scope) &
                    ~pl.col("ParentPath").str.to_lowercase().str.contains(ignore_scope)
                )
            else:
                # --- [STANDARD MODE] ---
                # 現代OS用。Sanctuary(聖域)を守りつつ、構造的なノイズを弾く
                
                # Sanctuary (守るべき場所) - これもYAML化検討可能だが、ロジック根幹に近いので一旦維持
                sanctuary_mask = (
                    pl.col("ParentPath").str.to_lowercase().str.contains("users") |
                    pl.col("ParentPath").str.to_lowercase().str.contains(r"tasks\\[^m]") | 
                    pl.col("ParentPath").str.to_lowercase().str.contains("startup") |
                    pl.col("ParentPath").str.to_lowercase().str.contains("inetpub") |
                    pl.col("ParentPath").str.to_lowercase().str.contains("xampp") |
                    pl.col("ParentPath").str.to_lowercase().str.contains("wamp")
                )
                
                # Root Garbage (autoexec etc.) - これも構造的ノイズとして維持
                root_garbage_files = ["autoexec.bat", "config.sys", "msdos.sys", "io.sys", "boot.ini", "ntldr"]
                root_garbage_mask = (
                    pl.col("FileName").str.to_lowercase().str.contains(r"install\.res\..+\.dll") |
                    pl.col("FileName").str.to_lowercase().is_in(root_garbage_files)
                )
                
                # OSノイズ（旧 NOISE_PATTERNS）はYAML側に移譲したので、ここでは「聖域 or ゴミじゃない」で判定
                # ※ YAMLのノイズフィルタは既に適用済みなので、ここでは構造的な判断のみ行う
                lf = lf.filter(sanctuary_mask | ~root_garbage_mask)

                # Standard Windows Binaries (FP reduction)
                # これもYAMLに移譲すべきだが、一旦ここに残っているロジック
                windows_fp_binaries = ["write.exe", "winhlp32.exe", "regedit.exe", "explorer.exe", "notepad.exe", "calc.exe"]
                lf = lf.filter(~pl.col("FileName").str.to_lowercase().is_in(windows_fp_binaries))

            # ---------------------------------------------------------
            # 2. Threat Identification (WANTED_FILES Replacement)
            # ---------------------------------------------------------
            print("    -> Applying Themis Threat Scoring (Target Identification)...")
            lf = loader.apply_threat_scoring(lf)
            
            # ---------------------------------------------------------
            # 3. Time Logic & Calculation
            # ---------------------------------------------------------
            cols = lf.collect_schema().names()
            
            si_cr = "si_dt" if "si_dt" in cols else ("Created0x10" if "Created0x10" in cols else "StandardInfoCreationTime")
            fn_cr = "fn_dt" if "fn_dt" in cols else ("Created0x30" if "Created0x30" in cols else "FileNameCreationTime")
            
            possible_mod_cols = ["si_mod_dt", "LastModified0x10", "StandardInfoLastModified"]
            si_mod = next((c for c in possible_mod_cols if c in cols), None)
            if not si_mod: si_mod = si_cr 

            for col_name in [si_cr, fn_cr, si_mod]:
                if col_name in cols:
                     lf = lf.with_columns(pl.col(col_name).str.replace("T", " "))
            
            lf = lf.with_columns([
                pl.col(si_cr).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("si_dt"),
                pl.col(fn_cr).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("fn_dt"),
                pl.col(si_mod).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("si_mod_dt")
            ]).drop_nulls(["si_dt", "fn_dt"])

            lf = lf.with_columns((pl.col("fn_dt") - pl.col("si_dt")).dt.total_seconds().alias("diff_sec"))

            # ---------------------------------------------------------
            # 4. Scoring & Tagging (Integrated with Themis)
            # ---------------------------------------------------------
            crit_exts = [".exe", ".dll", ".ps1", ".bat", ".sys", ".php", ".asp", ".jsp"]
            crit_pattern = f"(?i)({'|'.join([re.escape(e) for e in crit_exts])})$"
            
            # Themisのスコアが0より大きい＝WANTED_FILESや重要ターゲットにヒットしている
            
            lf = lf.with_columns([
                # Themisで脅威判定されたものは CRITICAL_ARTIFACT 扱い
                pl.when(pl.col("Threat_Score") > 0)
                  .then(pl.lit("CRITICAL_ARTIFACT"))
                  
                .when(pl.col("diff_sec") < -60)
                  .then(pl.lit("TIMESTOMP_BACKDATE"))
                  
                # Legacyモードの場合は FALSIFIED_FUTURE (未来) の判定を少し緩める
                .when((pl.col("diff_sec") > (3600 if args.legacy else self.tolerance)) & 
                      (pl.col("FileName").str.contains(crit_pattern) if args.legacy else pl.lit(True)))
                  .then(pl.lit("FALSIFIED_FUTURE"))
                  
                .otherwise(pl.lit("")).alias("Anomaly_Time"),
                
                pl.when(pl.col("si_mod_dt").dt.microsecond() == 0)
                  .then(pl.lit("ZERO_PRECISION"))
                  .otherwise(pl.lit("")).alias("Anomaly_Zero")
            ])
            
            lf = lf.with_columns(
                pl.struct(["Anomaly_Time", "Anomaly_Zero"]).map_elements(lambda x: (
                    200 if x["Anomaly_Time"] == "CRITICAL_ARTIFACT" else
                    100 if x["Anomaly_Time"] == "TIMESTOMP_BACKDATE" else
                    80 if x["Anomaly_Time"] == "FALSIFIED_FUTURE" else
                    50 if x["Anomaly_Zero"] == "ZERO_PRECISION" else 0
                ), return_dtype=pl.Int64).alias("Chronos_Score")
            )

            # Final Filter
            # スコア0のものを除外
            df = lf.filter(pl.col("Chronos_Score") > 0).collect()
            
            if df.height > 0:
                df = df.sort("Chronos_Score", descending=True)
                df.write_csv(args.out)
                print(f"[+] Anomalies detected: {df.height}")
                # カラムがあればThreat_Tagも表示
                disp_cols = ["Chronos_Score", "Anomaly_Time", "FileName", "ParentPath"]
                if "Threat_Tag" in df.columns: disp_cols.append("Threat_Tag")
                print(df.select([c for c in disp_cols if c in df.columns]).head(10))
            else:
                print("\n[*] Clean: No significant anomalies found.")
                # 空CSV出力
                schema = {"Chronos_Score": pl.Int64, "Anomaly_Time": pl.Utf8, "FileName": pl.Utf8, "ParentPath": pl.Utf8}
                pl.DataFrame(schema=schema).write_csv(args.out)

        except Exception as e:
            print(f"[!] Critical Error: {e}")
            import traceback
            traceback.print_exc()

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-o", "--out", default="Chronos_Results.csv")
    parser.add_argument("-t", "--tolerance", type=float, default=10.0)
    parser.add_argument("--legacy", action="store_true", help="Enable Legacy Mode")
    parser.add_argument("--targets-only", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--start", help="Ignored")
    parser.add_argument("--end", help="Ignored")
    args = parser.parse_args(argv)
    
    engine = ChronosEngine(args.tolerance)
    engine.analyze(args)

if __name__ == "__main__":
    main()
import argparse
import sys
import traceback
import os
from pathlib import Path
import polars as pl

# [ADD] Helper function to extract OS info
def get_os_info(kape_csv_dir):
    """
    SOFTWAREハイブのCSVからOS情報を物理的に抽出する
    Target: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    """
    if not kape_csv_dir or not Path(kape_csv_dir).exists():
        return "Unknown OS"
    
    # [FIX] 検索パターンを大幅に増強
    patterns = ["*Registry*.csv", "*SOFTWARE*.csv", "*Software*.csv", "*SystemInfo*.csv", "*BasicSystemInfo*.csv"]
    reg_files = []
    for p in patterns:
        reg_files.extend(list(Path(kape_csv_dir).rglob(p)))
    
    product_name = "Unknown OS"
    build_number = ""

    for csv in reg_files:
        try:
            # 必要なカラムだけ読んで高速化
            df = pl.read_csv(csv, ignore_errors=True, infer_schema_length=0)
            cols = df.columns
            
            # カラム名正規化
            key_col = next((c for c in cols if "Key" in c and "Path" in c), None)
            val_name_col = next((c for c in cols if "Value" in c and "Name" in c), None)
            val_data_col = next((c for c in cols if "Value" in c and "Data" in c), None)

            if not (key_col and val_name_col and val_data_col): continue

            # "Windows NT\CurrentVersion" を含む行をフィルタリング
            target_df = df.filter(
                (pl.col(key_col).str.contains(r"Windows NT\\CurrentVersion")) &
                (pl.col(val_name_col).is_in(["ProductName", "CurrentBuild"]))
            )

            for row in target_df.iter_rows(named=True):
                v_name = row.get(val_name_col)
                v_data = row.get(val_data_col)
                
                if v_name == "ProductName":
                    product_name = v_data
                elif v_name == "CurrentBuild":
                    build_number = f" (Build {v_data})"
            
            if product_name != "Unknown OS":
                return f"{product_name}{build_number}"

        except Exception:
            continue

    return "Unknown OS"

# ============================================================
#  [PATH FIX] Force add 'tools' directory to sys.path
#  これにより、どこから実行しても隣のモジュールが見えるようになるッス
# ============================================================
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.append(str(current_dir))

# 親ディレクトリ(ルート)も念のため追加
parent_dir = current_dir.parent
if str(parent_dir) not in sys.path:
    sys.path.append(str(parent_dir))

# ============================================================
#  Import The Triad
# ============================================================
try:
    # パスを通したので、ファイル名だけでimportできるはずッス
    from SH_ClothoReader import ClothoReader
    from SH_AtroposThinker import AtroposThinker
    from SH_LachesisWriter import LachesisWriter
    # ThemisLoaderも同様
    from SH_ThemisLoader import ThemisLoader
    # [NEW] Import Chronos for direct injection
    from SH_ChronosSift import ChronosEngine
    # [NEW] Import UserReporter for per-user reports
    from lachesis.user_reporter import UserReporter
except ImportError as e:
    # 万が一これでもダメな場合のデバッグ表示
    print(f"[!] Hekate Import Critical Error: {e}")
    print(f"[*] Debug: sys.path is {sys.path}")
    print(f"[*] Debug: Current dir is {current_dir}")
    print(f"[*] Hint: Ensure SH_ClothoReader.py exists in {current_dir}")
    sys.exit(1)


# ============================================================
#  SH_HekateWeaver v17.2 [Pathfinder Edition]
#  Mission: Orchestrate Clotho, Atropos, and Lachesis.
#  Update: Resolved stubborn ImportError via sys.path injection.
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HEKATE  --   [ The Triad v17.2 ]
      | | | | | |   "Themis defines the law, Hekate weaves the fate."
    """)

def main(argv=None):
    print_logo()
    
    parser = argparse.ArgumentParser(description="SkiaHelios Hekate Weaver (Themis Edition)")
    
    # Input / Output
    parser.add_argument("-i", "--input", required=True, help="Primary Timeline CSV (Hercules)")
    parser.add_argument("-o", "--out", default="SANS_Report.md", help="Output Report Path")
    
    # [NEW] Add this line!
    parser.add_argument("--kape", help="KAPE Artifacts Directory (Source for Registry)")
    
    # Artifact Inputs
    parser.add_argument("--aion", help="AION Persistence CSV")
    parser.add_argument("--persistence", help="Legacy alias for --aion")
    parser.add_argument("--pandora", help="Pandora Ghost CSV")
    parser.add_argument("--plutos", help="Plutos Gate CSV (Scored)")
    parser.add_argument("--plutos-net", help="Plutos Network Details CSV")
    parser.add_argument("--sphinx", help="Sphinx Deciphering CSV")
    parser.add_argument("--chronos", help="Chronos Sift CSV")
    parser.add_argument("--prefetch", help="Prefetch PECmd CSV")
    parser.add_argument("--siren", help="SirenHunt Results JSON")
    
    # Config
    parser.add_argument("--case", default="Investigation", help="Case Name")
    parser.add_argument("--lang", default="jp", help="Report Language (jp/en)")
    parser.add_argument("--rules", default="rules/triage_rules.yaml", help="Path to YAML rules (Loaded by Atropos)")
    
    args = parser.parse_args(argv)

    try:
        # ----------------------------------------------------
        # 1. Clotho: Spin the Thread (Load Data)
        # ----------------------------------------------------
        print("\n[*] Phase 1: Clotho is spinning the threads...")
        clotho = ClothoReader(args)
        dfs, siren_data, hostname, os_info, primary_user = clotho.spin_thread()

        # [NEW] OS Info Fallback Logic
        if os_info == "Unknown OS" and args.kape:
            print(f"    -> [Hekate] OS Info missing. Attempting to parse Registry from: {args.kape}")
            recovered_os = get_os_info(args.kape)
            if recovered_os != "Unknown OS":
                os_info = recovered_os
                print(f"    -> [Hekate] OS Identified: {os_info}")

        # -------------------------------------------------------------------------
        # [NEW] Chronos - USN Journal Direct Injection (Time Paradox Fix for Weaver)
        # -------------------------------------------------------------------------
        usn_csv = None
        # 探索ルート：入力ファイルのディレクトリ、KAPE出力先、カレント
        search_roots = []
        if args.input: search_roots.append(Path(args.input).parent)
        if args.kape: search_roots.append(Path(args.kape))
        search_roots.append(Path("."))

        print("    [*] Scanning for USN Journal ($J) to detect Time Paradox...")
        for root_path in search_roots:
            if not root_path or not root_path.exists(): continue
            # 再帰的に探す
            for f in root_path.rglob("*$J*Output.csv"):
                if "MFTECmd" in f.name:
                    usn_csv = str(f)
                    print(f"    [+] Found USN Journal: {usn_csv}")
                    break
            if usn_csv: break

        if usn_csv:
            try:
                print(f"    [!] Injecting USN Journal into Chronos Engine: {usn_csv}")
                engine = ChronosEngine()
                
                # Run specific USN logic directly
                lf_usn = pl.scan_csv(usn_csv, ignore_errors=True, infer_schema_length=0)
                lf_usn = engine._ensure_columns(lf_usn)
                lf_usn = engine._detect_usn_rollback(lf_usn)
                
                # Extract Critical Rollbacks
                rollback_hits = lf_usn.filter(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK").collect()
                
                # [FIX] Cast to String to match 'infer_schema_length=0' of main DF
                rollback_hits = rollback_hits.select([pl.col(c).cast(pl.Utf8) for c in rollback_hits.columns])
                
                if rollback_hits.height > 0:
                    print(f"      [ALERT] SYSTEM ROLLBACK DETECTED: {rollback_hits.height} events found!")
                    
                    # Ensure Score column consistency
                    if "Chronos_Score" not in rollback_hits.columns and "Threat_Score" in rollback_hits.columns:
                         rollback_hits = rollback_hits.with_columns(pl.col("Threat_Score").alias("Chronos_Score"))
                    
                    # Merge into dfs['Chronos']
                    if 'Chronos' not in dfs or dfs['Chronos'] is None:
                        dfs['Chronos'] = rollback_hits
                    else:
                        # Use diagonal concat to handle column mismatches
                        dfs['Chronos'] = pl.concat([dfs['Chronos'], rollback_hits], how="diagonal")
                else:
                    print("      [.] No Time Paradox found in USN.")
            except Exception as e:
                print(f"    [!] USN Injection Failed: {e}")
                # traceback.print_exc()

        # ----------------------------------------------------
        # 2. Atropos: Measure & Cut (Analyze Logic)
        # ----------------------------------------------------
        # Themisのルール適用はAtropos内部で行われるッス
        print("\n[*] Phase 2: Atropos is judging with Themis...")
        atropos = AtroposThinker(dfs, siren_data, hostname)
        analysis_result = atropos.contemplate()

        # ----------------------------------------------------
        # 3. Lachesis: Allot the Fate (Write Report)
        # ----------------------------------------------------
        print("\n[*] Phase 3: Lachesis is writing the fate...")
        lachesis = LachesisWriter(lang=args.lang, hostname=hostname, case_name=args.case)
        lachesis.weave_report(analysis_result, args.out, dfs, hostname, os_info, primary_user)

        # ----------------------------------------------------
        # 4. UserReporter: Generate per-user activity reports
        # ----------------------------------------------------
        print("\n[*] Phase 4: Generating per-user activity reports...")
        try:
            if "hercules" in dfs and dfs["hercules"] is not None:
                reporter = UserReporter(dfs["hercules"], args.out)
                user_reports = reporter.generate_all_reports()
                if user_reports:
                    print(f"    [+] Generated {len(user_reports)} user report(s)")
        except Exception as e:
            print(f"    [!] UserReporter warning: {e}")

        print(f"\n[+] Operation Complete. The fate has been woven into: {args.out}")

    except Exception as e:
        print(f"\n[!] HEKATE CRASH: The Triad has failed.")
        print(f"    Error: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
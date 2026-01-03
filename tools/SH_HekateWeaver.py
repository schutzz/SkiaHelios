import argparse
import sys
import traceback
import os
from pathlib import Path

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

        print(f"\n[+] Operation Complete. The fate has been woven into: {args.out}")

    except Exception as e:
        print(f"\n[!] HEKATE CRASH: The Triad has failed.")
        print(f"    Error: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
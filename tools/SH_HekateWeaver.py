import argparse
import sys
import traceback

# Import The Triad
try:
    from tools.SH_ClothoReader import ClothoReader
    from tools.SH_AtroposThinker import AtroposThinker
    from tools.SH_LachesisWriter import LachesisWriter
except ImportError:
    # パスが通っていない場合のフォールバック（直接実行時など）
    try:
        from SH_ClothoReader import ClothoReader
        from SH_AtroposThinker import AtroposThinker
        from SH_LachesisWriter import LachesisWriter
    except ImportError as e:
        print(f"[!] Hekate Import Error: {e}")
        sys.exit(1)

# ============================================================
#  SH_HekateWeaver v16.1 [Fix: Argument Passing]
#  Mission: Orchestrate Clotho, Atropos, and Lachesis.
#  Update: Accepted 'argv' for HeliosConsole integration.
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HEKATE  --   [ The Triad v16.1 ]
      | | | | | |   "Clotho reads, Atropos thinks, Lachesis writes."
    """)

# [FIX] 引数 argv=None を受け取れるように変更っス！
def main(argv=None):
    print_logo()
    
    parser = argparse.ArgumentParser(description="SkiaHelios Hekate Weaver (Triad Edition)")
    
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
    
    # [FIX] 受け取った argv をパースするように変更っス！
    args = parser.parse_args(argv)

    try:
        # ----------------------------------------------------
        # 1. Clotho: Spin the Thread (Load Data)
        # ----------------------------------------------------
        clotho = ClothoReader(args)
        dfs, siren_data, hostname = clotho.spin_thread()

        # ----------------------------------------------------
        # 2. Atropos: Measure & Cut (Analyze Logic)
        # ----------------------------------------------------
        atropos = AtroposThinker(dfs, siren_data, hostname)
        analysis_result = atropos.contemplate()

        # ----------------------------------------------------
        # 3. Lachesis: Allot the Fate (Write Report)
        # ----------------------------------------------------
        lachesis = LachesisWriter(lang=args.lang, hostname=hostname, case_name=args.case)
        lachesis.weave_report(analysis_result, args.out, dfs)

        print(f"\n[+] Operation Complete. The fate has been woven into: {args.out}")

    except Exception as e:
        print(f"\n[!] HEKATE CRASH: The Triad has failed.")
        print(f"    Error: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
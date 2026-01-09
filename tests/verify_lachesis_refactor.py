import sys
import os
import shutil
from pathlib import Path
import polars as pl
from datetime import datetime
import re
import traceback

# パス解決: プロジェクトルートを最優先で追加
project_root = Path(__file__).parent.parent.absolute()
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# テスト用出力ディレクトリ
OUTPUT_DIR = Path(__file__).parent / "test_output"
if not OUTPUT_DIR.exists():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def create_mock_dfs():
    """Lachesisが要求する全ての列を網羅したMockを作成するっス"""
    # 1. Timeline Mock (Criticality列を必須追加)
    df_timeline = pl.DataFrame({
        "Time": ["2016-06-21T12:01:46.054037", "2016-06-21T12:01:44.005640", "2016-06-20T23:48:22.226062"],
        "Source": ["UserAssist", "UserAssist", "USN"],
        "Category": ["EXEC", "ANTI", "FILE"],
        "Criticality": [100, 100, 300], # これが漏れてたっス！
        "Summary": ["Run Count: 5", "ccleaner.exe executed", "Rollback: -35997"],
        "Message": ["Execution", "Anti-Forensics", "Time anomaly"],
        "Tag": ["EXECUTION", "ANTI_FORENSICS", "TIME_PARADOX"],
        "FileName": ["Beautiful-Pictures.lnk", "ccleaner.exe", "$J"],
        "Target_Path": ["C:\\Windows\\System32\\cmd.exe", "", ""],
        "Arguments": ["/c calc.exe", "", ""],
        "Keywords": [["Beautiful-Pictures.lnk"], ["ccleaner.exe"], ["$J"]]
    })

    # 2. Pandora Mock
    df_pandora = pl.DataFrame({
        "Ghost_FileName": ["Beautiful-Pictures-Of-Cute-Animals-6.jpg.lnk", "extension_0_52.crx"],
        "ParentPath": ["C:\\Users\\Hunter\\AppData\\Roaming\\Microsoft\\Windows\\Recent", "C:\\Program Files (x86)\\Adobe"],
        "Threat_Score": [250.0, 300.0],
        "Threat_Tag": ["CRITICAL_PHISHING", "CRITICAL_MASQUERADE"],
        "Ghost_Time_Hint": ["2016-06-21T12:01:46", "2016-06-21T00:02:50"]
    })

    # 3. Chronos Mock
    df_chronos = pl.DataFrame({
        "FileName": ["pythonw.exe", "Unknown"],
        "ParentPath": ["c:\\python27\\pythonw.exe", ""],
        "Chronos_Score": [50.0, 300.0],
        "Threat_Tag": ["TIMESTOMP", "TIME_PARADOX"],
        "Anomaly_Time": ["", "Rollback: -35997 sec"],
        "si_dt": ["2016-06-21T10:00:00", "2016-06-20T23:48:22"],
        "UpdateTimestamp": ["2016-06-21T10:00:00", "2016-06-20T23:48:22"]
    })

    # 4. AION Mock
    df_aion = pl.DataFrame({
        "Target_FileName": ["ccleaner.exe"],
        "Full_Path": ["C:\\Program Files\\CCleaner\\ccleaner.exe"],
        "AION_Score": [80.0],
        "Last_Executed_Time": ["2016-06-21T12:01:44"]
    })

    return {
        "Timeline": df_timeline,
        "Pandora": df_pandora,
        "Chronos": df_chronos,
        "AION": df_aion,
        "UserAssist": df_timeline,
        "Prefetch": df_timeline
    }

def normalize_report(content):
    """比較のために動的な要素をマスクするっス"""
    # 日付行のマスク
    content = re.sub(r"\|\s*\*\*Report Date\*\*\s*\|.*?\|", "| **Report Date** | [MASKED_DATE] |", content)
    # JSON内の時刻マスク
    content = re.sub(r"\"Generated_At\":\s*\".*?\"", "\"Generated_At\": \"[MASKED_TIME]\"", content)
    # Mermaid内のハッシュ値由来のIDを正規化 (N + 数字)
    content = re.sub(r"N\d+", "N_NORMALIZED", content)
    return content.strip()

def run_test():
    print(f"[*] Starting Lachesis Verification at {datetime.now()}")
    dfs = create_mock_dfs()
    
    analysis_result = {
        "events": dfs["Timeline"].to_dicts(),
        "verdict_flags": ["PHISHING", "TIMESTOMP"],
        "lateral_summary": "None"
    }

    # --- 1. Run Legacy (Baseline) ---
    # print(f"[*] Step 1: Running Legacy Lachesis...")
    # legacy_out = OUTPUT_DIR / "Grimoire_Legacy.md"
    # Legacy removed, skipping comparison
    
    # --- 2. Run Refactored (New) ---
    print(f"[*] Step 2: Running Refactored Lachesis (Templated)...")
    new_out = OUTPUT_DIR / "Grimoire_Refactored.md"
    try:
        from tools.lachesis.core import LachesisCore
        writer_new = LachesisCore(hostname="4ORENSICS")
        # Correct Args: analysis_result, output_path, dfs, hostname, os_info, primary_user
        writer_new.weave_report(analysis_result, str(new_out), dfs, "4ORENSICS", "Windows 8.1 Mock", "Hunter")
        print(f"    -> Refactored Output Generated: {new_out}")
    except ImportError:
        print(f"    [?] New modules not found. Check tools/lachesis/ files.")
        import traceback; traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"    [!] New Run Failed!")
        import traceback; traceback.print_exc()
        sys.exit(1)

    # --- 3. Compare / Verify ---
    print(f"[*] Step 3: Verifying Output Content...")
    if new_out.exists() and new_out.stat().st_size > 0:
        with open(new_out, "r", encoding="utf-8") as f: content = f.read()
        
        # Check for key sections from template
        required_strings = [
            "Executive Summary",
            "Initial Access Vector Analysis",
            "Investigation Timeline",
            "Technical Findings",
            "Detection Statistics",
            "Conclusions & Recommendations",
            "Appendix"
        ]
        missing = [s for s in required_strings if s not in content]
        
        if not missing:
            print(f"\n✅ SUCCESS: Report generated and contains all required sections!")
        else:
            print(f"\n❌ FAILURE: Report generated but missing sections: {missing}")
            print(f"Content Preview:\n{content[:500]}...")
            sys.exit(1)
    else:
        print(f"\n❌ FAILURE: Output file not created or empty!")
        sys.exit(1)

if __name__ == "__main__":
    run_test()
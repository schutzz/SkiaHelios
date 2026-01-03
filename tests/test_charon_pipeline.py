import os
import yaml
import pandas as pd
import polars as pl
from pathlib import Path
import sys

# パス設定（環境に合わせて微調整してほしいっス）
BASE_DIR = Path(".")
sys.path.append(str(BASE_DIR.resolve())) # Allow importing tools from root
RULES_DIR = BASE_DIR / "rules" / "sigma_test"
OUTPUT_RULE_FILE = BASE_DIR / "rules" / "sigma_test_imported.yaml"
MOCK_DATA_FILE = BASE_DIR / "test_evtx_mock.csv"
RESULT_FILE = BASE_DIR / "test_result.csv"

# 必要なディレクトリ作成
RULES_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------
# Phase 1: テスト用Sigmaルールの生成 (The "Source")
# ---------------------------------------------------------
def create_test_sigma_rule():
    print("[*] Phase 1: Generating Test Sigma Rule...")
    rule_content = {
        "title": "AION Conductance Test Rule",
        "id": "test-signal-001",
        "status": "test",
        "description": "Detects the specific magic word for connectivity testing.",
        "author": "SkiaHelios Antigravity",
        "date": "2025-01-01",
        "logsource": {
            "category": "process_creation",
            "product": "windows"
        },
        "detection": {
            "selection": {
                "CommandLine": "AION_CONDUCTANCE_TEST_SIGNAL" # 👈 これを検知させる！
            },
            "condition": "selection"
        },
        "level": "critical",
        "tags": ["attack.execution", "AION.TEST"]
    }
    
    rule_path = RULES_DIR / "test_rule.yml"
    with open(rule_path, "w") as f:
        yaml.dump(rule_content, f)
    print(f"   > Rule created: {rule_path}")

# ---------------------------------------------------------
# Phase 2: CharonBridgeによる変換 (The "Converter")
# ---------------------------------------------------------
def run_charon_bridge():
    print("[*] Phase 2: Running SH_CharonBridge...")
    # 既存のCharonBridgeをインポートして実行（あるいはサブプロセスで呼ぶ）
    try:
        from tools.SH_CharonBridge import CharonBridge
        bridge = CharonBridge()
        bridge.execute(str(RULES_DIR), str(OUTPUT_RULE_FILE))
        
        # 検証
        with open(OUTPUT_RULE_FILE, "r") as f:
            data = yaml.safe_load(f)
            rules = data.get("threat_signatures", [])
            for r in rules:
                if "AION_CONDUCTANCE_TEST_SIGNAL" in r.get("pattern", ""):
                    print(f"   > Verification Success: Pattern found in {OUTPUT_RULE_FILE}")
                    return True
        print("   > Verification Failed: Pattern not found in output.")
        return False
    except ImportError:
        print("   [!] Error: SH_CharonBridge not found in tools/.")
        return False
    except Exception as e:
        print(f"   [!] Error during conversion: {e}")
        return False

# ---------------------------------------------------------
# Phase 3: モックデータの生成 (The "Input Signal")
# ---------------------------------------------------------
def create_mock_data():
    print("[*] Phase 3: Synthesizing Mock Event Log...")
    # HerculesRefereeが期待するカラム構造 (Kape EvtxECmd風)
    data = {
        "TimeCreated": ["2025-01-01 12:00:00", "2025-01-01 12:05:00"],
        "EventId": [4688, 4688],
        "Computer": ["TEST-PC.local", "TEST-PC.local"],
        "UserName": ["User1", "User1"],
        "Payload": [
            "C:\\Windows\\System32\\svchost.exe -k netsvcs", # 正常
            "C:\\Temp\\malware.exe /c echo AION_CONDUCTANCE_TEST_SIGNAL" # 👈 異常（トリガー）
        ],
        # HerculesはPayloadまたはCommandLineを見る
        "CommandLine": [
            "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            "C:\\Temp\\malware.exe /c echo AION_CONDUCTANCE_TEST_SIGNAL"
        ]
    }
    df = pd.DataFrame(data)
    df.to_csv(MOCK_DATA_FILE, index=False)
    print(f"   > Mock data injected: {MOCK_DATA_FILE}")

# ---------------------------------------------------------
# Phase 4: Themis & Herculesによる検知 (The "Detection")
# ---------------------------------------------------------
def run_detection_logic():
    print("[*] Phase 4: Executing Hercules Referee Logic...")
    
    # 簡易版Herculesロジック（ThemisLoaderの挙動確認）
    from tools.SH_ThemisLoader import ThemisLoader
    
    # Loaderにテスト用のルールファイルを強制的に読み込ませるためのハック
    loader = ThemisLoader(rule_paths=[str(OUTPUT_RULE_FILE)]) 
    
    # モック読み込み
    df = pl.read_csv(MOCK_DATA_FILE)
    
    # カラムマッピング（Hercules内で行っている処理の簡易再現）
    # SigmaのCommandLine -> AIONのTarget_Path へのマッピングが必要
    df = df.with_columns(
        pl.col("CommandLine").alias("Target_Path"),
        pl.col("Payload").alias("Full_Path"),
        pl.col("TimeCreated").alias("Timestamp_UTC")
    )

    # Themisの判定ロジック適用
    df_scored = loader.apply_threat_scoring(df)
    
    # 結果保存
    df_scored.write_csv(RESULT_FILE)
    
    # ---------------------------------------------------------
    # Phase 5: 結果検証 (The "Validation")
    # ---------------------------------------------------------
    print("[*] Phase 5: Validating Results...")
    hits = df_scored.filter(pl.col("Threat_Score") > 0)
    
    if hits.height > 0:
        print("\n" + "="*50)
        print("[+] TEST PASSED: Threat Detected!")
        print("="*50)
        for row in hits.iter_rows(named=True):
            print(f"Hit Rule: {row['Threat_Tag']}")
            print(f"Score:    {row['Threat_Score']}")
            print(f"Payload:  {row['Target_Path']}")
        return True
    else:
        print("\n" + "="*50)
        print("[-] TEST FAILED: No Threats Detected.")
        print("="*50)
        print("Debug Info: Check rules/sigma_test_imported.yaml and column mappings.")
        return False

if __name__ == "__main__":
    create_test_sigma_rule()
    if run_charon_bridge():
        create_mock_data()
        run_detection_logic()

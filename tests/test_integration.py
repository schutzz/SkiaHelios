import sys
import os
import shutil
import pytest
from pathlib import Path
import polars as pl

# ------------------------------------------------------------
# [Path Setup]
# プロジェクトルートをパスに追加して、toolsモジュールが見えるようにするっス
# ------------------------------------------------------------
sys.path.append(str(Path(__file__).parent.parent))

# 必要なモジュールをインポート
# ※ create_chimera_mock.py 内の main 関数を generate_mock として呼ぶっス
from tests.create_chimera_mock import main as generate_mock
from tools.SH_AIONDetector import AIONEngine

# テスト用の一時出力ディレクトリ
TEST_OUT = Path("tests/test_output")
MOCK_DIR = Path("Mock_TwinSnakes")

@pytest.fixture(scope="session", autouse=True)
def setup_teardown():
    """
    【テスト前】TwinSnakesのMockデータを生成
    【テスト後】生成したゴミをお掃除
    """
    # 1. クリーンアップ (前のゴミがあれば消す)
    if TEST_OUT.exists(): shutil.rmtree(TEST_OUT)
    if MOCK_DIR.exists(): shutil.rmtree(MOCK_DIR)
    
    TEST_OUT.mkdir(parents=True, exist_ok=True)
    
    # 2. Mock生成 (create_chimera_mock.py を実行)
    print("\n[Setup] Generating TwinSnakes Mock Data...")
    generate_mock()
    
    yield # ここでテスト関数が実行されるっス
    
    # 3. 終了後のお掃除
    # デバッグ時はコメントアウトして残すと便利っス
    if MOCK_DIR.exists(): shutil.rmtree(MOCK_DIR)
    if TEST_OUT.exists(): shutil.rmtree(TEST_OUT)

def test_mock_data_integrity():
    """
    Mockデータが正しく生成されているか（Hercules互換スキーマか）を確認するっス
    """
    host_a_timeline = MOCK_DIR / "Workstation-01" / "Master_Timeline.csv"
    assert host_a_timeline.exists(), "Host A Timeline not generated!"
    
    df = pl.read_csv(host_a_timeline, ignore_errors=True)
    required_cols = ["Timestamp_UTC", "User", "Judge_Verdict", "Tag"]
    
    for col in required_cols:
        assert col in df.columns, f"Missing column in Mock: {col}"
    
    # ちゃんと悪意ある行が含まれているかチェック
    critical_rows = df.filter(pl.col("Judge_Verdict").str.contains("CRITICAL"))
    assert critical_rows.height >= 3, "Mock data is missing critical attack vectors!"

def test_aion_persistence_detection():
    """
    [ツール検証] AIONDetector が Mock内の悪意あるRunKeyを検知できるかテスト
    """
    # Host A (Workstation-01) をターゲットにする
    target_dir = MOCK_DIR / "Workstation-01"
    # AIONは MFT(Master_Timeline) と フォルダ内のAutoruns.csv 等を見るっス
    mft_path = target_dir / "Master_Timeline.csv"
    
    print(f"\n[Test] Running AION on {target_dir}...")
    
    # AIONエンジンを初期化
    engine = AIONEngine(target_dir=str(target_dir), mft_csv=str(mft_path))
    
    # 解析実行
    results_df = engine.analyze()
    
    # --- 検証フェーズ ---
    # 1. 結果がNoneでないこと
    assert results_df is not None, "AION failed to return a DataFrame (None returned)."
    
    # 2. 何かしらの永続化を検知していること
    print(f"[Debug] AION Detected {results_df.height} items.")
    assert results_df.height > 0, "AION found 0 persistence items (Expected detection)."
    
    # 3. Mockに含まれる特定のマルウェア (Updater / PowerShell) を検知しているか
    # Mockデータでは "Value: Updater | Data: ...powershell..." という行があるはず
    hits = results_df.filter(
        pl.col("Full_Path").str.to_lowercase().str.contains("updater") |
        pl.col("Entry_Location").str.to_lowercase().str.contains("run")
    )
    assert hits.height > 0, "AION missed the malicious 'Updater' RunKey!"
    
    # 4. タグ付けが正しいか
    tags = hits["AION_Tags"].to_list()
    assert any("SUSPICIOUS" in t or "AUTORUNS" in t for t in tags), "Correct tags were not applied!"

def test_lateral_movement_artifacts():
    """
    [シナリオ検証] Host B (FileServer-99) に横展開の痕跡(LATERAL_MOVEMENT)があるか
    (Hekate/Herculesが処理する前の、Mockデータの論理的正当性チェック)
    """
    host_b_timeline = MOCK_DIR / "FileServer-99" / "Master_Timeline.csv"
    assert host_b_timeline.exists()
    
    df = pl.read_csv(host_b_timeline, ignore_errors=True)
    
    # LATERAL_TOOL (PSEXESVC) や CRITICAL_LATERAL タグを探す
    lateral_hits = df.filter(
        pl.col("Tag").str.contains("LATERAL") | 
        pl.col("Judge_Verdict").str.contains("LATERAL")
    )
    
    assert lateral_hits.height > 0, "Lateral Movement artifacts are missing in Host B Mock!"
    
    # 具体的に PSEXESVC があるか
    psexec = lateral_hits.filter(pl.col("Target_Path").str.contains("PSEXESVC"))
    assert psexec.height > 0, "PSEXESVC artifact missing!"

if __name__ == "__main__":
    # ローカルで直接実行して試す用
    print(">>> Running Manual Tests...")
    
    # Setup
    if MOCK_DIR.exists(): shutil.rmtree(MOCK_DIR)
    if TEST_OUT.exists(): shutil.rmtree(TEST_OUT)
    generate_mock()
    
    try:
        test_mock_data_integrity()
        print("[PASS] Mock Data Integrity")
        
        test_aion_persistence_detection()
        print("[PASS] AION Detection Logic")
        
        test_lateral_movement_artifacts()
        print("[PASS] Lateral Movement Scenario")
        
        print("\n>>> ALL TESTS PASSED SUCCESSFULLY! 🦁")
    except Exception as e:
        print(f"\n[FAIL] Test Failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Teardown
        if MOCK_DIR.exists(): shutil.rmtree(MOCK_DIR)
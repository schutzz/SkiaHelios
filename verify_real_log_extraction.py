import re
from pathlib import Path
from tools.SH_HekateWeaver import HekateWeaver
from tools.SH_SphinxDeciphering import SphinxEngine

# 1. Simulate the extraction logic from HekateWeaver
def _extract_seeds_from_args(text):
    """Argumentsからファイルパス/名前を抽出する (Container-Aware対応)"""
    if not text: return []
    
    # [ROBUSTNESS] Handle quoted paths (e.g. "C:\Temp\Script.ps1")
    # Remove quotes to ensure regex matches the content cleanly
    clean_text = str(text).replace('"', '')
    
    # 拡張子を持つトークンを抽出 (User provided pattern + typical ones)
    # Note: Added boundary check `(?:\s|["']|$|[^\w\.])` to avoid .Cmdletization -> .Cmd
    matches = re.findall(r'([\w\-\.\\/:~]+\.(?:exe|ps1|bat|cmd|vbs|dll|sys|doc|docx|xls|xlsx|pdf|zip|js|hta|wsf))(?:\s|["\']|$|[^\w\.])', clean_text, re.IGNORECASE)
    results = set()
    for m in matches:
        # パス区切り除去してファイル名のみにする
        fname = Path(m).name
        if len(fname) > 2: # 短すぎるゴミ除外
            results.add(fname.lower())
    return list(results)

# 2. Simulate the Raw Log Content provided by User
# EID 800 Pipeline Execution with buried Payload
raw_eid_800 = r"""
	Payload: CommandInvocation(Out-Default): "Out-Default", パラメーター バインド(Out-Default): 名前="InputObject"; 値="Attack_Chain.bat", パラメーター バインド(Out-Default): 名前="InputObject"; 値="Setup_Forensic_Ready.ps1", パラメーター バインド(Out-Default): 名前="InputObject"; 値="新規 テキスト ドキュメント.txt", 		FALSE	C:\Temp\pseudo\infected2\kape\E\Windows\System32\winevt\logs\Microsoft-Windows-PowerShell%4Operational.evtx	0x0	0	{"EventData":{"Data":[{"@Name":"ContextInfo","#text":"        重要度 = Informational,         ホスト名 = ConsoleHost,         ホストのバージョン = 5.1.26100.7462,         ホスト ID = 47db40c0-5a53-46ba-9316-2443a23233b3,         ホスト アプリケーション = C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,         エンジンのバージョン = 5.1.26100.7462,         実行空間 ID = 63f2165c-a2d5-4389-abcd-3bebb9a21809,         パイプライン ID = 23,         コマンド名 = ,         コマンドの種類 = Script,         スクリプト名 = ,         コマンド パス = ,         シーケンス番号 = 52,         ユーザー = DESKTOP-U7UOT5J\\user,         接続されたユーザー = ,         シェル ID = Microsoft.PowerShell, "},{"@Name":"UserData"},{"@Name":"Payload","#text":"CommandInvocation(Out-Default): \"Out-Default\", パラメーター バインド(Out-Default): 名前=\"InputObject\"; 値=\"Attack_Chain.bat\", パラメーター バインド(Out-Default): 名前=\"InputObject\"; 値=\"Setup_Forensic_Ready.ps1\", パラメーター バインド(Out-Default): 名前=\"InputObject\"; 値=\"新規 テキスト ドキュメント.txt\", "}]}}
"""

# EID 4104 ScriptBlock
raw_eid_4104 = r"""
ScriptBlockText: ./Attack_Chain.bat						FALSE	C:\Temp\pseudo\infected2\kape\E\Windows\System32\winevt\logs\Microsoft-Windows-PowerShell%4Operational.evtx	0x0	0	{"EventData":{"Data":[{"@Name":"MessageNumber","#text":"1"},{"@Name":"MessageTotal","#text":"1"},{"@Name":"ScriptBlockText","#text":"./Attack_Chain.bat"},{"@Name":"ScriptBlockId","#text":"188fba68-2125-46ac-af5e-ea1b865d7a93"},{"@Name":"Path"}]}}
"""

# EID 4688 Process Creation
raw_eid_4688 = r"""
CommandLine: C:\WINDOWS\system32\cmd.exe /c ""C:\users\user\desktop\Attack_Chain.bat""
"""

def verify_extraction():
    print("[-] Verifying Extraction Logic against User Logs...\n")

    # Test 1: EID 800 (The hardest one)
    print(f"--- [1] EID 800 (Pipeline Execution) ---")
    seeds_800 = _extract_seeds_from_args(raw_eid_800)
    print(f"Raw Input Length: {len(raw_eid_800)}")
    print(f"Extracted Seeds: {seeds_800}")
    
    expected_800 = {'attack_chain.bat', 'setup_forensic_ready.ps1', '新規 テキスト ドキュメント.txt.txt'} # Regex might miss txt if not in list.
    # Waite, I only added typical executable/doc extensions. txt is not in my list? 
    # Let's check regex: exe|ps1|bat|cmd|vbs|dll|sys|doc|docx|xls|xlsx|pdf|zip|js|hta|wsf
    # '.txt' is NOT in the list. This explains why '新規 テキスト ドキュメント.txt' might satisfy user "catch anything" but failed my regex.
    # User said "anything clearly in logs".
    # I should add 'txt' and maybe match generic extensions? 
    # But generic extension matching is noisy.
    
    if 'attack_chain.bat' in seeds_800:
        print("[PASS] Caught 'Attack_Chain.bat'")
    else:
        print("[FAIL] Missed 'Attack_Chain.bat'")

    if 'setup_forensic_ready.ps1' in seeds_800:
         print("[PASS] Caught 'Setup_Forensic_Ready.ps1'")

    # Test 2: EID 4104
    print(f"\n--- [2] EID 4104 (ScriptBlock) ---")
    seeds_4104 = _extract_seeds_from_args(raw_eid_4104)
    print(f"Extracted Seeds: {seeds_4104}")
    if 'attack_chain.bat' in seeds_4104:
        print("[PASS] Caught 'Attack_Chain.bat'")

    # Test 3: EID 4688 with double quotes
    print(f"\n--- [3] EID 4688 (Cmd Double Quotes) ---")
    seeds_4688 = _extract_seeds_from_args(raw_eid_4688)
    print(f"Input: {raw_eid_4688.strip()}")
    print(f"Extracted Seeds: {seeds_4688}")
    if 'attack_chain.bat' in seeds_4688:
        print("[PASS] Caught 'Attack_Chain.bat'")

if __name__ == "__main__":
    verify_extraction()

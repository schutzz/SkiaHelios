import csv
import os
from pathlib import Path

# ============================================================
#  SH_MockInjector v1.0 [Cerberus Validation Tool]
#  Mission: Generate consistent Mock Data for Logic Verification.
#  Output: Mock_Timeline.csv & Mock_Pandora.csv
# ============================================================

def generate_mock_data(output_dir):
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Generating Mock Data in: {out_path}")

    # ---------------------------------------------------------
    # 1. Mock Timeline (Hercules Input)
    # ---------------------------------------------------------
    timeline_file = out_path / "Mock_Timeline.csv"
    
    # Herculesに必要なカラム構成
    # Timestamp_UTC, Action, User, Subject_SID, Message, Tag, ...
    header = ["Timestamp_UTC", "Action", "User", "Subject_SID", "Message", "Tag", "Source", "Hosting_App"]
    
    # データセット: (Time, Action, Message)
    # ※ User/SIDは固定で "Admin", "S-1-5-21-MOCK" を使用
    rows = []

    # --- Scenario A: USB Connection + Immediate Deletion (Hit) ---
    # 10:00:00 - USB Connect (EID 6416)
    rows.append(["2025-12-27 10:00:00", "EID:6416 (PnP Device)", "SYSTEM", "S-1-5-18", "Device: USB Mass Storage Device (Vendor: SanDisk)", "Tag: [USB]", "System", ""])
    # 10:00:02 - Command Execution (Del)
    rows.append(["2025-12-27 10:00:02", "EID:4688 (Process Create)", "Admin", "S-1-5-21-MOCK", "CommandLine: cmd.exe /c del E:\\Secret_Data.pdf", "Tag: [EXEC]", "Security", "cmd.exe"])
    
    # --- Scenario B: Anti-Forensics (sdelete) (Hit) ---
    # 10:10:00 - sdelete Execution
    rows.append(["2025-12-27 10:10:00", "EID:4688 (Process Create)", "Admin", "S-1-5-21-MOCK", "CommandLine: sdelete.exe -p 3 C:\\Users\\Admin\\Keys.txt", "Tag: [EXEC]", "Security", "sdelete.exe"])

    # --- Scenario C: Negative Test (Time Gap > 10s) (No Hit) ---
    # 10:20:00 - Shell Start
    rows.append(["2025-12-27 10:20:00", "EID:4688 (Process Create)", "Admin", "S-1-5-21-MOCK", "CommandLine: powershell.exe -NoProfile", "Tag: [EXEC]", "Security", "powershell.exe"])
    # 10:20:25 - File Deletion Event (Target Ghost Time)
    # ※ログ上には直接的な削除イベントが残っていないか、断片的なものとする
    rows.append(["2025-12-27 10:20:25", "FileSystem Activity", "Admin", "S-1-5-21-MOCK", "File Deleted: D:\\Old_Logs.log", "Tag: [FILE]", "USN_Journal", ""])

    with open(timeline_file, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    print(f"   [+] Created: {timeline_file.name}")

    # ---------------------------------------------------------
    # 2. Mock Pandora Report (Hercules Trigger)
    # ---------------------------------------------------------
    pandora_file = out_path / "Mock_Pandora.csv"
    
    # Herculesに必要なカラム: Risk_Tag, Ghost_FileName, Ghost_Time_Hint
    p_header = ["Risk_Tag", "Ghost_FileName", "Ghost_Time_Hint", "ParentPath", "Source"]
    
    p_rows = []
    
    # Scenario A Target (Timeline: 10:00:02)
    p_rows.append(["[RISK_EXT] LNK_DEL", "Secret_Data.pdf", "2025-12-27 10:00:02", "E:\\", "Mock_USN"])
    
    # Scenario B Target (Timeline: 10:10:00)
    p_rows.append(["[RISK_EXT] LNK_DEL", "Keys.txt", "2025-12-27 10:10:00", "C:\\Users\\Admin", "Mock_MFT"])
    
    # Scenario C Target (Timeline: 10:20:25) - The Ghost exists, but the cause is too far away (25s gap)
    p_rows.append(["[RISK_EXT] EXEC", "Old_Logs.log", "2025-12-27 10:20:25", "D:\\", "Mock_USN"])

    with open(pandora_file, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(p_header)
        writer.writerows(p_rows)
    print(f"   [+] Created: {pandora_file.name}")
    print("[*] Mock Injection Complete. Ready for Validation.")

if __name__ == "__main__":
    # Save to TestCase/Mock_Data by default
    generate_mock_data("TestCase/Mock_Data")
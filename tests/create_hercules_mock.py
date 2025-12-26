import csv
import os
from pathlib import Path

def create_mock_data():
    base_dir = Path("tests/hercules_mock")
    base_dir.mkdir(parents=True, exist_ok=True)

    # 1. Mock Timeline (Chaos Format)
    timeline_path = base_dir / "Mock_Timeline.csv"
    timeline_data = [
        ["TimeCreated", "Action", "Subject_SID", "Tag", "Message"],
        # 1. Regular System Activity
        ["2025-01-01 10:00:00", "Process Created", "S-1-5-18", "", "System process"],
        
        # 2. Activity by User A (Active)
        ["2025-01-01 10:05:00", "File Access", "S-1-5-21-123-456-789-1001", "", "UserA Access"],

        # 3. Activity by User B (Before Deletion) - Should be tagged DELETED_USER_ACTIVITY later
        ["2025-01-01 11:00:00", "File Access", "S-1-5-21-123-456-789-1002", "", "UserB Access (Pre-Death)"],

        # 4. User B Deletion Event (EID 4726)
        # Action string simulates the event log content
        ["2025-01-01 12:00:00", "EID:4726 User Account Management/User Account Deleted TargetSid: S-1-5-21-123-456-789-1002", "S-1-5-18", "ACCOUNT_DELETED", "UserB Deleted by SYSTEM"],

        # 5. Activity by User B (After Deletion - Ghost) - Should be tagged DELETED_USER_ACTIVITY
        ["2025-01-01 12:05:00", "Process Created", "S-1-5-21-123-456-789-1002", "", "UserB Access (Ghost)"],

        # 6. Orphan Activity (SID not in registry)
        ["2025-01-01 13:00:00", "Process Created", "S-1-5-21-999-999-999-9999", "", "Unknown SID Action"]
    ]
    
    with open(timeline_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(timeline_data)
    print(f"Created: {timeline_path}")

    # 2. Mock Registry (ProfileList)
    reg_path = base_dir / "Mock_Registry_ProfileList.csv"
    reg_data = [
        ["KeyPath", "ValueName", "ValueData"],
        # User A Profile
        [r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-123-456-789-1001", "ProfileImagePath", r"C:\Users\UserA"],
        # User B Profile (Still in registry mostly, sometimes deleted users leave traces)
        [r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-123-456-789-1002", "ProfileImagePath", r"C:\Users\UserB"]
    ]

    with open(reg_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(reg_data)
    print(f"Created: {reg_path}")

if __name__ == "__main__":
    create_mock_data()

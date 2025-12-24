import csv
import os

def write_csv(filename, headers, rows):
    with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

def generate_data():
    os.makedirs("kape_dummy", exist_ok=True)
    
    # 1. LNK Data (Simulate USB Access)
    # Target columns: SourceCreated, SourceModified, LocalPath, DriveType
    lnk_headers = ["SourceCreated", "SourceModified", "LocalPath", "DriveType"]
    lnk_rows = [
        # Normal System File
        {"SourceCreated": "2025-01-01 10:00:00", "SourceModified": "2025-01-01 10:00:00", "LocalPath": "C:\\Windows\\System32\\cmd.exe", "DriveType": "3"},
        # USB Exfiltration (Drive E:, DriveType 2=Removable)
        {"SourceCreated": "2025-06-15 14:00:00", "SourceModified": "2025-06-15 14:05:00", "LocalPath": "E:\\Confidential_Doc.pdf", "DriveType": "2"},
        # Another USB file (Drive F:, No DriveType but path logic should catch it)
        {"SourceCreated": "2025-06-16 09:00:00", "SourceModified": "2025-06-16 09:10:00", "LocalPath": "F:\\Secret_Design.cad", "DriveType": ""}
    ]
    write_csv("kape_dummy/Lnk_test.csv", lnk_headers, lnk_rows)
    print("Generated kape_dummy/Lnk_test.csv")

    # 2. Pandora Ghost Data (Simulate 'Deleted from Disk' but found on USB)
    pandora_headers = ["Risk_Tag", "Ghost_FileName", "ParentPath"]
    pandora_rows = [
        {"Risk_Tag": "CONFIRMED", "Ghost_FileName": "Confidential_Doc.pdf", "ParentPath": "C:\\Users\\User\\Documents"}
    ]
    write_csv("pandora_test.csv", pandora_headers, pandora_rows)
    print("Generated pandora_test.csv")

    # 3. SRUM Data (Simulate Network Exfiltration)
    # Target columns: AppId, BytesSent, InterfaceLuid
    srum_headers = ["AppId", "BytesSent", "InterfaceLuid"]
    srum_rows = [
        # Normal Traffic
        {"AppId": "chrome.exe", "BytesSent": "500000", "InterfaceLuid": "1"}, # ~0.5 MB
        # Heavy Traffic (Exfiltration Tool)
        {"AppId": "rclone.exe", "BytesSent": "104857600", "InterfaceLuid": "1"}, # 100 MB
        # Another Heavy
        {"AppId": "mega_cmd.exe", "BytesSent": "52428800", "InterfaceLuid": "1"}  # 50 MB
    ]
    write_csv("kape_dummy/Srum_test.csv", srum_headers, srum_rows)
    print("Generated kape_dummy/Srum_test.csv")

if __name__ == "__main__":
    generate_data()

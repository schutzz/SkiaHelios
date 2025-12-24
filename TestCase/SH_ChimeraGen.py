import os
import csv
from pathlib import Path
import random
import datetime

# ==========================================
#  SH_ChimeraGen.py v1.1
#  Mission: Generate "The Chimera's Shadow" Dataset
#  Fix: Added Prefetch artifacts for ChaosGrasp
# ==========================================

BASE_DIR = Path("Mock_Chimera_Output")
OS_INSTALL_DATE = "2024-01-01 10:00:00.0000000"

def write_csv(filepath, headers, rows):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"[+] Injected Artifact: {filepath.name}")

def main():
    if BASE_DIR.exists():
        import shutil
        shutil.rmtree(BASE_DIR)
    BASE_DIR.mkdir()

    print("[*] Constructing 'Chimera' Scenario...")
    print(f"    -> Target OS Install Date: {OS_INSTALL_DATE}")

    # 1. FileSystem ($MFT)
    mft_headers = [
        "EntryNumber", "FileSequenceNumber", "InUse", "FileName", "ParentPath", 
        "StandardInformation_Created", "FileName_Created", "FileSize", "Attributes"
    ]
    mft_rows = [
        ["100", "1", "True", "explorer.exe", "C:\\Windows", OS_INSTALL_DATE, OS_INSTALL_DATE, "4096000", "Archive"],
        ["500", "5", "True", "kernel32_patch.dll", "C:\\Windows\\System32", OS_INSTALL_DATE, OS_INSTALL_DATE, "102400", "System|Hidden"],
        ["600", "10", "True", "desktop.ini", "C:\\Users\\Public", "2025-12-24 12:00:00", "2025-12-24 12:00:00", "256", "Hidden"],
        ["600", "10", "True", "desktop.ini:Payload.bin", "C:\\Users\\Public", "2025-12-24 12:05:00", "2025-12-24 12:05:00", "999999", "Hidden"]
    ]
    write_csv(BASE_DIR / "FileSystem" / "20251224_MFTECmd_$MFT_Output.csv", mft_headers, mft_rows)

    # 2. FileSystem ($J / USN)
    usn_headers = ["EntryNumber", "FileSequenceNumber", "ParentEntryNumber", "UpdateReasons", "TimeStamp", "FileName", "ParentPath"]
    usn_rows = [
        ["900", "1", "50", "FileCreate", "2025-12-24 23:50:00", "Secret_Project.vhdx", "C:\\Temp"],
        ["900", "2", "50", "DataExtend|Close", "2025-12-24 23:55:00", "Secret_Project.vhdx", "C:\\Temp"],
        ["900", "3", "50", "FileDelete", "2025-12-25 00:10:00", "Secret_Project.vhdx", "C:\\Temp"],
        ["901", "1", "50", "FileCreate", "2025-12-25 00:11:00", "noise_001.tmp", "C:\\Temp"]
    ]
    write_csv(BASE_DIR / "FileSystem" / "20251224_MFTECmd_$J_Output.csv", usn_headers, usn_rows)

    # 3. LNK Files (LECmd)
    lnk_headers = [
        "SourceCreated", "SourceModified", "LocalPath", "DriveType", 
        "VolumeSerialNumber", "TargetIDAbsolutePath"
    ]
    lnk_rows = [
        ["2025-12-24 23:56:00", "2025-12-24 23:58:00", "E:\\Staging\\Confidential_Doc.pdf", "Fixed", "DEAD-BEEF", "E:\\Staging\\Confidential_Doc.pdf"],
        ["2025-12-24 23:50:00", "2025-12-24 23:50:00", "D:\\Secret_Project.vhdx", "Removable", "1234-5678", "D:\\Secret_Project.vhdx"]
    ]
    write_csv(BASE_DIR / "ProgramExecution" / "20251224_LECmd_Output.csv", lnk_headers, lnk_rows)

    # 4. Prefetch (PECmd) - [New] Added to trigger ChaosGrasp
    pf_headers = ["LastRun", "ExecutableName", "SourceFilename", "RunCount"]
    pf_rows = [
        ["2025-12-24 23:58:00", "ACROBAT.EXE", "C:\\Program Files\\Adobe\\Acrobat.exe", "1"],
        ["2025-12-24 10:00:00", "SVCHOST.EXE", "C:\\Windows\\System32\\svchost.exe", "50"]
    ]
    write_csv(BASE_DIR / "ProgramExecution" / "20251224_PECmd_Output.csv", pf_headers, pf_rows)

    # 5. Persistence (AION)
    autoruns_headers = ["Category", "Entry", "Signer", "Image Path", "Launch String"]
    autoruns_rows = [
        ["WMI", "__EventFilter:EvilFilter", "", "C:\\Windows\\System32\\wbem\\scrcons.exe", "CommandLineEventConsumer.Name=\"EvilConsumer\""],
        ["WMI", "EvilConsumer", "", "powershell.exe -enc ...", ""]
    ]
    write_csv(BASE_DIR / "Persistence" / "Autoruns_WMI.csv", autoruns_headers, autoruns_rows)

    print(f"\n[*] Chimera Generation Complete at: {BASE_DIR.resolve()}")

if __name__ == "__main__":
    main()
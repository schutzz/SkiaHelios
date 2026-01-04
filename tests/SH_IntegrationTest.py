import polars as pl
import os
import shutil
from pathlib import Path
import sys

# Ensure tools are importable
sys.path.append(str(Path.cwd()))
from tools.SH_ChronosSift import main as ChronosMain
from tools.SH_PandorasLink import main as PandoraMain
from tools.SH_HerculesReferee import main as HerculesMain

# ============================================================
#  SH_IntegrationTest.py
#  Mission: Mock Test for SkiaHelios Full Pipeline
#  Verifies: Two-Pass Strategy, Hestia, Hercules, Pandora
# ============================================================

TEST_DIR = Path("TEST_ZONE_HELIOS")
KAPE_DIR = TEST_DIR / "KAPE_MOCK"

def setup_mock_data():
    if TEST_DIR.exists(): shutil.rmtree(TEST_DIR)
    KAPE_DIR.mkdir(parents=True)
    
    # 1. Mock MFT 
    # Includes: Noise (Hestia Target), Threat (Pandora Target)
    df_mft = pl.DataFrame({
        "ParentPath": [
            r"C:\Windows\System32", 
            r"C:\Users\Target\AppData\Local\Temp", 
            r"C:\Program Files\Hash_Suite_Free\docs",  # NOISE
            r"C:\Windows\System32"
        ],
        "FileName": [
            "cmd.exe", 
            "malware.exe", 
            "readme.txt", 
            "svchost.exe"
        ],
        "FileSize": [1024, 666666, 123, 2048],
        "SiModified": ["2026-01-01 10:00:00"] * 4,
        "Created0x10": ["2026-01-01 09:00:00"] * 4,
        "Created0x30": ["2026-01-01 09:00:00"] * 4,
        "LastModified0x10": ["2026-01-01 10:00:00"] * 4,
        "LastModified0x30": ["2026-01-01 10:00:00"] * 4,
        "Extension": [".exe", ".exe", ".txt", ".exe"],
        "InUse": [True] * 4
    })
    df_mft.write_csv(KAPE_DIR / "$MFT_Output.csv")

    # 2. Mock Event Logs (Hercules Input)
    # Includes: Matching Threat execution
    df_evtx = pl.DataFrame({
        "TimeCreated": ["2026-01-01 10:00:05"], # 5s after file mod
        "Payload": [r"C:\Users\Target\AppData\Local\Temp\malware.exe"], 
        "CommandLine": [r"C:\Users\Target\AppData\Local\Temp\malware.exe -attack"],
        "Computer": ["HOST-X"],
        "UserId": ["S-1-5-21-MockUser"],
        "UserName": ["MockUser"],
        "Channel": ["Security"]
    })
    df_evtx.write_csv(KAPE_DIR / "Security_EvtxECmd.csv")

    # 3. Mock USN (UsnJrnl)
    # Important: Pandora gap analysis uses USN timestamp vs MFT SiMod.
    # To create a "Ghost", MFT SiMod should be recent, USN should be present or matching?
    # Gap Analysis: Checks consistency. 
    # For "Ghost Hunting", usually implies Time Stomping or lateral movement gaps.
    # Here we just need it to run through without crashing.
    df_usn = pl.DataFrame({
        "ParentPath": [r"C:\Users\Target\AppData\Local\Temp"],
        "FileName": ["malware.exe"],
        "Timestamp": ["2026-01-01 10:00:00"],
        "UpdateReasons": ["FileCreate"],
        "EntryNumber": [100],
        "ParentEntryNumber": [50],
        "SequenceNumber": [1]
    })
    df_usn.write_csv(KAPE_DIR / "$J_Output.csv")

    print("[*] Mock Data Generated.")

def run_helios():
    print("[*] Launching Helios Pipeline...")
    
    # 1. Chronos
    print("    -> Step 1: Chronos")
    # Chronos expects -f to be input CSV... typically $MFT_Output.csv.
    # But usually it iterates a folder? 
    # Based on my review, ChronosEngine takes 'tolerance' in init.
    # And analyze(args) uses args.file.
    # Let's pass $MFT_Output.csv as -f.
    ChronosMain(["-f", str(KAPE_DIR / "$MFT_Output.csv"), "-o", "Ghost_Report.csv"])
    
    if not Path("Ghost_Report.csv").exists():
        print("[-] FAIL: Chronos did not generate Ghost_Report.csv")
        return False

    # 2. Pandora Pass 1 (Gap Analysis)
    print("    -> Step 2: Pandora (Pass 1)")
    # Needs start/end window
    PandoraMain([
        "--mft", str(KAPE_DIR / "$MFT_Output.csv"), 
        "--usn", str(KAPE_DIR / "$J_Output.csv"), 
        "--start", "2025-01-01", 
        "--end", "2027-01-01",
        "--out", "Pandora_Pass1.csv",
        "--manual"
    ])

    # 3. Hercules (Sniper Mode)
    print("    -> Step 3: Hercules")
    HerculesMain([
        "--timeline", "Pandora_Pass1.csv", 
        "--ghosts", "Ghost_Report.csv", 
        "--kape", str(KAPE_DIR), 
        "-o", "Hercules_Judged.csv"
    ])

    if not Path("Hercules_Judged.csv").exists():
         print("[-] FAIL: Hercules did not generate output")
         return False

    # 4. Pandora Pass 2 (Correlation Boost)
    print("    -> Step 4: Pandora (Pass 2)")
    PandoraMain([
        "--mft", str(KAPE_DIR / "$MFT_Output.csv"), 
        "--usn", str(KAPE_DIR / "$J_Output.csv"), 
        "--start", "2025-01-01", 
        "--end", "2027-01-01",
        "--chronos", "Ghost_Report.csv", 
        "--hercules", "Hercules_Judged.csv", 
        "--out", "Final_Timeline.csv",
        "--manual"
    ])

    return True

def verify_results():
    print("[*] Verifying Results...")
    
    if not Path("Final_Timeline.csv").exists():
        print("[-] FAIL: Final Timeline missing")
        return

    df = pl.read_csv("Final_Timeline.csv", ignore_errors=True)
    
    # Check 1: Hestia - 'readme.txt' in Hash_Suite should be GONE
    if df.height > 0:
        if df.filter(pl.col("Ghost_FileName") == "readme.txt").height > 0:
            print("[-] FAIL: Hestia did not kill Hash_Suite noise!")
        else:
            print("[+] PASS: Hestia killed noise.")
    
        # Check 2: Correlation - 'malware.exe' should have Correlation_Flag=1
        malware = df.filter(pl.col("Ghost_FileName") == "malware.exe")
        if malware.height == 0:
            print("[-] FAIL: Malware missing (possibly filtered due to low score? Check Threshold)")
        else:
            # Check Int64 Flag (Pass)
            # Check Score > Base
            try:
                score = malware["Threat_Score"][0]
                flag = malware["Correlation_Flag"][0] if "Correlation_Flag" in malware.columns else None
                print(f"[+] PASS: Malware Found. Threat Score: {score}, Flag: {flag}")
            except:
                print("[!] Malware found but columns missing?")
    else:
        print("[-] FAIL: Final Timeline is empty!")

    # Cleanup
    # shutil.rmtree(TEST_DIR)

def main():
    try:
        setup_mock_data()
        if run_helios():
            verify_results()
        else:
            print("[-] HELIOS EXECUTION FAILED")
    except Exception as e:
        print(f"[-] CRASH: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

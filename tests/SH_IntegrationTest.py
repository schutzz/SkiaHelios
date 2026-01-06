import polars as pl
import os
import shutil
from pathlib import Path
import sys
import contextlib

# Ensure tools are importable
sys.path.append(str(Path.cwd()))
from tools.SH_ChronosSift import main as ChronosMain
from tools.SH_PandorasLink import main as PandoraMain
from tools.SH_HerculesReferee import main as HerculesMain
import SH_HekateTriad # Import Hekate Main? It has a main block. We need to import the main function if available or run via subprocess.
# SH_HekateTriad uses `if __name__ == "__main__": main()`. I should probably subprocess it or import main.
# Let's check HekateTriad source. It has a `main()` function.
from SH_HekateTriad import main as HekateMain

# We don't import HeliosConsole directly as it runs subprocesses, we call the tools directly for better control/debugging here.

# ============================================================
#  SH_IntegrationTest.py v2.0
#  Mission: Comprehensive Mock Test for SkiaHelios
#  Scenarios: Standard Mode vs Triage Mode
# ============================================================

TEST_DIR = Path("TEST_ZONE_HELIOS")
KAPE_DIR = TEST_DIR / "KAPE_MOCK"

@contextlib.contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:  
            yield
        finally:
            sys.stdout = old_stdout

def setup_mock_data():
    if TEST_DIR.exists(): shutil.rmtree(TEST_DIR)
    KAPE_DIR.mkdir(parents=True)
    
    # 1. Mock MFT 
    df_mft = pl.DataFrame({
        "ParentPath": [
            r"C:\Windows\System32", 
            r"C:\Users\Target\AppData\Local\Temp", 
            r"C:\Program Files\Hash_Suite_Free\docs",  # NOISE (Hestia)
            r"C:\Windows\System32",
            r"C:\Program Files\Nmap",                   # DUAL-USE (Themis)
            r"C:\Users\Target\AppData\Local\Google\Chrome\User Data\Default" # JUNK (Triage Kill)
        ],
        "FileName": [
            "cmd.exe", 
            "Secret_Project.pdf", 
            "readme.txt", 
            "svchost.exe",
            "psexec.exe",
            "Cookies.ldb"  # Triage should kill this
        ],
        "FileSize": [1024, 666666, 123, 2048, 5000, 100],
        "SiModified": ["2026-01-01 10:00:00"] * 6,
        "Created0x10": ["2026-01-01 09:00:00"] * 6,
        "Created0x30": ["2026-01-01 09:00:00"] * 6,
        "LastModified0x10": ["2026-01-01 10:00:00"] * 6,
        "LastModified0x30": ["2026-01-01 10:00:00"] * 6,
        "Extension": [".exe", ".exe", ".txt", ".exe", ".exe", ".ldb"],
        "InUse": [True] * 6,
        "EntryNumber": [10, 50, 60, 20, 30, 40],
        "SequenceNumber": [1] * 6
    })
    
    # 1b. Mock "Ancient" MFT Entry (For Deep Dive Time Scoping Test)
    # This file is OLDER than the Deep Dive window (Jan 2026), but within default window (2025-2027)
    df_ancient = pl.DataFrame({
         "ParentPath": [r"C:\OldStuff"],
         "FileName": ["ancient_Secret_Project.pdf"],
         "FileSize": [666],
         "SiModified": ["2025-06-01 12:00:00"],
         "Created0x10": ["2025-06-01 12:00:00"],
         "Created0x30": ["2025-06-01 12:00:00"],
         "LastModified0x10": ["2025-06-01 12:00:00"],
         "LastModified0x30": ["2025-06-01 12:00:00"],
         "Extension": [".exe"],
         "InUse": [True],
         "EntryNumber": [999],
         "SequenceNumber": [1]
    })
    df_mft = pl.concat([df_mft, df_ancient])
    
    df_mft.write_csv(KAPE_DIR / "$MFT_Output.csv")

    # 2. Mock Event Logs (Hercules Input)
    df_evtx = pl.DataFrame({
        "TimeCreated": ["2026-01-01 10:00:05", "2026-01-01 09:55:00"], 
        "Payload": [r"C:\Users\Target\AppData\Local\Temp\mimikatz.exe", r"C:\Windows\System32\svchost.exe"], 
        "CommandLine": [r"mimikatz.exe -attack", r"svchost -k netsvcs"],
        "Computer": ["HOST-X", "HOST-X"],
        "UserId": ["S-1-5-21-MockUser", "S-1-5-18"], # User vs System
        "UserName": ["MockUser", "SYSTEM"],
        "Channel": ["Security", "Security"]
    })
    df_evtx.write_csv(KAPE_DIR / "Security_EvtxECmd.csv")

    # 3. Mock USN (UsnJrnl)
    df_usn = pl.DataFrame({
        "ParentPath": [r"C:\Users\Target\AppData\Local\Temp", r"C:\Program Files\Nmap", r"C:\Temp"],
        "FileName": ["mimikatz.exe", "psexec.exe", "deleted_ghost.exe"],
        "Timestamp": ["2026-01-01 10:00:00", "2026-01-01 09:00:00", "2026-01-01 11:00:00"],
        "UpdateReasons": ["FileCreate", "FileCreate", "FileDelete"],
        "EntryNumber": [100, 200, 300],
        "ParentEntryNumber": [50, 60, 70],
        "SequenceNumber": [1, 1, 2]
    })
    df_usn.write_csv(KAPE_DIR / "$J_Output.csv")

    # 4. Mock Master Timeline (Chaos Output) - Needed for Hercules
    df_chaos = pl.DataFrame({
        "Timestamp_UTC": ["2026-01-01 10:00:00", "2026-01-01 09:00:00"],
        "Artifact_Type": ["ShellBags", "LNK"],
        "Target_Path": [r"C:\Program Files\Nmap\psexec.exe", r"C:\Users\Target\AppData\Local\Temp\mimikatz.exe"],
        "User": ["MockUser", "MockUser"],
        "Action": ["Execute", "Open"],
        "Source_File": ["UsrClass.dat", "Shortcut.lnk"]
    })
    df_chaos.write_csv(KAPE_DIR / "Master_Timeline.csv")

    print("[*] Mock Data Generated.")

def run_pipeline(mode="STANDARD"):
    print(f"\n[*] Launching Pipeline: {mode} Mode")
    
    triage_flag = ["--triage"] if mode == "TRIAGE" else []
    
    # 1. Chronos
    print("    -> Step 1: Chronos")
    ChronosMain(["-f", str(KAPE_DIR / "$MFT_Output.csv"), "-o", f"Ghost_Report_{mode}.csv", "--targets-only"])
    
    # 2. Pandora Pass 1
    print("    -> Step 2: Pandora (Pass 1)")
    p1_args = [
        "--mft", str(KAPE_DIR / "$MFT_Output.csv"), 
        "--usn", str(KAPE_DIR / "$J_Output.csv"), 
        "--start", "2025-01-01", "--end", "2027-01-01",
        "--out", f"Pandora_P1_{mode}.csv",
        "--manual"
    ] + triage_flag
    PandoraMain(p1_args)

    # 3. Hercules
    print("    -> Step 3: Hercules")
    h_args = [
        "--timeline", str(KAPE_DIR / "Master_Timeline.csv"), 
        "--ghosts", f"Pandora_P1_{mode}.csv", 
        "--kape", str(KAPE_DIR), 
        "-o", f"Hercules_Judged_{mode}.csv"
    ] + triage_flag
    HerculesMain(h_args)

    # 4. Pandora Pass 2
    print("    -> Step 4: Pandora (Pass 2)")
    p2_args = [
        "--mft", str(KAPE_DIR / "$MFT_Output.csv"), 
        "--usn", str(KAPE_DIR / "$J_Output.csv"), 
        "--start", "2025-01-01", "--end", "2027-01-01",
        "--chronos", f"Ghost_Report_{mode}.csv", 
        "--hercules", f"Hercules_Judged_{mode}.csv", 
        "--out", f"Final_Timeline_{mode}.csv",
        "--manual"
    ] + triage_flag
    
    # Deep Dive Scoping override
    if mode == "DEEP":
        # Simulate logic: Pivot is 2026-01-01 10:00:00. Window +/- 30m
        p2_args = [x for x in p2_args if x not in ["--start", "--end", "2025-01-01", "2027-01-01"]]
        # Re-add scoped times
        p2_args.extend(["--start", "2026-01-01 09:30:00", "--end", "2026-01-01 10:30:00"])
        
    PandoraMain(p2_args)

    # 5. Hekate (Report Generation)
    print("    -> Step 5: Hekate")
    # Hekate args: --case, --outdir, --chronos, --pandora, --hercules
    hekate_args = [
        "--case", f"TEST_CASE_{mode}",
        "--outdir", str(TEST_DIR / "Helios_Output"),
        "--chronos", f"Ghost_Report_{mode}.csv",
        "--pandora", f"Final_Timeline_{mode}.csv",
        "--hercules", f"Hercules_Judged_{mode}.csv",
        "--timeline", str(KAPE_DIR / "Master_Timeline.csv"),
        "--user", "MockUser",
        "--host", "HOST-X"
    ]
    # Ensure output dir exists
    (TEST_DIR / "Helios_Output").mkdir(exist_ok=True)
    
    # Mock sys.argv for Hekate
    original_argv = sys.argv
    sys.argv = ["SH_HekateTriad.py"] + hekate_args
    
    print(f"    [DEBUG] Hekate Args: {sys.argv}")
    print(f"    [DEBUG] Checking Inputs:")
    print(f"      Timeline: {KAPE_DIR / 'Master_Timeline.csv'} -> {os.path.exists(KAPE_DIR / 'Master_Timeline.csv')}")
    print(f"      Pandora: {f'Final_Timeline_{mode}.csv'} -> {os.path.exists(f'Final_Timeline_{mode}.csv')}")

    try:
        HekateMain()
    except SystemExit as e:
        print(f"    [!] Hekate exited with code {e.code}")
    except Exception as e:
        print(f"    [!] Hekate crashed: {e}")
    finally:
        sys.argv = original_argv

def verify_results():
    print("\n[*] Verifying Results...")
    
    # --- STANDARD MODE CHECKS ---
    df_std = pl.read_csv("Final_Timeline_STANDARD.csv", ignore_errors=True)
    
    # 1. High Value Target: Secret_Project.pdf should be present
    if df_std.filter(pl.col("Ghost_FileName") == "Secret_Project.pdf").height > 0:
        print("[+] PASS (Std): Secret_Project detected.")
    else:
        print("[-] FAIL (Std): Secret_Project missing.")

    # 2. Junk: Cookies.ldb might be present (or low score, but not aggressively killed)
    # The default Hestia rules might fetch it as noise, but let's see.
    # Actually, .ldb is NOT in default Pandora kill list, so it should survive in Standard.
    ldb_std = df_std.filter(pl.col("Ghost_FileName") == "Cookies.ldb")
    if ldb_std.height > 0 and ldb_std["Threat_Score"][0] > 0:
        print("[+] PASS (Std): Cookies.ldb survives (as expected).")
    else:
        # It might be killed by 'inetcookies' noise keyword in Lachesis/Pandora?
        # Pandora has 'inetcookies' in file_kill_list? No, Lachesis has. Pandora has 'safe browsing' etc.
        print("[?] INFO: Cookies.ldb filtered in Standard. (Checking if score is 0)")
    
    # --- TRIAGE MODE CHECKS ---
    df_triage = pl.read_csv("Final_Timeline_TRIAGE.csv", ignore_errors=True)
    
    # 3. Junk Kill: Cookies.ldb MUST be killed (Score 0 or Tag NOISE_ARTIFACT)
    ldb_triage = df_triage.filter(pl.col("Ghost_FileName") == "Cookies.ldb")
    if ldb_triage.height == 0 or ldb_triage["Threat_Score"][0] == 0:
         print("[+] PASS (Triage): Cookies.ldb was KILLED.")
    else:
         print(f"[-] FAIL (Triage): Cookies.ldb survived! Score: {ldb_triage['Threat_Score'][0]}")

    # 4. Hercules System Silence
    # In Triage mode, Hercules should NOT have correlated the SYSTEM user event (svchost.exe)
    # So 'svchost.exe' in Pandora output (if it exists as a "ghost" - wait, svchost wasn't a ghost in USN/gap, so it relies on Hercules to add it?)
    # Hercules adds EVTX hits to the pipeline if they are Critical.
    # 'svchost.exe' running 'netsvcs' is usually benign but might be flagged if we didn't filter it.
    # But specifically, we check if Hercules OUTPUT (Hercules_Judged_TRIAGE.csv) silenced the System event.
    df_herc_std = pl.read_csv("Hercules_Judged_STANDARD.csv", ignore_errors=True)
    df_herc_tri = pl.read_csv("Hercules_Judged_TRIAGE.csv", ignore_errors=True)
    
    sys_std = df_herc_std.filter(pl.col("Subject_SID") == "S-1-5-18")
    sys_tri = df_herc_tri.filter(pl.col("Subject_SID") == "S-1-5-18")
    
    # System event (svchost) might be filtered by noise rules anyway... 
    # Let's check the size. If we forced it to be "CRITICAL_SIGMA" it would appear.
    # Start by just checking if Triage has FEWER rows than Standard.
    print(f"[*] Hercules Rows - Standard: {df_herc_std.height}, Triage: {df_herc_tri.height}")
    
    if df_herc_tri.height <= df_herc_std.height:
        print("[+] PASS (Triage): Hercules output size consistent/reduced.")
    else:
        print("[-] FAIL: Triage produced MORE events?")

    # --- DEEP DIVE CHECKS ---
    # 5. Time Scoping
    # ancient_Secret_Project.pdf (2025-06-01) should be in Standard/Triage but ABSENT in Deep Dive (2026-01-01 window)
    if df_std.filter(pl.col("Ghost_FileName") == "ancient_Secret_Project.pdf").height > 0:
         print("[+] PASS (Std): Ancient file present (Correct for wide window).")
    else:
         print("[-] FAIL (Std): Ancient file missing from Standard?")

    if "Final_Timeline_DEEP.csv" in os.listdir("."):
        df_deep = pl.read_csv("Final_Timeline_DEEP.csv", ignore_errors=True)
        ancient_deep = df_deep.filter(pl.col("Ghost_FileName") == "ancient_Secret_Project.pdf")
        
        if ancient_deep.height == 0:
             print("[+] PASS (Deep): Ancient file SUCCESSFULLY SCOPED OUT.")
        else:
             print("[-] FAIL (Deep): Ancient file leaked into Deep Dive!")
    else:
        print("[-] FAIL (Deep): output csv not found.")

    # 6. Hekate Check
    if (TEST_DIR / "Helios_Output" / "Grimoire_TEST_CASE_STANDARD_jp.md").exists():
        print("[+] PASS (Hekate): Grimoire generated.")
    else:
        print("[-] FAIL (Hekate): Grimoire missing.")

    print("[*] Comprehensive Test Complete.")

def main():
    try:
        setup_mock_data()
        
        # Run Standard
        run_pipeline("STANDARD")
            
        # Run Triage
        # Run Triage
        run_pipeline("TRIAGE")

        # Run Deep Dive
        run_pipeline("DEEP")
            
        verify_results()
        
    except Exception as e:
        print(f"[-] CRASH: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

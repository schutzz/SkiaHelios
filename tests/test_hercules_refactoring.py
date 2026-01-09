import polars as pl
import sys
import os

# Adjust path to import tools
sys.path.append(os.getcwd())

from tools.SH_HerculesReferee import HerculesReferee

def run_test():
    print("=== Hercules Refactoring Integration Test ===")
    
    # Mock Data
    data = {
        "Timestamp_UTC": ["2025-01-01 00:00:00", "2025-01-01 00:01:00", "2025-01-01 00:02:00", "2025-01-01 00:03:00", "2025-01-01 00:04:00", "2025-01-01 00:05:00"],
        "FileName": ["shell.php", "sdelete.exe", "test.lnk", "beacon.exe", "net.exe", "normal.txt"],
        "ParentPath": ["C:\\Inetpub\\wwwroot\\", "C:\\Tools\\", "C:\\Users\\User\\Desktop", "C:\\Temp\\", "C:\\Windows\\System32\\", "C:\\Users\\User\\Documents"],
        "Target_Path": ["", "", "powershell.exe -enc S4cr3t", "192.168.1.100", "net user hacker /add", ""],
        "Message": ["", "", "", "Callback to C2", "User creation", ""],
        "Action": ["", "", "", "", "", ""]
    }
    
    df = pl.DataFrame(data)
    
    # Save mock files
    df.write_csv("test_timeline.csv")
    pl.DataFrame({"Ghost_FileName": []}).write_csv("test_ghosts.csv")
    
    # Initialize Referee
    referee = HerculesReferee(kape_dir=".", triage_mode=False)
    
    # Run Judge
    df_result = referee.judge(df)
    
    print("\n[Results]")
    df_result = df_result.select(["FileName", "Tag", "Threat_Score", "Judge_Verdict"])
    print(df_result)
    
    # Assertions
    # 1. WebShell
    row = df_result.filter(pl.col("FileName") == "shell.php")
    assert "WEBSHELL" in row[0, "Tag"], "WebShell detection failed"
    
    # 2. AntiForensics
    row = df_result.filter(pl.col("FileName") == "sdelete.exe")
    assert "ANTI_FORENSICS" in row[0, "Tag"], "AntiForensics detection failed"
    
    # 3. LNK
    row = df_result.filter(pl.col("FileName") == "test.lnk")
    assert "PS_ENCODED" in row[0, "Tag"], "LNK detection failed"
    
    # 4. Network/C2
    row = df_result.filter(pl.col("FileName") == "beacon.exe")
    assert "POTENTIAL_C2" in row[0, "Tag"], "Network/C2 detection failed"
    
    # 5. User Creation
    row = df_result.filter(pl.col("FileName") == "net.exe")
    assert "USER_CREATION" in row[0, "Tag"], "User Creation detection failed"

    print("\n✅ All Tests Passed!")

if __name__ == "__main__":
    run_test()

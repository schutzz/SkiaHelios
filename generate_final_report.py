import polars as pl
import datetime
from tools.SH_HekateWeaver import HekateWeaver

def generate_mock_report():
    print("[*] Generating Final Mock Report...")

    # 1. Mock Data Construction
    # (A) MFT & USN for Nemesis (Origin Trace)
    # Scenario: cmd.exe executed BadScript.bat
    df_mft = pl.DataFrame({
        "EntryNumber": ["888", "999"],
        "SequenceNumber": ["1", "10"],
        "FileName": ["BadScript.bat", "LiveMalware.exe"],
        "ParentPath": ["C:\\Temp", "C:\\Temp"],
        "si_dt": [datetime.datetime(2025, 1, 1, 15, 59, 59), datetime.datetime(2025, 1, 1, 10, 0, 0)],
        "Reason": ["FILE_CREATE", "FILE_CREATE"],
        "si_sid": ["S-1-5-21-MockUser", "S-1-5-21-MockUser"],
        "Ghost_FileName": [None, None],
        "Chaos_FileName": [None, None]
    }, schema={"EntryNumber": pl.Utf8, "SequenceNumber": pl.Utf8, "FileName": pl.Utf8, "ParentPath": pl.Utf8, 
               "si_dt": pl.Datetime, "Reason": pl.Utf8, "si_sid": pl.Utf8, "Ghost_FileName": pl.Utf8, "Chaos_FileName": pl.Utf8})
    
    df_usn = pl.DataFrame({
        "EntryNumber": ["888"],
        "SequenceNumber": ["1"],
        "FileName": ["BadScript.bat"],
        "Timestamp_UTC": ["2025-01-01 16:00:00.000"],
        "Reason": "FILE_CREATE",
        "Ghost_FileName": [None],
        "Chaos_FileName": [None],
        "ParentPath": ["C:\\Temp"]
    }, schema={"EntryNumber": pl.Utf8, "SequenceNumber": pl.Utf8, "FileName": pl.Utf8, "Timestamp_UTC": pl.Utf8, 
               "Reason": pl.Utf8, "Ghost_FileName": pl.Utf8, "Chaos_FileName": pl.Utf8, "ParentPath": pl.Utf8})

    # (B) Sphinx (EventLog) - The Container Event
    # cmd.exe execution
    df_sphinx = pl.DataFrame({
        "TimeCreated": ["2025-01-01T16:00:00"],
        "Sphinx_Tags": ["ATTACK"],
        "Original_Snippet": ["Process Creation: cmd.exe /c start C:\\Temp\\BadScript.bat"],
        "Decoded_Hint": ["cmd.exe /c start C:\\Temp\\BadScript.bat"],
        "User_ID": ["S-1-5-21-MockUser"]
    })

    # (C) Network (C2)
    df_network = pl.DataFrame({
        "Timestamp_UTC": ["2025-01-01T16:05:00"],
        "Tag": ["C2"],
        "Action": ["Connect"],
        "Target_Path": ["http://malicious-c2.com/beacon"],
        "User_ID": ["S-1-5-21-MockUser"]
    })

    # (D) AION (Persistence)
    df_aion = pl.DataFrame({
        "Last_Executed_Time": ["2025-01-01T16:10:00"],
        "AION_Tags": ["WANTED"],
        "Target_FileName": ["UpdateService.exe"],
        "Full_Path": ["C:\\Windows\\Temp\\UpdateService.exe"],
        "Entry_Location": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "User": ["MockUser"]
    })
    
    # (E) Pandora (Deleted Ghosts)
    df_pandora = pl.DataFrame({
        "Ghost_FileName": ["evidence_wipe.log"],
        "ParentPath": ["C:\\Temp"],
        "Ghost_Time_Hint": ["2025-01-01T16:30:00"],
        "Source": ["USN Journal"],
        "User": ["System"]
    })

    # (F) Chronos (Timestomp)
    # Empty for now or simple
    df_chronos = pl.DataFrame({"FileName": []}, schema={"FileName": pl.Utf8})

    dfs = {
        "Chronos": df_mft, "Pandora": df_usn, # Mapped correctly for NemesisTracer usage
        "Sphinx": df_sphinx, "Network": df_network, 
        "AION": df_aion, 
        "Hercules": None 
    }

    # 2. HekateWeaver Instantiation
    # Mock txt config
    txt_config = {
        "title": "Incident Investigation Report (Mock Final)",
        "coc_header": "Evidence & Case Info",
        "investigator": "Antigravity Agent",
        "h1_exec": "1. Executive Summary",
        "h1_time": "2. Investigative Timeline",
        "h1_tech": "3. Technical Findings",
        "h1_rec": "4. Conclusion & Recommendations",
        "h1_app": "5. Appendix",
        "cats": {"INIT": "Initial Access", "DROP": "File Drop", "C2": "C2 Communication", "PERSIST": "Persistence", "ANTI": "Anti-Forensics"}
    }
    
    # Bypass file loading by passing None, then inject dfs
    weaver = HekateWeaver(timeline_csv=None, lang="jp", case_name="Operation Mock Final")
    weaver.dfs = dfs # Inject manual DFs
    weaver.txt = txt_config # Override text config
    
    # 3. Generate
    out_path = "Grimoire_Final.md"
    weaver.generate_report(out_path)
    print(f"[+] Report generated at: {out_path}")

if __name__ == "__main__":
    generate_mock_report()

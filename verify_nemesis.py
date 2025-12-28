import polars as pl
import re

# Mock definitions matching SH_HekateWeaver.py v15.24 (Nemesis Unleashed)
class NemesisTracer:
    def __init__(self, df_mft, df_usn):
        self.df_mft = df_mft
        self.df_usn = df_usn

    def trace_lifecycle(self, attack_seeds):
        if not attack_seeds: return []
        
        # 1. 文字列検索パターンの構築
        pattern = "|".join([re.escape(s) for s in attack_seeds if len(s) > 3])
        if not pattern: return []

        lifecycle_events = []
        target_file_ids = set()

        # --- Phase A: Seed Matching (String Base) ---
        if self.df_mft is not None:
            try:
                mft_hits = self.df_mft.filter(
                    pl.col("FileName").str.contains(f"(?i){pattern}")
                )
                for row in mft_hits.iter_rows(named=True):
                    lifecycle_events.append(self._to_event(row, "MFT", "Creation/Existence"))
                    fid = row.get("EntryNumber")
                    if fid: target_file_ids.add(str(fid))
            except: pass

        if self.df_usn is not None:
            try:
                usn_hits = self.df_usn.filter(
                    pl.col("Ghost_FileName").str.contains(f"(?i){pattern}") |
                    pl.col("ParentPath").str.contains(f"(?i){pattern}")
                )
                for row in usn_hits.iter_rows(named=True):
                    lifecycle_events.append(self._to_event(row, "USN", "Lifecycle Change"))
                    fid = row.get("EntryNumber")
                    if fid: target_file_ids.add(str(fid))
            except: pass

        # --- Phase B: ID Chaining ---
        print(f"[Debug] Collected Target IDs: {target_file_ids}")
        
        if target_file_ids:
            id_list = list(target_file_ids)
            
            # B-1. USN Scan
            if self.df_usn is not None:
                 try:
                    chain_hits = self.df_usn.filter(
                        pl.col("EntryNumber").cast(pl.Utf8).is_in(id_list)
                    )
                    for row in chain_hits.iter_rows(named=True):
                        lifecycle_events.append(self._to_event(row, "USN", "Lifecycle Change (ID Chain)"))
                 except: pass

            # B-2. MFT Scan (New Feature)
            if self.df_mft is not None:
                 try:
                    mft_chain = self.df_mft.filter(
                        pl.col("EntryNumber").cast(pl.Utf8).is_in(id_list)
                    )
                    for row in mft_chain.iter_rows(named=True):
                         lifecycle_events.append(self._to_event(row, "MFT", "Chain Recovery"))
                 except: pass

        return lifecycle_events

    def _to_event(self, row, source_type, category):
        fname = row.get("FileName") or row.get("Ghost_FileName")
        reason = str(row.get("UpdateReason") or "Unknown").upper() 
        
        action_map = {
            "FILE_CREATE": "File Created (Birth)",
            "FILE_DELETE": "File Deleted (Termination)",
            "RENAME_OLD_NAME": "Renamed FROM (Identity Change)",
            "RENAME_NEW_NAME": "Renamed TO (Identity Masking)",
            "DATA_EXTEND": "File Modified/Appended"
        }
        specific_action = "Lifecycle Activity"
        for r_key, r_desc in action_map.items():
            if r_key in reason:
                specific_action = r_desc
                break

        return {
            "Time": row.get("si_dt") or row.get("Ghost_Time_Hint"),
            "Source": f"Nemesis ({source_type})",
            "Summary": f"Lifecycle Trace [{specific_action}]: {fname}",
            "Detail": f"Full Reason: {reason}\nPath: {row.get('ParentPath')}",
            "Criticality": 95
        }

def main():
    print("[*] Setting up Mock Data (Scenario: Rename -> Hidden Existence in MFT)...")
    
    # 1. MFT Mock Data 
    # Scenario: 
    # - ID 300: "System_Config.dat" exists on disk (MFT).
    # - BUT we don't know it's "malicious" yet.
    # - WE ONLY KNOW seed "AttackerTool.exe".
    mft_data = {
        "FileName": ["System_Config.dat"], 
        "ParentPath": ["C:\\Windows\\Temp"],
        "si_dt": ["2025-12-28 12:00:00"],
        "EntryNumber": [300]
    }
    df_mft = pl.DataFrame(mft_data)

    # 2. USN Mock Data 
    # Connects "AttackerTool.exe" (Seed) -> "System_Config.dat" (ID 300)
    usn_data = {
        "Ghost_FileName": [
            "AttackerTool.exe",   # Seed Match!
            "AttackerTool.exe",   # Rename Old
            "System_Config.dat"   # Rename New (ID 300)
        ],
        "ParentPath": ["C:\\Windows\\Temp", "C:\\Windows\\Temp", "C:\\Windows\\Temp"],
        "UpdateReason": [
            "FILE_CREATE", 
            "RENAME_OLD_NAME", 
            "RENAME_NEW_NAME"
        ],
        "Ghost_Time_Hint": [
            "11:50:00", "11:55:00", "11:55:00"
        ],
        "EntryNumber": [300, 300, 300]
    }
    df_usn = pl.DataFrame(usn_data)

    tracer = NemesisTracer(df_mft, df_usn)
    
    seed = ["AttackerTool.exe"] # We only look for this
    print(f"[*] Running Trace_Lifecycle for seed: {seed}")
    results = tracer.trace_lifecycle(seed)
    
    print(f"\n[+] Total hits: {len(results)}")
    
    # Verify MFT Recovery
    mft_recoveries = [r for r in results if "Chain Recovery" in r['Summary'] or "System_Config.dat" in r['Summary']]
    
    found_names = [ev['Summary'].split(': ')[-1] for ev in results]
    print(f"[Analysis] Found Filenames: {set(found_names)}")
    
    if "System_Config.dat" in found_names:
        print("[SUCCESS] Found current on-disk artifact 'System_Config.dat' via ID Chain!")
    else:
        print("[FAILURE] Failed to link back to MFT artifact.")

if __name__ == "__main__":
    main()

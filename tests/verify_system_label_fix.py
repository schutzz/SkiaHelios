
import polars as pl
import sys

def verify_fix():
    print("[*] Verifying System Artifact Label Fix Logic")

    # Mock Data
    data = {
        "FileName": ["system", "system", "system", "explorer.exe", "system"],
        "Event_Summary": [
            "Logon|User:Admin|EID:4625", 
            "Process Created|EID:1234", 
            "Something|EID:4720", 
            "Logon|EID:4625",
            "Rollback: Some info"
        ],
        "Source": ["EventLog", "EventLog", "EventLog", "EventLog", "EventLog"],
        "Message": ["", "", "", "", ""],
        "Action": ["", "", "", "", ""]
    }
    
    df = pl.DataFrame(data)
    # pl.Config.set_tbl_formatting("ASCII_MARKDOWN") # Optional if needed
    # print("Original DataFrame:")
    # print(df)

    # --- Logic from SH_HerculesReferee.py ---
    # Simplified adaptation of the logic found in judge()
    
    src_col = "Event_Summary"
    
    # Define EID Mapping (Same as in SH_HerculesReferee)
    eid_map = {
        "4624": "Logon Success",
        "4625": "AUTH_FAILURE",
        "4648": "Explicit Creds Logon",
        "4720": "User Created",
        "4726": "User Deleted",
        "4728": "Member Added (Global)",
        "4732": "Member Added (Local)",
        "4756": "Member Added (Universal)",
        "7045": "Service Installed",
        "4104": "PowerShell Script",
        "2004": "Rule Match"
    }

    if "FileName" in df.columns and src_col in df.columns:
        # Create an expression for EID extraction
        eid_expr = pl.col(src_col).str.extract(r"(?i)EID:(\d+)", 1)
        
        # Create the replacement logic
        base_replacement = pl.col(src_col).str.split("|").list.get(0).str.strip_chars() + " (EventLog)"
        
        # Start with base replacement
        refined_replacement = base_replacement
        
        # Apply EID mappings dynamically
        for eid, name in eid_map.items():
            refined_replacement = (
                pl.when(eid_expr == eid)
                .then(pl.lit(f"{name} (EID:{eid})"))
                .otherwise(refined_replacement)
            )
        
        # specific handling for Time Rollback
        refined_replacement = (
                pl.when(pl.col(src_col).str.contains(r"(?i)Rollback:"))
                .then(pl.lit("System Time Change"))
                .otherwise(refined_replacement)
        )

        df = df.with_columns(
            pl.when(pl.col("FileName").str.to_lowercase().str.strip_chars() == "system")
              .then(refined_replacement)
              .otherwise(pl.col("FileName"))
              .alias("FileName")
        )
    
    # ----------------------------------------

    print("\nProcessed DataFrame (verification steps below):")
    # print(df)

    # Verification
    # Row 0: system, EID:4625 -> "AUTH_FAILURE (EID:4625)"
    row0 = df.item(0, "FileName")
    if row0 != "AUTH_FAILURE (EID:4625)":
        print(f"[FAILED] Row 0 expected 'AUTH_FAILURE (EID:4625)', got '{row0}'")
    else:
        print("[PASS] Row 0 Correct")

    # Row 1: system, EID:1234 (not in map) -> "Process Created (EventLog)"
    row1 = df.item(1, "FileName")
    if row1 != "Process Created (EventLog)":
        print(f"[FAILED] Row 1 expected 'Process Created (EventLog)', got '{row1}'")
    else:
        print("[PASS] Row 1 Correct")

    # Row 2: system, EID:4720 -> "User Created (EID:4720)"
    row2 = df.item(2, "FileName")
    if row2 != "User Created (EID:4720)":
        print(f"[FAILED] Row 2 expected 'User Created (EID:4720)', got '{row2}'")
    else:
        print("[PASS] Row 2 Correct")

    # Row 3: explorer.exe, EID:4625 -> "explorer.exe" (Should not change)
    row3 = df.item(3, "FileName")
    if row3 != "explorer.exe":
        print(f"[FAILED] Row 3 expected 'explorer.exe', got '{row3}'")
    else:
        print("[PASS] Row 3 Correct")
        
    # Row 4: system, Rollback -> "System Time Change"
    row4 = df.item(4, "FileName")
    if row4 != "System Time Change":
        print(f"[FAILED] Row 4 expected 'System Time Change', got '{row4}'")
    else:
        print("[PASS] Row 4 Correct")

if __name__ == "__main__":
    verify_fix()

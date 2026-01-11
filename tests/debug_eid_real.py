
import polars as pl

def debug_eid_fix():
    print("[*] Debugging EID Fix with Real-world Data")

    # Mock Data based on Master_Timeline.csv (Target_Path instead of FileName)
    data = {
        "Target_Path": ["system", "System", "system ", "explorer.exe"],
        "Action": [
            "**EID:4625 | Target: IT104-3\\Student**", 
            "EID:4625 | Target: IT104-3\\Student", 
            "Logon Failure | EID:4625", 
            "Logon|EID:4625"
        ],
        "Source": ["EventLog", "EventLog", "EventLog", "EventLog"],
        "Message": ["", "", "", ""]
    }
    
    df = pl.DataFrame(data)
    
    # [Fix] Standardize FileName column if missing
    if "FileName" not in df.columns and "Target_Path" in df.columns:
        print("[*] Simulating Fix: Aliasing Target_Path -> FileName")
        df = df.with_columns(pl.col("Target_Path").alias("FileName"))

    src_col = "Action" # In Master_Timeline, it's Action
    
    # Existing Logic Copy-Paste (simplified)
    eid_map = {"4625": "AUTH_FAILURE"}
    
    eid_expr = pl.col(src_col).str.extract(r"(?i)EID:(\d+)", 1)
    
    base_replacement = pl.col(src_col).str.split("|").list.get(0).str.strip_chars() + " (EventLog)"
    refined_replacement = base_replacement
    
    for eid, name in eid_map.items():
        refined_replacement = (
            pl.when(eid_expr == eid)
            .then(pl.lit(f"{name} (EID:{eid})"))
            .otherwise(refined_replacement)
        )
        
    df = df.with_columns(
        pl.when(pl.col("FileName").str.to_lowercase().str.strip_chars() == "system")
          .then(refined_replacement)
          .otherwise(pl.col("FileName"))
          .alias("FileName")
    )
    
    # print(df)
    
    # Check results
    results = df.select("FileName").to_series().to_list()
    print("Results:", results)
    
    expected = "AUTH_FAILURE (EID:4625)"
    if results[0] == expected:
        print("[PASS] Row 0 Renamed")
    else:
        print(f"[FAIL] Row 0: '{results[0]}' != '{expected}'")

if __name__ == "__main__":
    debug_eid_fix()

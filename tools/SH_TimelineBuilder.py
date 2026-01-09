import polars as pl
import argparse
from pathlib import Path
from datetime import datetime

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kape", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    
    events = []
    
    # 1. MFT Processing
    mft_files = list(Path(args.kape).rglob("*$MFT_Output.csv"))
    if mft_files:
        print(f"[*] Processing MFT: {mft_files[0]}")
        try:
            df = pl.read_csv(mft_files[0], ignore_errors=True, infer_schema_length=0)
            
            # Select relevant columns
            cols = df.columns
            t_col = next((c for c in ["StandardInformation_Created", "Created0x10"] if c in cols), None)
            n_col = next((c for c in ["FileName", "Name"] if c in cols), "FileName")
            p_col = next((c for c in ["ParentPath", "ParentFolder"] if c in cols), "ParentPath")
            
            if t_col:
                df = df.filter(pl.col(t_col).str.len_chars() > 10).select([
                    pl.col(t_col).alias("Timestamp_UTC"),
                    pl.lit("MFT").alias("Source"),
                    pl.lit("FILE").alias("Category"),
                    pl.format("File Created: {} ({})", pl.col(n_col), pl.col(p_col)).alias("Summary"),
                    pl.lit("System").alias("User"),
                    pl.lit(0).alias("Criticality"),
                    pl.lit("").alias("Tag"),
                    pl.col(n_col).alias("Keywords"),
                    pl.col(n_col).alias("FileName"),
                    pl.col(p_col).alias("ParentPath")
                ])
                events.append(df)
        except Exception as e: print(f"[!] MFT Error: {e}")

    # 2. Evtx Processing
    evtx_files = list(Path(args.kape).rglob("*EvtxECmd*.csv"))
    if evtx_files:
        print(f"[*] Processing EVTX: {evtx_files[0]}")
        try:
            df = pl.read_csv(evtx_files[0], ignore_errors=True, infer_schema_length=0)
            
            cols = df.columns
            t_col = next((c for c in ["TimeCreated", "Timestamp_UTC"] if c in cols), None)
            eid_col = next((c for c in ["EventId", "Id"] if c in cols), "EventId")
            msg_col = next((c for c in ["Message", "Payload"] if c in cols), "Message") # Simplify
            
            if t_col:
                reduced_df = df.select([
                    pl.col(t_col).alias("Timestamp_UTC"),
                    pl.lit("EventLog").alias("Source"),
                    pl.lit("LOG").alias("Category"),
                    pl.format("EID:{}", pl.col(eid_col)).alias("Summary"), # Simplified
                    pl.lit("System").alias("User"),
                    pl.lit(0).alias("Criticality"),
                    pl.lit("").alias("Tag"),
                    pl.lit("").alias("Keywords"),
                    pl.lit("").alias("FileName"),
                    pl.lit("").alias("ParentPath")
                ])
                # Append full message if needed in separate pass or simplify
                events.append(reduced_df)
        except Exception as e: print(f"[!] EVTX Error: {e}")

    if events:
        final_df = pl.concat(events, how="diagonal")
        final_df = final_df.sort("Timestamp_UTC")
        print(f"[*] Writing Master Timeline ({final_df.height} events)...")
        final_df.write_csv(args.out)
    else:
        print("[!] No events found.")

if __name__ == "__main__":
    main()

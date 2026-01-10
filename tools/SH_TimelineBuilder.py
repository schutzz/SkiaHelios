import polars as pl
import argparse
import sys
import os
import re
from pathlib import Path
from datetime import datetime

# YAML Loading Logic (with Fallback)
def load_rules(path):
    rules = []
    # Try generic PyYAML first
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            y = yaml.safe_load(f)
            return y.get("threat_signatures", [])
    except ImportError:
        pass # Fallback to manual parser
    except Exception as e:
        print(f"[!] YAML Error: {e}")
        return []

    # Fallback Manual Parser
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        blocks = content.split("- name:")
        for b in blocks[1:]: # Skip preamble
            rule = {}
            lines = b.splitlines()
            # Name is the first line usually
            rule["name"] = lines[0].strip().strip('"')
            
            # Simple regex for other fields
            for key in ["tag", "score", "target", "pattern"]:
                m = re.search(r'^\s*' + key + r':\s*(?:"(.*)"|(.*))', b, re.MULTILINE)
                if m:
                    val = m.group(1) or m.group(2)
                    rule[key] = val.strip()
            
            if "pattern" in rule:
                 rules.append(rule)
    except Exception as e:
        print(f"[!] Parser Error: {e}")
    
    return rules

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kape", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    
    events = []
    
    # 1. MFT
    mft_files = list(Path(args.kape).rglob("*$MFT_Output.csv"))
    if mft_files:
        print(f"[*] Processing MFT: {mft_files[0]}")
        try:
            df = pl.read_csv(mft_files[0], ignore_errors=True, infer_schema_length=0)
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
                    pl.lit(0).alias("Threat_Score"),
                    pl.lit("").alias("Tag"),
                    pl.col(n_col).alias("Keywords"),
                    pl.col(n_col).alias("FileName"),
                    pl.col(p_col).alias("ParentPath"),
                    pl.lit("FileCreate").alias("Action")
                ])
                events.append(df)
        except Exception as e: print(f"[!] MFT Error: {e}")

    # 2. EVTX
    evtx_files = list(Path(args.kape).rglob("*EvtxECmd*.csv"))
    if evtx_files:
        print(f"[*] Processing EVTX: {evtx_files[0]}")
        try:
            df = pl.read_csv(evtx_files[0], ignore_errors=True, infer_schema_length=0)
            cols = df.columns
            t_col = next((c for c in ["TimeCreated", "Timestamp_UTC"] if c in cols), None)
            eid_col = next((c for c in ["EventId", "Id"] if c in cols), "EventId")
            
            if t_col:
                reduced_df = df.select([
                    pl.col(t_col).alias("Timestamp_UTC"),
                    pl.lit("EventLog").alias("Source"),
                    pl.lit("LOG").alias("Category"),
                    pl.format("EID:{}", pl.col(eid_col)).alias("Summary"),
                    pl.lit("System").alias("User"),
                    pl.lit(0).alias("Threat_Score"),
                    pl.lit("").alias("Tag"),
                    pl.lit("").alias("Keywords"),
                    pl.lit("").alias("FileName"),
                    pl.lit("").alias("ParentPath"),
                    pl.lit("Log").alias("Action")
                ])
                events.append(reduced_df)
        except Exception as e: print(f"[!] EVTX Error: {e}")

    # 3. USN
    usn_files = list(Path(args.kape).rglob("*$J_Output.csv"))
    if usn_files:
        print(f"[*] Processing USN Journal: {usn_files[0]}")
        try:
            df = pl.read_csv(usn_files[0], ignore_errors=True, infer_schema_length=0)
            cols = df.columns
            t_col = next((c for c in ["UpdateTimestamp", "Timestamp"] if c in cols), None)
            n_col = next((c for c in ["Name", "FileName"] if c in cols), "Name")
            reason_col = next((c for c in ["UpdateReasons", "Reason"] if c in cols), None)
            
            if t_col:
                if reason_col:
                    df = df.filter(pl.col(reason_col).str.contains("(?i)(FileCreate|Rename|Delete)"))
                
                summary_expr = pl.format("USN: {} ({})", pl.col(n_col), pl.col(reason_col)) if reason_col else pl.format("USN: {}", pl.col(n_col))
                action_expr = pl.col(reason_col).alias("Action") if reason_col else pl.lit("USN").alias("Action")

                reduced_df = df.select([
                    pl.col(t_col).alias("Timestamp_UTC"),
                    pl.lit("USN").alias("Source"),
                    pl.lit("FILE").alias("Category"),
                    summary_expr.alias("Summary"),
                    pl.lit("System").alias("User"),
                    pl.lit(0).alias("Threat_Score"),
                    pl.lit("").alias("Tag"),
                    pl.col(n_col).alias("Keywords"),
                    pl.col(n_col).alias("FileName"),
                    pl.lit("").alias("ParentPath"),
                    action_expr
                ])
                events.append(reduced_df)
                print(f"    + Added {reduced_df.height} USN events")
        except Exception as e: print(f"[!] USN Error: {e}")

    if events:
        final_df = pl.concat(events, how="diagonal")
        final_df = final_df.sort("Timestamp_UTC")
        
        # Add Full_Path for rules
        if "ParentPath" in final_df.columns and "FileName" in final_df.columns:
            final_df = final_df.with_columns(
                (pl.col("ParentPath").fill_null("") + "\\" + pl.col("FileName").fill_null("")).alias("Full_Path")
            )
            final_df = final_df.with_columns(pl.col("Full_Path").alias("Target_Path"))

        # Scoring Logic
        rules = load_rules("rules/triage_rules.yaml")
        if rules:
            print(f"[*] Applying {len(rules)} scoring rules...")
            scores = pl.col("Threat_Score")
            tags = pl.col("Tag")
            
            for i, r in enumerate(rules):
                print(f"DEBUG: Rule {i+1}/{len(rules)}: {r.get('name', 'Unknown')}", flush=True)
                try:
                    pat = r.get("pattern")
                    target = r.get("target", "FileName")
                    score = int(r.get("score", 0) or 0)
                    tag = r.get("tag", "ALERT")
                    
                    if not pat or target not in final_df.columns: continue
                    
                    # Apply Mask Eagerly
                    mask = pl.col(target).str.contains(pat)
                    
                    final_df = final_df.with_columns([
                        pl.when(mask).then(
                            pl.max_horizontal(pl.col("Threat_Score"), pl.lit(score))
                        ).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
                        
                        pl.when(mask).then(
                            pl.format("{},{}", pl.col("Tag"), pl.lit(tag)).str.strip_chars(",")
                        ).otherwise(pl.col("Tag")).alias("Tag")
                    ])
                    
                except: pass
            
            # Count Hits
            hits = final_df.filter(pl.col("Threat_Score") > 0).height
            print(f"    + {hits} events scored > 0")

        print(f"[*] Writing Master Timeline ({final_df.height} events)...")
        final_df.write_csv(args.out)
    else:
        print("[!] No events found.")

if __name__ == "__main__":
    main()

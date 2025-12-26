import polars as pl
import argparse
from pathlib import Path
import sys
import re
from datetime import datetime, timedelta

# ============================================================
#  SH_HerculesReferee v2.0 [Sniper Edition]
#  Mission: Resolve Identities, Audit Privileges & Hunt Ghosts
#  Updated: Integrated with Pandora's Ghost Intel for Sniper Scans.
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HERCULES --   [ The Sniper v2.0 ]
      | | | | | |    "I see what you deleted."
    """)

class HerculesReferee:
    def __init__(self, timeline_csv, kape_dir, pandora_csv=None):
        self.timeline_path = Path(timeline_csv)
        self.kape_dir = Path(kape_dir)
        self.pandora_path = Path(pandora_csv) if pandora_csv else None
        
        self.sid_to_user = {} 
        self.user_to_sid = {}
        self.deleted_users = set()
        
        # Sniper Intel
        self.ghost_intel = [] # List of {time, filename, risk_tag}

    def _register(self, sid, user, source="Unknown"):
        if not sid or not user: return
        sid = str(sid).strip()
        user = str(user).strip()
        
        if not sid.startswith("S-1-"): return
        if user.lower() in ["n/a", "none", "null", "", "system", "local service", "network service"]: return
        if user.lower().endswith(".csv"): return 

        if sid not in self.sid_to_user:
            # print(f"[+] Identity Link Found ({source}): {user} <==> {sid}")
            self.sid_to_user[sid] = user
        
        u_key = user.lower()
        if u_key not in self.user_to_sid:
            self.user_to_sid[u_key] = sid

    def _load_registry_users(self):
        print("[*] Phase 1: Scanning KAPE Output for Identity Mappings...")
        reg_files = list(self.kape_dir.rglob("*.csv"))
        
        for reg in reg_files:
            try:
                df = pl.read_csv(reg, ignore_errors=True, infer_schema_length=0)
                cols = df.columns
                key_col = next((c for c in cols if "Key" in c), None)
                val_data_col = next((c for c in cols if "ValueData" in c or "Data" in c), None)
                
                if not key_col or not val_data_col: continue

                targets = df.filter(
                    pl.col(key_col).str.contains(r"S-1-5-21-") & 
                    pl.col(key_col).str.contains(r"ProfileList")
                )
                
                if not targets.is_empty():
                    # print(f"   > Digesting: {reg.name}")
                    for row in targets.iter_rows(named=True):
                        full_key = str(row[key_col])
                        full_path = str(row[val_data_col])
                        m_sid = re.search(r'(S-1-5-21-\d+-\d+-\d+-\d+)', full_key)
                        
                        if m_sid and "Users" in full_path:
                            sid = m_sid.group(1)
                            user = full_path.replace("\\", "/").split("/")[-1]
                            self._register(sid, user, f"Registry:{reg.name}")
            except: pass

    def _load_pandora_ghosts(self):
        if not self.pandora_path or not self.pandora_path.exists():
            print("[!] Pandora Report not found. Skipping Sniper Mode.")
            return

        print(f"[*] Phase 1.5: Loading Pandora Intel from {self.pandora_path.name}...")
        try:
            df = pl.read_csv(self.pandora_path, ignore_errors=True)
            
            # Filter for High Risk Ghosts only
            targets = df.filter(
                (pl.col("Risk_Tag").str.contains(r"LNK_DEL|EXEC|RISK_EXT")) &
                (pl.col("Ghost_Time_Hint").is_not_null())
            )
            
            print(f"   > Identified {targets.height} High-Risk Ghosts for Sniper Scan.")
            
            for row in targets.iter_rows(named=True):
                try:
                    ts_str = str(row["Ghost_Time_Hint"])
                    # Simple robust parsing attempt
                    ts = None
                    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"]:
                        try:
                            ts = datetime.strptime(ts_str.split('.')[0], "%Y-%m-%d %H:%M:%S") # Strip sub-seconds for ease
                            break
                        except: pass
                    
                    if ts:
                        self.ghost_intel.append({
                            "ts": ts,
                            "filename": str(row["Ghost_FileName"]),
                            "tag": str(row["Risk_Tag"])
                        })
                except Exception as e:
                    pass
        except Exception as e:
            print(f"[!] Failed to load Pandora CSV: {e}")

    def _sniper_scan(self, df):
        if not self.ghost_intel:
            return df

        print(f"[*] Phase 4: Engaging Sniper Mode (Time Correlation)...")
        
        # We need a mutable list of tags to update
        # Polars is immutable, so we'll build a mask or join
        
        # Convert DF timestamp to datetime for comparison
        # Assuming "Time" or "Timestamp_UTC" or "Timestamp" exists
        time_col = next((c for c in df.columns if "Time" in c or "Timestamp" in c), None)
        if not time_col:
            print("[!] No timestamp column found in Timeline. Sniper Mode aborted.")
            return df
            
        # Add temporary datetime column
        df = df.with_columns(
            pl.col(time_col).str.strptime(pl.Datetime, "%Y-%m-%d %H:%M:%S", strict=False).alias("_dt_temp")
        )

        sniper_hits = []

        # Iterate over Intel (Yes, loops are slow, but Intel count is usually small < 100)
        for intel in self.ghost_intel:
            center_time = intel["ts"]
            # [CERBERUS CORE] 物理的相関の極限（±10秒へ緩和）
            # 3秒だとOSの書き込みラグ（数秒）でニアミスするため、10秒の遊びを持たせる
            window_start = center_time - timedelta(seconds=10)
            window_end = center_time + timedelta(seconds=10)
            target_file = intel["filename"].lower()
            
            # Filter logs in this window
            window_df = df.filter(
                pl.col("_dt_temp").is_between(window_start, window_end)
            )
            
            if window_df.height > 0:
                # print(f"   > Scanning window {window_start} for Ghost: {intel['filename']}")
                
                for row in window_df.iter_rows(named=True):
                    action = str(row.get("Action", "")).lower()
                    msg = str(row.get("Message", "")).lower() if "Message" in row else ""
                    
                    hit_tag = ""
                    
                    # [Logic 1] USB Device Hunter (LNK_DEL context)
                    if "LNK_DEL" in intel["tag"]:
                        if "6416" in action or "2003" in action or "2100" in action:
                            hit_tag = f"[!SNIPER_HIT] USB_NEAR_DELETION"
                        elif "1006" in action and "defend" in action:
                            hit_tag = f"[!SNIPER_HIT] DEFENDER_ALERT"
                            
                    # [Logic 2] Shell & Process Execution Hunter (Triggered deletion?)
                    # cmd.exe, powershell.exe, or the file itself being run/deleted
                    if "4688" in action:
                        if target_file in msg:
                            hit_tag = f"[!SNIPER_HIT] EXEC_OFFSET_MATCH"
                        elif "cmd.exe" in msg or "powershell" in msg:
                            hit_tag = f"[!SNIPER_HIT] SHELL_EXEC_NEAR_DELETION"

                    # [Logic 3] RDP Activity
                    if "4624" in action and "logon type: 10" in msg:
                         hit_tag = f"[!SNIPER_HIT] RDP_LOGIN_NEAR_DELETION"
                    
                    if hit_tag:
                        # Store the hit to update the main DF later
                        sniper_hits.append({
                            time_col: row[time_col],
                            "Action": row["Action"],
                            "Sniper_Tag": hit_tag
                        })

        # Apply Sniper Tags
        if sniper_hits:
            print(f"   > Sniper confirmed {len(sniper_hits)} correlations!")
            hits_df = pl.DataFrame(sniper_hits)
            
            # Join and update
            # We perform a left join on Time + Action to merge tags
            df = df.join(hits_df, on=[time_col, "Action"], how="left")
            
            # Merge columns: if Sniper_Tag exists, prepend it to Tag
            df = df.with_columns(
                pl.when(pl.col("Sniper_Tag").is_not_null())
                .then(pl.concat_str([pl.lit("[!HIT] "), pl.col("Sniper_Tag"), pl.lit(" | "), pl.col("Tag")]))
                .otherwise(pl.col("Tag"))
                .alias("Tag")
            ).drop("Sniper_Tag")
            
        return df.drop("_dt_temp")

    def _oracle_inference(self, df):
        # Fallback Logic (Oracle Mk.II)
        # print("[*] Phase 1.9: Invoking Oracle (Fallback)...")
        human_sids = df.filter(pl.col("Subject_SID").str.contains(r"^S-1-5-21-")).select("Subject_SID").unique().to_series().to_list()
        human_sids = [s for s in human_sids if s and s not in ["None", "N/A"]]
        
        orphan_users = df.filter(
            (pl.col("User").is_not_null()) &
            (~pl.col("User").str.contains(r"(?i)system|service|dwm|umfd|window manager|n/a|none")) &
            (pl.col("Subject_SID").is_null() | (pl.col("Subject_SID") == "None") | (pl.col("Subject_SID") == "N/A"))
        ).select("User").unique().to_series().to_list()
        orphan_users = [u for u in orphan_users if u and u not in ["None", "N/A"] and "usrclass" not in u.lower()]

        if len(human_sids) == 1 and len(orphan_users) == 1:
            target_sid = human_sids[0]
            target_user = orphan_users[0]
            if target_sid not in self.sid_to_user:
                # print(f"[!!!] THE ORACLE SPEAKS: Merging {target_user} <==> {target_sid}")
                self._register(target_sid, target_user, "Oracle_Heuristic")

    def _hunt_ghosts(self, df):
        try:
            if "Action" in df.columns:
                deleted = df.filter(pl.col("Action").str.contains("EID:4726"))
                for row in deleted.iter_rows(named=True):
                    m = re.search(r"TargetSid:\s*(S-1-5-[\d-]+)", str(row['Action']))
                    if m: self.deleted_users.add(m.group(1))
        except: pass

    def _is_system(self, user, sid):
        u = str(user).lower()
        if any(x in u for x in ["system", "local service", "network service", "dwm", "umfd", "anonymous"]): return True
        s = str(sid)
        if s.startswith("S-1-5-18") or s.startswith("S-1-5-19") or s.startswith("S-1-5-20"): return True
        return False

    def _audit_authority(self, df):
        print(f"[*] Phase 3: Auditing Authority...")
        self._oracle_inference(df)

        def resolve_user(u, s):
            if s in self.sid_to_user: return self.sid_to_user[s]
            if u and str(u).lower() not in ["n/a", "none", ""]: return u
            return "N/A"

        def resolve_sid(u, s):
            if s and str(s).startswith("S-1-5-21"): return s
            if u:
                uk = str(u).lower()
                if uk in self.user_to_sid: return self.user_to_sid[uk]
            return s if s else "N/A"

        def get_status(u, s):
            if self._is_system(u, s): return "SYSTEM"
            if s in self.deleted_users: return "DELETED"
            if s and str(s).startswith("S-1-5-21-"):
                if u and u != "N/A": return "ACTIVE"
                return "ACTIVE (Unresolved)"
            if u and u != "N/A": return "ACTIVE"
            return "IGNORE"

        def judge(act, u, s):
            act = str(act)
            risk = ""
            if "EID:4732" in act and "Administrators" in act: risk = "CRITICAL_PRIV_ESC"
            if "EID:4672" in act and not self._is_system(u, s): risk = "CRITICAL_PRIV_USE"
            if s in self.deleted_users: risk = f"DELETED_USER_ACTIVITY {risk}"
            return f"[!] {risk}" if risk else "NORMAL"

        df = df.with_columns([
            pl.struct(["User", "Subject_SID"]).map_elements(lambda x: resolve_user(x["User"], x["Subject_SID"]), return_dtype=pl.Utf8).alias("Resolved_User"),
        ])
        df = df.with_columns([
            pl.struct(["Resolved_User", "Subject_SID"]).map_elements(lambda x: resolve_sid(x["Resolved_User"], x["Subject_SID"]), return_dtype=pl.Utf8).alias("Subject_SID")
        ])
        df = df.with_columns([
            pl.struct(["Resolved_User", "Subject_SID"]).map_elements(lambda x: get_status(x["Resolved_User"], x["Subject_SID"]), return_dtype=pl.Utf8).alias("Account_Status"),
            pl.struct(["Action", "Resolved_User", "Subject_SID"]).map_elements(lambda x: judge(x["Action"], x["Resolved_User"], x["Subject_SID"]), return_dtype=pl.Utf8).alias("Judge_Verdict")
        ])
        
        if "Tag" not in df.columns: df = df.with_columns(pl.lit("").alias("Tag"))
        df = df.with_columns(
            pl.when(pl.col("Judge_Verdict") != "NORMAL").then(pl.col("Judge_Verdict")).otherwise(pl.col("Tag")).alias("Tag")
        )
        return df

    def execute(self, output_path):
        try:
            df = pl.read_csv(self.timeline_path, ignore_errors=True, infer_schema_length=0)
            self._load_registry_users()
            self._load_pandora_ghosts() # Load Intel
            
            self._hunt_ghosts(df)
            df = self._audit_authority(df)
            
            # Execute Sniper Mode
            df = self._sniper_scan(df)
            
            df.write_csv(output_path)
            print(f"[+] Judgment Materialized: {output_path}")
            return True
        except Exception as e:
            print(f"[!] Hercules Failed: {e}")
            import traceback; traceback.print_exc()
            return False

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True, help="Timeline CSV")
    parser.add_argument("-d", "--dir", required=True, help="KAPE Artifacts Dir")
    parser.add_argument("-p", "--pandora", help="Pandora Report CSV for Sniper Mode")
    parser.add_argument("-o", "--out", required=True)
    args = parser.parse_args(argv)
    
    HerculesReferee(args.input, args.dir, args.pandora).execute(args.out)

if __name__ == "__main__":
    main()
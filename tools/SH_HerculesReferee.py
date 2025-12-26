import polars as pl
import argparse
from pathlib import Path
import sys
import re

# ============================================================
#  SH_HerculesReferee v3.7 [Omnivore]
#  Mission: Resolve Identities & Audit Privilege Escalation
#  Updated: Scans ALL CSVs for ProfileList patterns (No filename filter).
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HERCULES --   [ The Judge v3.7 ]
      | | | | | |    "I devour all data."
    """)

class HerculesReferee:
    def __init__(self, timeline_csv, kape_dir):
        self.timeline_path = Path(timeline_csv)
        self.kape_dir = Path(kape_dir)
        self.sid_to_user = {} 
        self.user_to_sid = {}
        self.deleted_users = set()

    def _register(self, sid, user, source="Unknown"):
        if not sid or not user: return
        sid = str(sid).strip()
        user = str(user).strip()
        
        if not sid.startswith("S-1-"): return
        if user.lower() in ["n/a", "none", "null", "", "system", "local service", "network service"]: return
        if user.lower().endswith(".csv"): return 

        if sid not in self.sid_to_user:
            print(f"[+] Identity Link Found ({source}): {user} <==> {sid}")
            self.sid_to_user[sid] = user
        
        u_key = user.lower()
        if u_key not in self.user_to_sid:
            self.user_to_sid[u_key] = sid

    def _load_registry_users(self):
        print("[*] Phase 1: Scanning KAPE Output for Identity Mappings...")
        reg_files = list(self.kape_dir.rglob("*.csv"))
        
        for reg in reg_files:
            # [FIX] No more filename filtering. We check content.
            try:
                # Read only first few lines to check if it's relevant, or read all if small
                # BasicSystemInfo is usually small enough.
                # Use ignore_errors to skip bad lines
                df = pl.read_csv(reg, ignore_errors=True, infer_schema_length=0)
                
                cols = df.columns
                # Dynamic column detection
                key_col = next((c for c in cols if "Key" in c), None)
                val_data_col = next((c for c in cols if "ValueData" in c or "Data" in c), None)
                
                if not key_col or not val_data_col: continue

                # Filter for ProfileList SIDs
                targets = df.filter(
                    pl.col(key_col).str.contains(r"S-1-5-21-") & 
                    pl.col(key_col).str.contains(r"ProfileList")
                )
                
                if not targets.is_empty():
                    print(f"   > Digesting: {reg.name}")
                    for row in targets.iter_rows(named=True):
                        full_key = str(row[key_col])
                        full_path = str(row[val_data_col])
                        
                        # Extract SID
                        m_sid = re.search(r'(S-1-5-21-\d+-\d+-\d+-\d+)', full_key)
                        
                        # Extract User from path C:\Users\user
                        if m_sid and "Users" in full_path:
                            sid = m_sid.group(1)
                            user = full_path.replace("\\", "/").split("/")[-1]
                            self._register(sid, user, f"Registry:{reg.name}")
                            
            except: pass

    def _oracle_inference(self, df):
        # Fallback Logic (Oracle Mk.II)
        print("[*] Phase 1.9: Invoking Oracle (Fallback)...")
        human_sids = df.filter(pl.col("Subject_SID").str.contains(r"^S-1-5-21-")).select("Subject_SID").unique().to_series().to_list()
        human_sids = [s for s in human_sids if s and s not in ["None", "N/A"]]
        
        orphan_users = df.filter(
            (pl.col("User").is_not_null()) &
            (~pl.col("User").str.contains(r"(?i)system|service|dwm|umfd|window manager|n/a|none")) &
            (pl.col("Subject_SID").is_null() | (pl.col("Subject_SID") == "None") | (pl.col("Subject_SID") == "N/A"))
        ).select("User").unique().to_series().to_list()
        orphan_users = [u for u in orphan_users if u and u not in ["None", "N/A"] and "usrclass" not in u.lower()]

        # Force Merge if unique
        if len(human_sids) == 1 and len(orphan_users) == 1:
            target_sid = human_sids[0]
            target_user = orphan_users[0]
            if target_sid not in self.sid_to_user:
                print(f"[!!!] THE ORACLE SPEAKS: Merging {target_user} <==> {target_sid}")
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
            self._hunt_ghosts(df)
            final_df = self._audit_authority(df)
            final_df.write_csv(output_path)
            print(f"[+] Judgment Materialized: {output_path}")
            return True
        except Exception as e:
            print(f"[!] Hercules Failed: {e}")
            import traceback; traceback.print_exc()
            return False

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-d", "--dir", required=True)
    parser.add_argument("-o", "--out", required=True)
    args = parser.parse_args(argv)
    HerculesReferee(args.input, args.dir).execute(args.out)

if __name__ == "__main__":
    main()
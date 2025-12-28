import polars as pl
import argparse
from pathlib import Path
import sys
import datetime

# ============================================================
#  SH_HerculesReferee v3.5 [Schema Enforcer]
#  Mission: Identity + Script Hunter + GHOST CORRELATION
#  Fix: Explicit schema enforcement to prevent type inference crashes.
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HERCULES --   [ Referee v3.5 ]
      | | | | | |    "Sniper Mode: LOCKED."
    """)

class HerculesReferee:
    def __init__(self, kape_dir):
        self.kape_dir = Path(kape_dir)

    def _load_evtx_csv(self):
        csvs = list(self.kape_dir.rglob("*EvtxECmd*.csv"))
        if not csvs: return None
        target = csvs[0]
        print(f"[*] Loading Event Logs from: {target.name}")
        return pl.read_csv(target, ignore_errors=True, infer_schema_length=0)

    # --- Logic A: Identity ---
    def _audit_authority(self, df_timeline):
        print("[*] Phase 3A: Auditing Authority...")
        df = df_timeline.clone()
        
        def judge_identity(user, sid, tag):
            u_str = str(user).lower()
            s_str = str(sid).lower()
            t_str = str(tag)
            if "system" in u_str or "s-1-5-18" in s_str:
                return "NORMAL"
            if "risk" in t_str.lower() or "critical" in t_str.lower():
                return "CRITICAL_USER_ACTION"
            return "NORMAL"

        verdict_col = []
        for row in df.iter_rows(named=True):
            verdict_col.append(judge_identity(row.get("User"), row.get("Subject_SID"), row.get("Tag")))
        
        return df.with_columns(pl.Series(name="Judge_Verdict", values=verdict_col))

    # --- Logic B: Script Hunter ---
    def analyze_process_tree(self, df_evtx):
        print("[*] Phase 3B: Script Hunter (Process Tree)...")
        df_proc = df_evtx.filter(pl.col("EventId") == "4688")
        if df_proc.is_empty(): return []

        judgments = []
        for row in df_proc.iter_rows(named=True):
            payload = str(row.get("PayloadData6") or row.get("Payload") or "").lower()
            score = 0
            tags = []
            verdict = "NORMAL"

            if "attack_chain" in payload or "loader.ps1" in payload:
                score += 50; tags.append("ATTACK_SCRIPT_EXEC"); verdict = "CRITICAL_SCRIPT"
            if "sdelete" in payload:
                score += 40; tags.append("ANTI_FORENSICS_WIPING"); verdict = "CRITICAL_WIPING"
            if "curl" in payload or "wget" in payload:
                score += 30; tags.append("C2_BEACON_ATTEMPT"); verdict = "SUSPICIOUS_NETWORK"
            if "reg add" in payload or "schtasks" in payload:
                score += 30; tags.append("PERSISTENCE_INSTALL"); verdict = "SUSPICIOUS_PERSISTENCE"
            
            if score > 0:
                judgments.append({
                    "Timestamp_UTC": str(row.get("TimeCreated") or ""),
                    "Action": "Process_Created",
                    "User": str(row.get("UserName") or row.get("UserId") or ""),
                    "Subject_SID": str(row.get("UserId") or ""),
                    "Target_Path": payload[:500],
                    "Source_File": "Security.evtx",
                    "Tag": ", ".join(tags),
                    "Judge_Verdict": verdict,
                    "Resolved_User": str(row.get("UserName") or "N/A"),
                    "Account_Status": "IGNORE",
                    "Artifact_Type": "EventLog"
                })
        return judgments

    # --- Logic C: Sniper Correlation (Schema Safe) ---
    def correlate_ghosts(self, df_events, df_ghosts):
        print("[*] Phase 3C: Sniper Mode (Ghost Correlation)...")
        if df_ghosts is None or df_ghosts.is_empty(): return df_events
        
        # 1. Force strict string schema for ALL relevant columns
        # This prevents "Null vs String" inference crashes during rebuild
        cols_to_force = [
            "Tag", "Judge_Verdict", "Target_Path", "User", "Resolved_User", 
            "Action", "Source_File", "Subject_SID", "Account_Status", "Artifact_Type"
        ]
        
        for col in cols_to_force:
            if col not in df_events.columns:
                df_events = df_events.with_columns(pl.lit("").cast(pl.Utf8).alias(col))
            else:
                df_events = df_events.with_columns(pl.col(col).cast(pl.Utf8).fill_null(""))

        # Filter high risk ghosts
        risky_ghosts = df_ghosts.filter(pl.col("Risk_Tag").is_in(["RISK_EXT", "OBFUSCATED"]))
        if risky_ghosts.is_empty(): return df_events

        # Timestamp prep
        df_events = df_events.with_columns(pl.col("Timestamp_UTC").str.to_datetime(strict=False).alias("_dt"))
        
        hits = []
        events = df_events.to_dicts()
        
        ghost_times = []
        for g in risky_ghosts.iter_rows(named=True):
            gt = g.get("Last_Executed_Time") or g.get("Ghost_Time_Hint")
            if gt:
                try:
                    dt = datetime.datetime.fromisoformat(str(gt).replace("Z", ""))
                    ghost_times.append((dt, g.get("Ghost_FileName")))
                except: pass

        if not ghost_times: return df_events.drop("_dt")

        for ev in events:
            # Drop helper column from dict to keep clean
            dt_val = ev.pop("_dt", None)
            
            if dt_val is None: 
                hits.append(ev)
                continue
            
            ev_tag = ev["Tag"]
            is_hit = False
            
            for gt, gname in ghost_times:
                delta = (dt_val - gt).total_seconds()
                if abs(delta) < 30:
                    new_tag = f"[SNIPER] (Correlated w/ {gname})"
                    ev["Tag"] = f"{ev_tag}, {new_tag}" if ev_tag else new_tag
                    ev["Judge_Verdict"] = "SNIPER_HIT"
                    is_hit = True
                    break
            
            hits.append(ev)

        # 2. Rebuild with explicit schema from the sanitized df_events
        # Using schema=df_events.schema tells Polars "Don't guess, use this!"
        return pl.DataFrame(hits, schema=df_events.drop("_dt").schema)

    # --- Logic D: Session Tracker (SID Affinity) ---
    def track_sessions(self, df_evtx):
        print("[*] Phase 3D: Tracking User Sessions (SID Transition)...")
        if df_evtx is None: return
        
        # Target Events: 4624 (Logon), 4634/4647 (Logoff), 4672 (Admin Priv)
        df_sess = df_evtx.filter(pl.col("EventId").cast(pl.Utf8).is_in(["4624", "4634", "4647", "4672"]))
        if df_sess.is_empty(): return

        # Normalize Columns
        cols = df_sess.columns
        uid_col = next((c for c in ["TargetUserSid", "SubjectUserSid", "UserId"] if c in cols), None)
        lid_col = next((c for c in ["TargetLogonId", "SubjectLogonId", "LogonId"] if c in cols), None)
        time_col = next((c for c in ["TimeCreated", "Timestamp_UTC"] if c in cols), "Time")

        if not (uid_col and lid_col and time_col):
            print("[-] Missing critical session columns. Skipping tracker.")
            return

        # Sort by time
        df_sess = df_sess.sort(time_col)
        
        active_sessions = {} # {LogonId: {SID, Start, Privileges}}
        session_history = []

        for row in df_sess.iter_rows(named=True):
            eid = str(row["EventId"])
            lid = str(row.get(lid_col) or "")
            sid = str(row.get(uid_col) or "")
            ts = str(row.get(time_col) or "")
            
            if not lid or lid == "0x0": continue

            if eid == "4624": # Logon
                active_sessions[lid] = {"SID": sid, "Start": ts, "Privileges": [], "End": None}
            
            elif eid == "4672": # Special Privileges (Admin)
                # Usually happens right after 4624 with same LogonId
                if lid in active_sessions:
                    # Extract privileges if available (PayloadData often has them in messy format)
                    # Simplified: Just mark as High Integrity / Admin context
                    active_sessions[lid]["Privileges"].append("ADMIN_PRIVILEGE_ASSERTED")
            
            elif eid in ["4634", "4647"]: # Logoff
                if lid in active_sessions:
                    sess = active_sessions.pop(lid)
                    sess["End"] = ts
                    session_history.append(sess)
        
        # Dump remaining active sessions (implicitly active at end of log)
        for lid, sess in active_sessions.items():
            sess["End"] = "ACTIVE"
            session_history.append(sess)
            
        # Export to JSON
        import json
        out_path = self.kape_dir / "hercules_sessions.json"
        try:
            with open(out_path, "w") as f:
                json.dump(session_history, f, indent=2)
            print(f"[+] Session Map Exported: {out_path} ({len(session_history)} sessions)")
        except Exception as e:
            print(f"[-] Failed to export session map: {e}")

    def execute(self, timeline_csv, ghost_csv, output_csv):
        try:
            df_timeline = pl.read_csv(timeline_csv, ignore_errors=True, infer_schema_length=0)
            df_ghosts = pl.read_csv(ghost_csv, ignore_errors=True, infer_schema_length=0)
            df_evtx = self._load_evtx_csv()
        except Exception as e:
            print(f"[-] Error loading inputs: {e}")
            return

        # 0. Session Tracking (Pre-process)
        if df_evtx is not None:
            self.track_sessions(df_evtx)

        # 1. Identity
        df_identity = self._audit_authority(df_timeline)
        
        # 2. Script Hunter
        df_combined = df_identity
        if df_evtx is not None:
            script_hits = self.analyze_process_tree(df_evtx)
            if script_hits:
                print(f"   > Script Hunter found {len(script_hits)} events.")
                df_scripts = pl.DataFrame(script_hits)
                
                # Align columns explicitly
                # Enforce string types on Identity DF before concat to match Script DF
                df_identity = df_identity.with_columns([
                    pl.col(c).cast(pl.Utf8) for c in df_identity.columns if c != "Timestamp_UTC" # Keep time mostly raw or string is fine
                ])
                
                df_combined = pl.concat([df_identity, df_scripts], how="diagonal")

        # 3. Sniper Correlation (with Schema Enforcement)
        df_final = self.correlate_ghosts(df_combined, df_ghosts)

        # 4. Final Filter
        if df_final.height > 0:
            print(f"   > Filtering noise... (Original: {df_final.height} rows)")
            df_final = df_final.filter(
                (pl.col("Judge_Verdict") != "NORMAL") |
                ((pl.col("Tag").is_not_null()) & (pl.col("Tag") != ""))
            )
            print(f"   > Final Critical Events: {df_final.height} rows")
        
        df_final.write_csv(output_csv)
        print(f"[+] Judgment Materialized: {output_csv}")

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeline", required=True)
    parser.add_argument("--ghosts", required=True)
    parser.add_argument("--kape", required=True)
    parser.add_argument("-o", "--out", default="Hercules_Judged_Timeline.csv")
    args = parser.parse_args(argv)
    referee = HerculesReferee(kape_dir=args.kape)
    referee.execute(args.timeline, args.ghosts, args.out)

if __name__ == "__main__":
    main()
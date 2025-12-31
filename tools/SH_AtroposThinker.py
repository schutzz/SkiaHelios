import polars as pl
import datetime
import re
from pathlib import Path
from collections import defaultdict, Counter

# ============================================================
#  SH_AtroposThinker v1.9.4 [Verdict Fixed]
#  Mission: Analyze correlations, deduce verdicts, cut noise.
#  Fix: Properly add LATERAL_MOVEMENT flag to Verdicts.
# ============================================================

class NemesisTracer:
    def __init__(self, df_mft, df_usn, noise_validator=None):
        self.df_mft = df_mft
        self.df_usn = df_usn
        self.noise_validator = noise_validator
        self.id_cols = ["EntryNumber", "MftRecordNumber", "FileReferenceNumber", "ReferenceNumber"]

    def trace_lifecycle(self, attack_seeds):
        if not attack_seeds: return []
        pattern = "|".join([re.escape(s) for s in attack_seeds if len(s) > 2])
        if not pattern: return []

        lifecycle_events = []
        target_file_ids_map = {} 

        for df, src in [(self.df_mft, "MFT"), (self.df_usn, "USN")]:
            if df is None: continue
            name_cols = [c for c in ["FileName", "Ghost_FileName", "OldFileName", "Target_FileName"] if c in df.columns]
            if not name_cols: continue

            try:
                filter_expr = pl.any_horizontal([pl.col(c).str.contains(f"(?i){pattern}") for c in name_cols])
                seed_hits = df.filter(filter_expr)

                for row in seed_hits.iter_rows(named=True):
                    lifecycle_events.append(self._to_event(row, src, "Seed Matching"))
                    seq_num = row.get("SequenceNumber")
                    for c in self.id_cols:
                        if row.get(c): 
                            target_file_ids_map[str(row[c])] = seq_num
                            break
            except: pass

        lifecycle_events.extend(self._recover_lifecycle_by_ids(target_file_ids_map, "ID-Chain Recovery"))
        return lifecycle_events

    def _parse_id(self, val):
        if not val: return None, None
        try:
            val_int = int(val)
            if val_int > 0xFFFFFFFFFFFF: 
                entry = val_int & 0xFFFFFFFFFFFF
                seq = (val_int >> 48) & 0xFFFF
                return str(entry), str(seq)
            return str(val_int), None
        except:
            return str(val), None

    def _recover_lifecycle_by_ids(self, target_ids_dict, mode_label="ID-Chain Recovery"):
        events = []
        if not target_ids_dict: return events

        for df, src in [(self.df_usn, "USN"), (self.df_mft, "MFT")]:
            if df is None: continue
            found_col = next((c for c in self.id_cols if c in df.columns), None)
            if not found_col: continue

            seq_col = "SequenceNumber" if "SequenceNumber" in df.columns else None
            target_keys = list(target_ids_dict.keys())
            try:
                chain_hits = df.filter(pl.col(found_col).cast(pl.Utf8).is_in(target_keys))
                
                for row in chain_hits.iter_rows(named=True):
                    row_raw_id = row[found_col]
                    row_entry, row_packed_seq = self._parse_id(row_raw_id)
                    target_seq = target_ids_dict.get(row_entry)
                    check_seq = row.get(seq_col) or row_packed_seq
                    
                    if target_seq is not None and check_seq is not None:
                         try:
                             if int(check_seq) != int(target_seq) and int(target_seq) != 0: continue
                         except: pass 
                    events.append(self._to_event(row, src, mode_label))
            except: pass
        
        has_birth = any("BIRTH" in str(ev.get('Reason', '')).upper() or "CREATE" in str(ev.get('Reason', '')).upper() for ev in events)
        if events and not has_birth:
            events.sort(key=lambda x: x.get('dt_obj') or datetime.datetime.max)
            oldest_ev = events[0]
            src_hint = str(oldest_ev.get('Source', 'Unknown')).replace('Nemesis ', '').strip('()')
            oldest_ev['Summary'] += " [PROVISIONAL ORIGIN]"
            oldest_ev['Detail'] += f" (Reason: Oldest Trace / Birth Missing | Reliability Source: {src_hint})"
            oldest_ev['Criticality'] = 85

        return events

    def trace_origin_by_execution(self, execution_events):
        if not execution_events: return []
        captured_ids_map = {}
        lifecycle_events = []
        dynamic_seeds = set()

        for ev in execution_events:
            exec_dt = ev.get('dt_obj')
            if not exec_dt: continue
            raw_text = str(ev.get('Detail', '')) + " " + str(ev.get('Summary', ''))
            new_discovered = self._extract_seeds_from_args(raw_text)
            dynamic_seeds.update(new_discovered)

            candidates = set()
            if ev.get('Keywords'):
                for k in ev['Keywords']:
                    k_lower = str(k).lower()
                    fname_only = k_lower.split("\\")[-1]
                    if not (self.noise_validator and self.noise_validator(fname_only)):
                        candidates.add(fname_only)
                        candidates.add(k_lower)
            candidates.update(dynamic_seeds)
            candidates = {c for c in candidates if len(c) > 2 and not (self.noise_validator and self.noise_validator(c))}
            if not candidates: continue

            window_start = exec_dt - datetime.timedelta(seconds=5)
            window_end = exec_dt + datetime.timedelta(seconds=5)
            pattern = "|".join([re.escape(c) for c in candidates])
            if not pattern: continue

            if self.df_usn is not None:
                time_col = next((c for c in ["Timestamp_UTC", "Last_Executed_Time", "Ghost_Time_Hint", "Time"] if c in self.df_usn.columns), None)
                if time_col: 
                    name_cols = [c for c in ["FileName", "Ghost_FileName", "Chaos_FileName"] if c in self.df_usn.columns]
                    if name_cols:
                        try:
                            name_filter = pl.any_horizontal([pl.col(c).str.to_lowercase().str.contains(f"(?i){pattern}") for c in name_cols])
                            hits = self.df_usn.filter(name_filter)
                            for row in hits.iter_rows(named=True):
                                row_t = str(row.get(time_col)).replace('Z','')
                                try:
                                    rdt = datetime.datetime.fromisoformat(row_t)
                                    if not (window_start <= rdt <= window_end): continue
                                except: pass

                                if self.noise_validator:
                                    f_path = str(row.get("ParentPath", "")) + "\\" + str(row.get("FileName") or row.get("Ghost_FileName") or "")
                                    if self.noise_validator(f_path): continue
                                for c in self.id_cols:
                                    if row.get(c):
                                        entry, seq = self._parse_id(row[c])
                                        existing_seq = row.get("SequenceNumber")
                                        final_seq = existing_seq if existing_seq else seq
                                        if entry: captured_ids_map[entry] = final_seq
                                        break
                        except: pass
            
            if self.df_mft is not None:
                mft_name_cols = [c for c in ["FileName", "Ghost_FileName", "Chaos_FileName"] if c in self.df_mft.columns]
                if mft_name_cols:
                     try:
                         mft_name_filter = pl.any_horizontal([pl.col(c).cast(pl.Utf8).fill_null("").str.to_lowercase().str.contains(f"(?i){pattern}") for c in mft_name_cols])
                         mft_hits = self.df_mft.filter(mft_name_filter)
                         for row in mft_hits.iter_rows(named=True):
                            if self.noise_validator:
                                f_path = str(row.get("ParentPath", "")) + "\\" + str(row.get("FileName") or "")
                                if self.noise_validator(f_path): continue
                            for c in self.id_cols:
                                if row.get(c):
                                    entry, seq = self._parse_id(row[c])
                                    existing_seq = row.get("SequenceNumber")
                                    final_seq = existing_seq if existing_seq else seq
                                    if entry and entry not in captured_ids_map:
                                        captured_ids_map[entry] = final_seq
                                    break
                     except: pass

        if captured_ids_map:
            lifecycle_events.extend(self._recover_lifecycle_by_ids(captured_ids_map, "Origin Trace (Execution)"))
        
        return lifecycle_events

    def _extract_seeds_from_args(self, text):
        if not text: return []
        clean_text = str(text).replace('"', '')
        matches = re.findall(r'([a-zA-Z]:\\[^\s"\'<>|]*\.(?:exe|ps1|bat|cmd|vbs|dll|sys|doc|docx|xls|xlsx|pdf|zip|js|hta|wsf))', clean_text, re.IGNORECASE)
        results = set()
        for m in matches:
            fname = Path(m).name
            if len(fname) > 2: results.add(fname.lower())
        return list(results)

    def _to_event(self, row, source_type, mode):
        fname = row.get("FileName") or row.get("Ghost_FileName") or "Unknown"
        old_name = row.get("OldFileName") 
        reason = str(row.get("Reason") or row.get("UpdateReason") or "N/A").upper()
        owner = row.get("SI_SID") or row.get("SID") or row.get("Owner") or "N/A"
        spec = "Activity"
        if "CREATE" in reason: spec = "Birth"
        elif "DELETE" in reason: spec = "Termination"
        elif "RENAME" in reason: spec = "Identity Change"
        
        summary = f"Lifecycle Trace [{spec}]: {fname}"
        if old_name and old_name != fname: summary = f"Lifecycle Trace [Identity Shift]: {old_name} -> {fname}"
        
        t_str = str(row.get("si_dt") or row.get("Ghost_Time_Hint") or row.get("Timestamp_UTC"))
        
        return {
            "Time": t_str,
            "Source": f"Nemesis ({source_type})", "User": "System/Inferred",
            "Summary": summary,
            "Detail": f"Mode: {mode} | Reason: {reason}\nPath: {row.get('ParentPath')}\nOwner: {owner}",
            "Criticality": 95, "Category": "ANTI" if "DELETE" in reason else "DROP",
            "Keywords": [fname],
            "Owner_SID": owner,
            "dt_obj": None 
        }


class AtroposThinker:
    def __init__(self, dfs, siren_data, hostname):
        self.dfs = dfs
        self.siren_data = siren_data
        self.hostname = hostname
        self.valid_events = []
        self.origin_stories = []
        self.verdict_flags = set()
        self.lateral_summary = ""
        self.compromised_users = Counter()
        self.flow_steps = []
        self.re_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.re_filename = re.compile(r'([\w\-\.]+\.(?:exe|ps1|bat|dll))', re.IGNORECASE)

    def _parse_strict_time(self, t_str):
        if not t_str: return None
        s = str(t_str).strip()
        if not s or s.lower() in ("none", "nan", ""): return None
        if 'T' in s:
            try:
                if s.endswith('Z'): s = s[:-1] + '+00:00'
                return datetime.datetime.fromisoformat(s)
            except: pass
        if '-' in s:
            if '.' in s:
                try: return datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f")
                except: pass
            else:
                try: return datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
                except:
                    try: return datetime.datetime.strptime(s, "%Y-%m-%d %H:%M")
                    except: pass
        elif '/' in s:
            formats = ["%m/%d/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M", "%Y/%m/%d %H:%M"]
            for fmt in formats:
                try: return datetime.datetime.strptime(s, fmt)
                except: pass
        try: return datetime.datetime.fromisoformat(s.replace(' ', 'T'))
        except: pass
        return None

    def contemplate(self):
        print("[*] Atropos is contemplating the fate of artifacts...")
        raw_events = self._collect_and_filter_events()
        
        seeds = self._harvest_seeds(raw_events)
        nemesis = NemesisTracer(self.dfs.get('Chronos'), self.dfs.get('Pandora'), self._is_known_noise)
        
        if seeds:
            print(f"   -> Nemesis identified {len(seeds)} attack seeds. Tracing...")
            nemesis_events = nemesis.trace_lifecycle(list(seeds))
            current_sigs = {e['Summary'] + str(e['Time']) for e in raw_events}
            for ne in nemesis_events:
                if (ne['Summary'] + str(ne['Time'])) not in current_sigs:
                    raw_events.append(ne)

        execution_events = self._filter_execution_events(raw_events)
        for ev in execution_events:
             if not ev.get('dt_obj'): ev['dt_obj'] = self._parse_strict_time(ev.get('Time'))
        
        phys_events = nemesis.trace_origin_by_execution(execution_events)
        if phys_events:
            current_sigs = {e['Summary'] + str(e['Time']) for e in raw_events}
            for pe in phys_events:
                if (pe['Summary'] + str(pe['Time'])) not in current_sigs:
                    raw_events.append(pe)

        for ev in raw_events:
            if not ev.get('dt_obj'): ev['dt_obj'] = self._parse_strict_time(ev.get('Time'))
        self._merge_ghosts(raw_events)
        self._infer_execution_drops(raw_events)
        self._detect_privilege_escalation(raw_events)

        for ev in raw_events:
            if not ev.get('dt_obj'):
                ev['dt_obj'] = self._parse_strict_time(ev.get('Time'))
        raw_events.sort(key=lambda x: x.get('dt_obj') or datetime.datetime.max)

        self.origin_stories = self._analyze_origin_context(raw_events)
        self._judge_fate(raw_events)
        
        # [Fix] Lateral Logic
        self.lateral_summary = self._detect_lateral_movement(raw_events)
        self._measure_heat_correlation(raw_events)

        self._extract_attack_flow(raw_events)
        self.valid_events = raw_events
        
        for ev in raw_events:
            if ev.get('User') and "System" not in str(ev['User']) and "N/A" not in str(ev['User']):
                self.compromised_users[ev['User']] += 1

        phases = self._partition_timeline(self.valid_events)

        return {
            "events": self.valid_events,
            "phases": phases,
            "origin_stories": self.origin_stories,
            "verdict_flags": self.verdict_flags,
            "lateral_summary": self.lateral_summary,
            "compromised_users": self.compromised_users,
            "flow_steps": self.flow_steps
        }

    def _detect_privilege_escalation(self, events):
        df_sessions = self.dfs.get('Sessions')
        if df_sessions is None or df_sessions.is_empty(): return
        user_sessions = []
        try:
            for row in df_sessions.iter_rows(named=True):
                sid = str(row.get('SID', ''))
                if "S-1-5-18" in sid: continue
                start_t = self._parse_strict_time(row.get('Start'))
                end_raw = row.get('End')
                end_t = datetime.datetime.max if str(end_raw) == "ACTIVE" else self._parse_strict_time(end_raw)
                if start_t and end_t:
                    user_sessions.append({"SID": sid, "Start": start_t, "End": end_t})
        except: return

        if not user_sessions: return
        count = 0
        for ev in events:
            user = str(ev.get('User', '')).lower()
            if "system" not in user and "s-1-5-18" not in str(ev.get('Owner_SID', '')).lower(): continue
            cat = ev.get('Category', '')
            if cat not in ['EXEC', 'PERSIST', 'ANTI', 'DROP']: continue
            ev_time = ev.get('dt_obj')
            if not ev_time: continue

            is_overlap = False
            for sess in user_sessions:
                if sess['Start'] <= ev_time <= sess['End']:
                    is_overlap = True; break
            if is_overlap:
                ev['Criticality'] = 100
                ev['Summary'] = "[PRIVILEGE_ESCALATION] " + ev['Summary']
                self.verdict_flags.add("[PRIVILEGE_ESCALATION]")
                count += 1
        if count > 0: print(f"   [!] DETECTED: {count} Potential Privilege Escalation events.")

    def _harvest_seeds(self, events):
        seeds = set()
        for ev in events:
            if ev.get('Criticality', 0) < 85: continue
            kws = ev.get('Keywords', [])
            if not kws: continue
            if isinstance(kws, str): kws = [kws]
            for k in kws:
                full_path = str(k).strip()
                if not full_path: continue
                fname_only = Path(full_path).name
                if not self._is_known_noise(full_path) and not self._is_known_noise(fname_only):
                    seeds.add(full_path)
                    if len(fname_only) > 3: seeds.add(fname_only)
        return seeds

    def _filter_execution_events(self, events):
        CONTAINER_APPS_CHECK = {
            "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", 
            "python.exe", "perl.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", 
            "bitsadmin.exe", "certutil.exe", "csc.exe", "vbc.exe", "installutil.exe", 
            "psexec.exe", "wmiprvse.exe", "scrcons.exe", "microsoft.powershell.cmd"
        }
        execs = []
        for ev in events:
            if ev.get('Category') in ['INIT', 'EXEC']:
                is_container = False
                kws = ev.get('Keywords', [])
                for k in kws:
                    if str(k).lower().split("\\")[-1] in CONTAINER_APPS_CHECK:
                        is_container = True; break
                if ev.get('Criticality', 0) >= 80 or is_container:
                    execs.append(ev)
        return execs

    def _merge_ghosts(self, events):
        indices_to_remove = set()
        nemesis_deaths = [ev for ev in events if "Nemesis" in str(ev.get('Source', '')) and ("DELETE" in str(ev.get('Reason', '')).upper())]
        for n_ev in nemesis_deaths:
            if "[CONFIRMED DELETION]" not in n_ev['Summary']: 
                n_ev['Summary'] = "[CONFIRMED DELETION] " + n_ev['Summary']
            n_time = n_ev.get('dt_obj')
            if not n_time: continue
            for i, p_ev in enumerate(events):
                if i in indices_to_remove: continue
                if "Pandora" not in str(p_ev.get('Source', '')) and "ANTI" not in str(p_ev.get('Category', '')): continue
                p_time = p_ev.get('dt_obj')
                if not p_time: continue
                if abs((n_time - p_time).total_seconds()) > 5: continue
                n_names = set(str(k).lower().split("\\")[-1] for k in n_ev.get('Keywords', []))
                p_names = set(str(k).lower().split("\\")[-1] for k in p_ev.get('Keywords', []))
                if n_names.intersection(p_names):
                    n_ev['Summary'] += f" <br>(Matches Pandora Ghost: {p_ev['Summary']})"
                    indices_to_remove.add(i)
        if indices_to_remove:
            kept = [ev for i, ev in enumerate(events) if i not in indices_to_remove]
            events.clear(); events.extend(kept)

    def _infer_execution_drops(self, events):
        executed_files = {} 
        dropped_files = set()
        for ev in events:
            if ev['Category'] == 'DROP':
                if ev.get('Keywords'): dropped_files.add(str(ev['Keywords'][0]).lower())
            elif ev['Category'] in ['INIT', 'EXEC', 'PERSIST']:
                if ev.get('Criticality', 0) < 90: continue
                kws = ev.get('Keywords')
                if kws:
                    fname = str(kws[0]).lower()
                    if not self._is_known_noise(fname): executed_files[fname] = ev 
        new_events = []
        for fname, exec_ev in executed_files.items():
            if self._is_known_noise(fname): continue
            if exec_ev.get('Criticality', 0) < 80: continue 
            if fname not in dropped_files and "unknown" not in fname:
                exec_dt = exec_ev.get('dt_obj')
                if exec_dt:
                    inferred_dt = exec_dt - datetime.timedelta(seconds=1)
                    new_events.append({
                        "Time": str(inferred_dt), 
                        "Source": "Inferred from High-Confidence Execution", 
                        "User": exec_ev['User'],
                        "Summary": f"File Creation (Inferred): {fname}",
                        "Detail": f"Executed without prior drop record. Likely malicious.",
                        "Criticality": 85, "Category": "DROP", 
                        "Keywords": [fname], "dt_obj": inferred_dt
                    })
        events.extend(new_events)

    def _analyze_origin_context(self, events):
        origin_stories = []
        drops = [e for e in events if e['Category'] == 'DROP' and e.get('Criticality', 0) >= 70]
        for drop in drops:
            drop_dt = drop.get('dt_obj')
            if not drop_dt: continue
            kws = drop.get('Keywords', [])
            fname = str(kws[0]).lower() if kws else ""
            if not fname: continue
            story = {"File": fname, "Drop_Time": drop_dt, "Web_Correlation": None, "Path_Indicator": None, "Execution_Link": None}
            detail = str(drop.get('Detail', '')).lower()
            if "content.outlook" in detail: story['Path_Indicator'] = "Outlook添付ファイル (Content.Outlook)"
            elif "inetcache" in detail: story['Path_Indicator'] = "ブラウザキャッシュ (Drive-by Download)"
            elif "downloads" in detail: story['Path_Indicator'] = "ダウンロードフォルダ"
            execs = [e for e in events if e['Category'] in ['EXEC', 'INIT'] and e.get('dt_obj') and e['dt_obj'] >= drop_dt]
            for ex in execs:
                ex_kws = [str(k).lower() for k in ex.get('Keywords', [])]
                if fname in ex_kws:
                    story['Execution_Link'] = f"Executed at {ex['Time']} (Source: {ex['Source']})"
                    break
            if story['Path_Indicator'] or story['Web_Correlation'] or story['Execution_Link']:
                origin_stories.append(story)
        return origin_stories

    def _judge_fate(self, events):
        if self.siren_data:
            for story in self.origin_stories:
                f_lower = str(story['File']).lower()
                for target in self.siren_data:
                    if target.get('FileName') == f_lower and target.get('Executed'):
                        story['Execution_Link'] = f"Executed (Prefetch Verified) (Count: {target.get('Run_Count', 1)})"
                        if not story['Path_Indicator']:
                            full_p = str(target.get('Full_Path', ''))
                            if "outlook" in full_p.lower(): story['Path_Indicator'] = "Outlook添付ファイル"
        if self.siren_data:
            for target in self.siren_data:
                if target.get('Siren_Score', 0) >= 50 and target.get('Executed'):
                    full_p = str(target.get('Full_Path', '')).lower()
                    if "outlook" in full_p: self.verdict_flags.add("[PHISHING_ATTACHMENT_EXEC]")
                    elif "download" in full_p: self.verdict_flags.add("[DRIVE_BY_DOWNLOAD_EXEC]")
        for story in self.origin_stories:
            if "outlook" in str(story.get('Path_Indicator', '')).lower() and story.get('Execution_Link'):
                self.verdict_flags.add("[PHISHING_ATTACHMENT_EXEC]")
        if not self.verdict_flags:
            for ev in events:
                detail = str(ev.get('Detail', '')).lower()
                if "content.outlook" in detail and ev.get('Criticality', 0) >= 60:
                     self.verdict_flags.add("[PHISHING_ATTACHMENT_EXEC]")

    def _detect_lateral_movement(self, events):
        lateral_lines = []
        has_lateral = False
        
        for ev in events:
            summary = str(ev.get('Summary', '')).upper()
            detail = str(ev.get('Detail', ''))
            cat = ev.get('Category', '')
            kws = str(ev.get('Keywords', ''))
            
            if "LATERAL" in summary or "INTERNAL_EXFIL" in summary or "RDP_" in summary or "SMB_WMI" in kws:
                has_lateral = True
                direction = "Unknown"
                target_ip = self._extract_ip(detail)
                
                if "DROP" in cat or "WROTE" in summary:
                    direction = f"INCOMING ATTACK (Target: {self.hostname})"
                elif "TRANSFER" in summary or "EXECUTED" in summary or "CONNECTION" in summary:
                    direction = f"OUTGOING ATTACK (Source: {self.hostname} -> {target_ip if target_ip else 'Unknown'})"
                
                lateral_lines.append(f"- **[{direction}]** {ev['Summary']}")

        if has_lateral:
            # [FIX] 明示的にフラグを立てる！
            self.verdict_flags.add("[LATERAL_MOVEMENT_CONFIRMED]")
            
            block = ["\n### 🚨 Lateral Movement & Internal Exfiltration Detected\n"]
            block.append("本端末において、横展開または内部データ持ち出しの痕跡が確認されました。\n")
            block.extend(lateral_lines)
            block.append("\n**[LATERAL_MOVEMENT_CONFIRMED]**\n")
            return "".join(block)
        
        return ""

    def _measure_heat_correlation(self, events):
        heat_events = [e for e in events if "Plutos" in str(e.get('Source')) and "HEAT" in str(e.get('Summary', '')).upper()]
        if not heat_events: return
        print(f"   -> Measuring Heat Correlation for {len(heat_events)} burst events...")
        for h_ev in heat_events:
            burst_time = h_ev.get('dt_obj')
            if not burst_time: continue
            start_w = burst_time - datetime.timedelta(minutes=5)
            end_w = burst_time + datetime.timedelta(minutes=5)
            correlated = False
            for ev in events:
                if ev == h_ev: continue
                ev_time = ev.get('dt_obj')
                if not ev_time: continue
                if start_w <= ev_time <= end_w:
                    cat = ev.get('Category', '')
                    summary = str(ev.get('Summary', '')).lower()
                    if cat in ['EXEC', 'DROP'] or "service" in summary:
                        kws = str(ev.get('Keywords', '')).lower()
                        if any(x in kws for x in ['7z', 'rar', 'psexec', 'curl', 'wget', 'copy']):
                            h_ev['Summary'] += " [CORRELATED_WITH_EXECUTION]"
                            h_ev['Detail'] += f"\n[!] CORRELATION: Coincides with {ev['Summary']} at {ev['Time']}"
                            h_ev['Criticality'] = 100
                            ev['Criticality'] = 100
                            self.verdict_flags.add("[DATA_EXFIL_CONFIRMED]")
                            correlated = True
            if correlated:
                print(f"      [!] Heat Burst at {burst_time} confirmed as malicious activity.")

    def _extract_attack_flow(self, events):
        seen_steps = set()
        for ev in events:
            if ev.get('Criticality', 0) >= 80:
                kw = ""
                if ev.get('Keywords'): kw = f" ({ev['Keywords'][0]})"
                cat = ev['Category']
                step = ""
                if cat == "INIT": step = f"初期侵入/不正スクリプト実行{kw}"
                elif cat == "DROP": step = f"攻撃ツールの展開{kw}"
                elif cat == "C2": step = f"C2通信{kw}"
                elif cat == "PERSIST": step = f"永続化設定{kw}"
                elif cat == "ANTI": step = f"痕跡隠滅{kw}"
                elif cat == "EXEC": step = f"不正プログラム実行{kw}"
                if step and step not in seen_steps:
                    self.flow_steps.append(step)
                    seen_steps.add(step)

    def _partition_timeline(self, events, gap_threshold_hours=24):
        if not events: return []
        phases = []
        current_phase = [events[0]]
        for i in range(1, len(events)):
            prev_time = events[i-1].get('dt_obj')
            curr_time = events[i].get('dt_obj')
            if not prev_time or not curr_time:
                current_phase.append(events[i]); continue
            delta = (curr_time - prev_time).total_seconds() / 3600
            if delta > gap_threshold_hours:
                phases.append(current_phase); current_phase = []
            current_phase.append(events[i])
        phases.append(current_phase)
        return phases

    def _collect_and_filter_events(self):
        events = []
        if self.dfs.get('Prefetch') is not None:
            df = self.dfs['Prefetch']
            name_col = next((c for c in ["ExecutableName", "SourceFilename", "FileName"] if c in df.columns), None)
            time_col = next((c for c in ["LastRun", "SourceCreated", "SourceModified"] if c in df.columns), None)
            if name_col and time_col:
                for row in df.iter_rows(named=True):
                    fname = str(row[name_col])
                    if self._is_known_noise(fname): continue
                    events.append(self._create_event(
                        row[time_col], "Prefetch (PECmd)", "System", f"Process Execution: {fname}", 
                        f"Run Count: {row.get('RunCount', 1)}", 100, "EXEC", [fname]
                    ))

        if self.dfs.get('Sphinx') is not None:
            df = self.dfs['Sphinx']
            hits = df.filter(pl.col("Sphinx_Tags").str.contains("ATTACK|DECODED"))
            for row in hits.iter_rows(named=True):
                full = row.get("Decoded_Hint") or row.get("Original_Snippet") or ""
                if self._is_script_noise(full): continue
                events.append(self._create_event(
                    row['TimeCreated'], "Sphinx (PowerShell)", self._resolve_user(row, "SPHINX"),
                    f"Script Exec: {row.get('Sphinx_Tags')}", full[:300], 100, "INIT", []
                ))

        if self.dfs.get('Hercules') is not None and "Judge_Verdict" in self.dfs['Hercules'].columns:
            hits = self.dfs['Hercules'].filter(pl.col("Judge_Verdict").str.contains("CRITICAL|SUSPICIOUS"))
            for row in hits.iter_rows(named=True):
                target = str(row.get("Target_Path", ""))
                fname = self._extract_filename_from_cmd(target)
                if self._is_known_noise(fname): continue
                events.append(self._create_event(
                    row['Timestamp_UTC'], f"Hercules ({row.get('Artifact_Type')})", self._resolve_user(row, "HERCULES"),
                    f"Suspicious: {row.get('Tag')}", f"Cmd: {target}", 100 if "CRITICAL" in str(row['Judge_Verdict']) else 80, "EXEC", [fname] if fname else []
                ))

        if self.dfs.get('Plutos') is not None:
            for row in self.dfs['Plutos'].iter_rows(named=True):
                 heat = 0
                 try: heat = int(row.get('Heat_Score', 0))
                 except: pass
                 summary = f"{row.get('Plutos_Verdict')}: {row.get('Remote_IP')}"
                 crit = 90
                 if heat >= 80:
                     summary = f"[HIGH HEAT] {summary}"; crit = 95
                 events.append(self._create_event(
                     row.get('Timestamp'), "Plutos Gate", "Network",
                     summary, f"Process: {row.get('Process')}\nTags: {row.get('Tags')}", crit, "C2", [row.get('Process')]
                 ))
        
        if self.dfs.get('Pandora') is not None:
             for row in self.dfs['Pandora'].iter_rows(named=True):
                 fname = str(row.get('Ghost_FileName'))
                 if not self._is_known_noise(fname):
                     events.append(self._create_event(
                         row.get('Ghost_Time_Hint'), "Pandora (USN)", self._resolve_user(row, "PANDORA"),
                         f"File Deletion: {fname}", f"Path: {row.get('ParentPath')}", 80, "ANTI", [fname]
                     ))

        if self.dfs.get('Chronos') is not None and "FileName" in self.dfs['Chronos'].columns:
             for row in self.dfs['Chronos'].iter_rows(named=True):
                 fname = str(row.get('FileName'))
                 if not self._is_known_noise(fname):
                     score = 0
                     try: score = int(float(row.get('Chronos_Score', 0)))
                     except: pass
                     if "TIMESTOMP" in str(row.get('Anomaly_Time', '')):
                         events.append(self._create_event(row.get('si_mod_dt'), "Chronos", "System", f"Timestomp: {fname}", "", 50, "ANTI", [fname]))
                     elif score >= 150:
                         events.append(self._create_event(row.get('si_dt'), "Chronos", "System", f"File Creation: {fname}", "", 70, "DROP", [fname]))

        if self.dfs.get('AION') is not None:
            for row in self.dfs['AION'].iter_rows(named=True):
                fname = row.get('Target_FileName', 'Unknown')
                score = 0
                try: score = int(row.get('AION_Score', 0))
                except: pass
                if score >= 10:
                    events.append(self._create_event(
                        row.get('Last_Executed_Time'), "AION (Persistence)", "System",
                        f"Persistence: {fname}", f"Location: {row.get('Entry_Location')}", 95, "PERSIST", [fname]
                    ))

        return events

    def _create_event(self, time, src, user, summary, detail, crit, cat, kws):
        return {"Time": time, "Source": src, "User": user, "Summary": summary, "Detail": detail, "Criticality": crit, "Category": cat, "Keywords": kws}

    def _is_known_noise(self, fpath):
        fp = str(fpath).lower()
        fname = Path(fp).name.lower()
        if any(d in fp for d in ["windows\\system32", "program files", "winsxs", "assembly"]): return True
        if fname.endswith((".tmp", ".log", ".dat", ".xml", ".ini", ".pf", ".db")): return True
        if fname in ["svchost.exe", "explorer.exe", "chrome.exe", "edge.exe"]: return True
        return False

    def _is_script_noise(self, text):
        t = str(text).lower()
        if len(t) < 50 and "iex" not in t: return True
        return False

    def _extract_filename_from_cmd(self, text):
        m = self.re_filename.search(str(text))
        return m.group(1) if m else None

    def _extract_ip(self, text):
        m = self.re_ip.search(str(text))
        return m.group(0) if m else None

    def _resolve_user(self, row, src):
        u = str(row.get("User") or row.get("UserName") or "")
        if u and u.lower() not in ["system", "n/a", ""]: return u
        return "System/Unknown"
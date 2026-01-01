import polars as pl
import datetime
import re
from pathlib import Path
from collections import defaultdict, Counter
from tools.SH_ThemisLoader import ThemisLoader
# [New] Import separated Nemesis module
from tools.SH_NemesisTracer import NemesisTracer

# ============================================================
#  SH_AtroposThinker v2.5 [Modular Edition]
#  Mission: Analyze correlations, deduce verdicts.
#  Update: Decoupled NemesisTracer into separate module.
# ============================================================

class AtroposThinker:
    def __init__(self, dfs, siren_data, hostname):
        self.dfs = dfs
        self.siren_data = siren_data
        self.hostname = hostname
        self.loader = ThemisLoader()
        self.noise_regex = self._compile_noise_regex()

        self.valid_events = []
        self.origin_stories = []
        self.verdict_flags = set()
        self.lateral_summary = ""
        self.compromised_users = Counter()
        self.flow_steps = []
        self.re_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.re_filename = re.compile(r'([\w\-\.]+\.(?:exe|ps1|bat|dll|php|jsp|asp))', re.IGNORECASE)

    def _compile_noise_regex(self):
        patterns = []
        for rule in self.loader.noise_rules:
            p = rule.get("pattern")
            if p: patterns.append(p)
        if not patterns: return None
        try:
            return re.compile("|".join(patterns), re.IGNORECASE)
        except:
            return None

    def _is_noise(self, text):
        if not text or not self.noise_regex: return False
        return bool(self.noise_regex.search(str(text)))

    def _parse_strict_time(self, t_str):
        if not t_str: return None
        s = str(t_str).strip()
        if not s or s.lower() in ("none", "nan", ""): return None
        try:
            return datetime.datetime.fromisoformat(s.replace('Z', '+00:00').replace('T', ' '))
        except:
            formats = ["%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"]
            for fmt in formats:
                try: return datetime.datetime.strptime(s, fmt)
                except: pass
        return None

    def contemplate(self):
        print("[*] Atropos v2.5 (Modular) is contemplating the fate of artifacts...")
        
        self._preprocess_dataframes()
        raw_events = self._collect_and_filter_events()
        
        seeds = self._harvest_seeds(raw_events)
        
        # Initialize Nemesis from external module
        nemesis = NemesisTracer(self.dfs.get('Chronos'), self.dfs.get('Pandora'), self.noise_regex)
        
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
            raw_events.extend(phys_events)

        for ev in raw_events:
            if not ev.get('dt_obj'): ev['dt_obj'] = self._parse_strict_time(ev.get('Time'))
        
        self._merge_ghosts(raw_events)
        self._infer_execution_drops(raw_events)
        self._detect_privilege_escalation(raw_events)

        for ev in raw_events:
             if not ev.get('dt_obj'): ev['dt_obj'] = self._parse_strict_time(ev.get('Time'))
        raw_events.sort(key=lambda x: x.get('dt_obj') or datetime.datetime.max)

        self.origin_stories = self._analyze_origin_context(raw_events)
        self._judge_fate(raw_events)
        
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

    def _preprocess_dataframes(self):
        for key, df in self.dfs.items():
            if df is None: continue
            is_lazy = isinstance(df, pl.LazyFrame)
            lf = df if is_lazy else df.lazy()
            cols = lf.collect_schema().names()
            
            # [Golden Rule]
            lf = self.loader.apply_threat_scoring(lf)
            noise_expr = self.loader.get_noise_filter_expr(cols)
            lf = lf.filter((~noise_expr) | (pl.col("Threat_Score") > 0))
            
            self.dfs[key] = lf.collect()

    def _merge_ghosts(self, events):
        indices_to_remove = set()
        pandora_map = {}
        for i, ev in enumerate(events):
            if "Pandora" in str(ev.get('Source')):
                fname = ""
                if ev.get('Keywords'): fname = str(ev['Keywords'][0]).lower()
                key = (str(ev['Time']), fname)
                pandora_map[key] = i

        for i, ev in enumerate(events):
            if "Nemesis" in str(ev.get('Source')):
                fname = ""
                if ev.get('Keywords'): fname = str(ev['Keywords'][0]).lower()
                key = (str(ev['Time']), fname)
                if key in pandora_map:
                    indices_to_remove.add(i)
                    p_idx = pandora_map[key]
                    if "Lifecycle" not in events[p_idx]['Detail']:
                        events[p_idx]['Detail'] += f"\n(Corroborated by Nemesis Trace)"

        if indices_to_remove:
            kept = [ev for i, ev in enumerate(events) if i not in indices_to_remove]
            events.clear()
            events.extend(kept)

    # ... (Helpers: _detect_privilege_escalation, _harvest_seeds, _filter_execution_events, etc. omitted for brevity) ...
    # ※ 実装時はv2.4のヘルパーメソッドをそのままコピーしてください！
    
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
            has_tags = bool(ev.get('Tags'))
            if not has_tags and ev.get('Criticality', 0) < 85: 
                continue

            kws = ev.get('Keywords', [])
            if not kws: continue
            if isinstance(kws, str): kws = [kws]
            for k in kws:
                full_path = str(k).strip()
                if not full_path: continue
                fname_only = Path(full_path).name
                if not self._is_noise(full_path) and not self._is_noise(fname_only):
                    seeds.add(full_path)
                    if len(fname_only) > 3: seeds.add(fname_only)
        return seeds

    def _filter_execution_events(self, events):
        execs = []
        for ev in events:
            if ev.get('Category') in ['INIT', 'EXEC']:
                is_container = False
                tags = str(ev.get('Tags', ''))
                if "CONTAINER" in tags:
                    is_container = True
                if ev.get('Criticality', 0) >= 80 or is_container:
                    execs.append(ev)
        return execs

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
                    if not self._is_noise(fname): executed_files[fname] = ev 
        new_events = []
        for fname, exec_ev in executed_files.items():
            if self._is_noise(fname): continue
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
        for ev in events:
            tags = str(ev.get('Tags', ''))
            if "ROOTKIT" in tags: self.verdict_flags.add("[ROOTKIT_DETECTED]")
            if "WEBSHELL" in tags: self.verdict_flags.add("[WEBSHELL_DETECTED]")
            if "OBFUSCATION" in tags: self.verdict_flags.add("[OBFUSCATION_DETECTED]")

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
            
            extracted_ip = self._extract_ip(detail) or self._extract_ip(summary)
            if extracted_ip and not self._is_localhost(extracted_ip):
                 has_lateral = True
            
            if "LATERAL" in summary or "INTERNAL_EXFIL" in summary or "RDP_" in summary or "SMB_WMI" in kws or extracted_ip:
                has_lateral = True
                direction = "Unknown"
                if "DROP" in cat or "WROTE" in summary:
                    direction = f"INCOMING ATTACK (Target: {self.hostname})"
                elif "TRANSFER" in summary or "EXECUTED" in summary or "CONNECTION" in summary:
                    direction = f"OUTGOING ATTACK (Source: {self.hostname} -> {extracted_ip if extracted_ip else 'Unknown'})"
                
                line = f"- **[{direction}]** {ev['Summary']}"
                if extracted_ip: line += f" (IP: {extracted_ip})"
                lateral_lines.append(line)

        if has_lateral:
            self.verdict_flags.add("[LATERAL_MOVEMENT_CONFIRMED]")
            block = ["\n### 🚨 Lateral Movement & Internal Exfiltration Detected\n"]
            block.append("本端末において、横展開または内部データ持ち出しの痕跡が確認されました。\n")
            block.extend(lateral_lines)
            block.append("\n**[LATERAL_MOVEMENT_CONFIRMED]**\n")
            return "".join(block)
        return ""
    
    def _is_localhost(self, ip):
        if not ip: return False
        return ip.startswith("127.") or ip == "0.0.0.0" or ip == "::1"

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
        
        # 1. Prefetch
        if self.dfs.get('Prefetch') is not None:
            df = self.dfs['Prefetch']
            name_col = next((c for c in ["ExecutableName", "SourceFilename", "FileName"] if c in df.columns), None)
            time_col = next((c for c in ["LastRun", "SourceCreated", "SourceModified"] if c in df.columns), None)
            if name_col and time_col:
                for row in df.iter_rows(named=True):
                    fname = str(row[name_col])
                    if self._is_noise(fname): continue
                    tags = row.get("Threat_Tag", "")
                    score = int(row.get("Threat_Score", 0))
                    crit = 100 if score >= 80 else 80
                    
                    summary = f"Process Execution: {fname}"
                    if tags: summary += f" [{tags}]"
                    
                    events.append(self._create_event(
                        row[time_col], "Prefetch (PECmd)", "System", summary, 
                        f"Run Count: {row.get('RunCount', 1)}\nTags: {tags}\nScore: {score}", 
                        crit, "EXEC", [fname], tags=tags
                    ))

        # 2. Sphinx (PowerShell)
        if self.dfs.get('Sphinx') is not None:
            df = self.dfs['Sphinx']
            hits = df.filter(pl.col("Sphinx_Tags").str.contains("ATTACK|DECODED"))
            for row in hits.iter_rows(named=True):
                full = row.get("Decoded_Hint") or row.get("Original_Snippet") or ""
                if len(full) < 50 and "iex" not in str(full).lower(): continue
                events.append(self._create_event(
                    row['TimeCreated'], "Sphinx (PowerShell)", self._resolve_user(row, "SPHINX"),
                    f"Script Exec: {row.get('Sphinx_Tags')}", full[:300], 100, "INIT", [], tags=""
                ))

        # 3. Hercules (Event Logs)
        if self.dfs.get('Hercules') is not None and "Judge_Verdict" in self.dfs['Hercules'].columns:
            hits = self.dfs['Hercules'].filter(pl.col("Judge_Verdict").str.contains("CRITICAL|SUSPICIOUS"))
            for row in hits.iter_rows(named=True):
                target = str(row.get("Target_Path", ""))
                fname = self._extract_filename_from_cmd(target)
                if self._is_noise(fname): continue
                tags = row.get("Threat_Tag", "")
                events.append(self._create_event(
                    row['Timestamp_UTC'], f"Hercules ({row.get('Artifact_Type')})", self._resolve_user(row, "HERCULES"),
                    f"Suspicious: {row.get('Tag')}", f"Cmd: {target}", 100 if "CRITICAL" in str(row['Judge_Verdict']) else 80, "EXEC", [fname] if fname else [], tags=tags
                ))

        # 4. Pandora (Ghost Files)
        if self.dfs.get('Pandora') is not None:
             for row in self.dfs['Pandora'].iter_rows(named=True):
                 fname = str(row.get('Ghost_FileName'))
                 tags = row.get("Threat_Tag", "")
                 
                 score = int(row.get("Threat_Score", 0))
                 crit = 80
                 summary = f"File Deletion: {fname}"
                 
                 if score >= 90 or "WEBSHELL" in tags or "ROOTKIT" in tags:
                     crit = 100
                     summary = f"[THREAT_DETECTED] File Deletion: {fname} [{tags}]"
                     self.verdict_flags.add(f"[DETECTED: {tags}]")
                 elif score >= 50:
                     crit = 90
                     summary += f" [{tags}]"
                 
                 events.append(self._create_event(
                     row.get('Ghost_Time_Hint'), "Pandora (USN)", self._resolve_user(row, "PANDORA"),
                     summary, f"Path: {row.get('ParentPath')}\nTags: {tags}\nScore: {score}", crit, "ANTI", [fname], tags=tags
                 ))

        # 5. Chronos (Timestomping)
        if self.dfs.get('Chronos') is not None and "FileName" in self.dfs['Chronos'].columns:
             for row in self.dfs['Chronos'].iter_rows(named=True):
                 fname = str(row.get('FileName'))
                 tags = row.get("Threat_Tag", "")
                 score = int(float(row.get('Chronos_Score', 0))) 
                 themis_score = int(row.get("Threat_Score", 0)) 
                 
                 crit = 70
                 if themis_score >= 80: crit = 95
                 
                 if "TIMESTOMP" in str(row.get('Anomaly_Time', '')):
                     events.append(self._create_event(row.get('si_mod_dt'), "Chronos", "System", f"Timestomp: {fname}", f"Tags: {tags}", 50, "ANTI", [fname], tags=tags))
                 elif score >= 150 or themis_score >= 80:
                     events.append(self._create_event(row.get('si_dt'), "Chronos", "System", f"File Creation: {fname} [{tags}]", f"Tags: {tags}", crit, "DROP", [fname], tags=tags))

        # 6. AION (Persistence)
        if self.dfs.get('AION') is not None:
            for row in self.dfs['AION'].iter_rows(named=True):
                fname = row.get('Target_FileName', 'Unknown')
                if self._is_noise(fname): continue 
                score = int(row.get('AION_Score', 0))
                if score >= 10:
                    events.append(self._create_event(
                        row.get('Last_Executed_Time'), "AION (Persistence)", "System",
                        f"Persistence: {fname}", f"Location: {row.get('Entry_Location')}", 95, "PERSIST", [fname], tags=""
                    ))

        # 7. Plutos (Network)
        if self.dfs.get('Plutos') is not None:
            for row in self.dfs['Plutos'].iter_rows(named=True):
                 heat = 0
                 try: heat = int(row.get('Heat_Score', 0))
                 except: pass
                 remote_ip = row.get('Remote_IP')
                 summary = f"{row.get('Plutos_Verdict')}: {remote_ip}"
                 crit = 90
                 if heat >= 80:
                     summary = f"[HIGH HEAT] {summary}"; crit = 95
                 
                 if remote_ip and not self._is_localhost(remote_ip):
                     events.append(self._create_event(
                         row.get('Timestamp'), "Plutos Gate", "Network",
                         summary, f"Process: {row.get('Process')}\nTags: {row.get('Tags')}", crit, "C2", [row.get('Process')], tags=""
                     ))

        return events

    def _create_event(self, time, src, user, summary, detail, crit, cat, kws, tags=""):
        return {"Time": time, "Source": src, "User": user, "Summary": summary, "Detail": detail, "Criticality": crit, "Category": cat, "Keywords": kws, "Tags": tags}

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
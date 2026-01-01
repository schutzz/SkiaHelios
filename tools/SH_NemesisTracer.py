import polars as pl
import re
import datetime
from pathlib import Path

# ============================================================
#  SH_NemesisTracer v1.0 [Standalone]
#  Mission: Trace the lifecycle of artifacts across USN/MFT.
#  Origin: Extracted from Atropos v2.4 for modularity.
# ============================================================

class NemesisTracer:
    def __init__(self, df_mft, df_usn, noise_validator_regex=None):
        self.df_mft = df_mft
        self.df_usn = df_usn
        self.noise_re = noise_validator_regex
        self.id_cols = ["EntryNumber", "MftRecordNumber", "FileReferenceNumber", "ReferenceNumber"]

    def _is_noise(self, text):
        if not text or not self.noise_re: return False
        return bool(self.noise_re.search(str(text)))

    def _deduplicate_events(self, events):
        """
        同一時刻・同一サマリー・同一詳細のイベントを排除する。
        USNジャーナルの微細な更新連打を1行にまとめるッス。
        """
        unique_map = {}
        deduped = []
        
        # 優先順位: Seed Matching > ID-Chain
        events.sort(key=lambda x: (x['Time'], "Seed" in str(x.get('Detail',''))), reverse=True)

        for ev in events:
            fname = ""
            if ev.get('Keywords'): fname = str(ev['Keywords'][0]).lower()
            
            # Key: Time + FileName + Category
            key = (str(ev['Time']), fname, ev['Category'])
            
            if key not in unique_map:
                unique_map[key] = True
                deduped.append(ev)
                
        return deduped

    def trace_lifecycle(self, attack_seeds):
        if not attack_seeds: return []
        valid_seeds = [s for s in attack_seeds if len(s) > 2 and not self._is_noise(s)]
        if not valid_seeds: return []
        
        # Escape for regex
        pattern = "|".join([re.escape(s) for s in valid_seeds])
        if not pattern: return []

        lifecycle_events = []
        target_file_ids_map = {} 

        # 1. Seed Matching
        for df, src in [(self.df_mft, "MFT"), (self.df_usn, "USN")]:
            if df is None: continue
            name_cols = [c for c in ["FileName", "Ghost_FileName", "OldFileName", "Target_FileName"] if c in df.columns]
            if not name_cols: continue

            try:
                filter_expr = pl.any_horizontal([pl.col(c).str.contains(f"(?i){pattern}") for c in name_cols])
                seed_hits = df.filter(filter_expr)

                for row in seed_hits.iter_rows(named=True):
                    if self._is_noise(row.get("FileName")) or self._is_noise(row.get("ParentPath")): continue
                    
                    lifecycle_events.append(self._to_event(row, src, "Seed Matching"))
                    
                    # ID Tracking Setup
                    seq_num = row.get("SequenceNumber")
                    for c in self.id_cols:
                        if row.get(c): 
                            target_file_ids_map[str(row[c])] = seq_num
                            break
            except: pass

        # 2. ID Chain Recovery
        lifecycle_events.extend(self._recover_lifecycle_by_ids(target_file_ids_map, "ID-Chain Recovery"))
        
        return self._deduplicate_events(lifecycle_events)

    def trace_origin_by_execution(self, execution_events):
        if not execution_events: return []
        captured_ids_map = {}
        lifecycle_events = []
        dynamic_seeds = set()

        for ev in execution_events:
            exec_dt = ev.get('dt_obj')
            if not exec_dt: continue
            raw_text = str(ev.get('Detail', '')) + " " + str(ev.get('Summary', ''))
            
            # Extract new seeds from command lines
            new_discovered = self._extract_seeds_from_args(raw_text)
            dynamic_seeds.update(new_discovered)

            candidates = set()
            if ev.get('Keywords'):
                for k in ev['Keywords']:
                    k_lower = str(k).lower()
                    fname_only = k_lower.split("\\")[-1]
                    if not self._is_noise(fname_only):
                        candidates.add(fname_only)
                        candidates.add(k_lower)
            candidates.update(dynamic_seeds)
            candidates = {c for c in candidates if len(c) > 2 and not self._is_noise(c)}
            if not candidates: continue

            window_start = exec_dt - datetime.timedelta(seconds=5)
            window_end = exec_dt + datetime.timedelta(seconds=5)
            pattern = "|".join([re.escape(c) for c in candidates])
            if not pattern: continue

            # Time-Window Search
            for df in [self.df_usn, self.df_mft]:
                if df is None: continue
                time_col = next((c for c in ["Timestamp_UTC", "Last_Executed_Time", "Ghost_Time_Hint", "Time"] if c in df.columns), None)
                name_cols = [c for c in ["FileName", "Ghost_FileName", "Chaos_FileName"] if c in df.columns]
                
                if time_col and name_cols:
                    try:
                        name_filter = pl.any_horizontal([pl.col(c).str.to_lowercase().str.contains(f"(?i){pattern}") for c in name_cols])
                        hits = df.filter(name_filter)
                        for row in hits.iter_rows(named=True):
                            f_path = str(row.get("ParentPath", "")) + "\\" + str(row.get("FileName") or row.get("Ghost_FileName") or "")
                            if self._is_noise(f_path): continue

                            row_t = str(row.get(time_col)).replace('Z','')
                            try:
                                rdt = datetime.datetime.fromisoformat(row_t)
                                if not (window_start <= rdt <= window_end): continue
                            except: pass

                            for c in self.id_cols:
                                if row.get(c):
                                    entry, seq = self._parse_id(row[c])
                                    existing_seq = row.get("SequenceNumber")
                                    final_seq = existing_seq if existing_seq else seq
                                    if entry: captured_ids_map[entry] = final_seq
                                    break
                    except: pass

        if captured_ids_map:
            lifecycle_events.extend(self._recover_lifecycle_by_ids(captured_ids_map, "Origin Trace (Execution)"))
        
        return self._deduplicate_events(lifecycle_events)

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
                # Polars optimization: cast to Utf8 for matching keys
                chain_hits = df.filter(pl.col(found_col).cast(pl.Utf8).is_in(target_keys))
                
                for row in chain_hits.iter_rows(named=True):
                    if self._is_noise(row.get("FileName")) or self._is_noise(row.get("ParentPath")): continue

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
        
        return events

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
        tags = row.get("Threat_Tag", "")
        
        base_crit = 85
        try:
            score = int(row.get("Threat_Score", 0))
            if score >= 50: base_crit = 90
            if score >= 80: base_crit = 95
            if score >= 90: base_crit = 100
        except: pass

        spec = "Activity"
        if "CREATE" in reason: spec = "Birth"
        elif "DELETE" in reason: spec = "Termination"
        elif "RENAME" in reason: spec = "Identity Change"
        
        summary = f"Lifecycle Trace [{spec}]: {fname}"
        if tags: summary += f" [{tags}]"
        
        if old_name and old_name != fname: summary = f"Lifecycle Trace [Identity Shift]: {old_name} -> {fname}"
        
        t_str = str(row.get("si_dt") or row.get("Ghost_Time_Hint") or row.get("Timestamp_UTC"))
        
        return {
            "Time": t_str,
            "Source": f"Nemesis ({source_type})",
            "User": "System/Inferred",
            "Summary": summary,
            "Detail": f"Mode: {mode} | Reason: {reason}\nPath: {row.get('ParentPath')}\nOwner: {owner}\nTags: {tags}",
            "Criticality": base_crit, 
            "Category": "ANTI" if "DELETE" in reason else "DROP",
            "Keywords": [fname],
            "Owner_SID": owner,
            "Tags": tags,
            "dt_obj": None 
        }
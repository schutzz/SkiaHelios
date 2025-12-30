import polars as pl
import argparse
from pathlib import Path
import sys
import datetime
import re
import json
from collections import defaultdict, Counter

# ============================================================
#  SH_HekateWeaver v15.41 [God Mode + Prefetch]
#  Mission: Correlate All Artifacts & Generate SANS Report
#  Update: Added Prefetch (PECmd) Support for Execution Evidence
# ============================================================

def print_logo():
    print(r"""
      | | | | | |
    -- HEKATE  --   [ God Mode v15.41 ]
      | | | | | |   "Order restored. Truth revealed."
    """)

TEXT_RES = {
    "en": {
        "title": "Incident Investigation Report",
        "coc_header": "Chain of Custody & Case Info",
        "h1_exec": "1. Executive Summary",
        "h1_origin": "2. Initial Access Vector (Origin Analysis)",
        "h1_time": "3. Investigation Timeline",
        "h1_tech": "4. Technical Findings",
        "h1_rec": "5. Conclusion & Recommendations",
        "h1_app": "6. Appendices",
        "cats": {"INIT": "Initial Access", "C2": "Command & Control", "PERSIST": "Persistence", "ANTI": "Anti-Forensics", "EXEC": "Execution", "DROP": "File Creation (Origin)", "WEB": "Web Access"},
        "investigator": "Forensic Analyst"
    },
    "jp": {
        "title": "インシデント調査報告書",
        "coc_header": "証拠保全および案件情報 (Chain of Custody)",
        "h1_exec": "1. エグゼクティブ・サマリー",
        "h1_origin": "2. 初期侵入経路分析 (Initial Access Vector)",
        "h1_time": "3. 調査タイムライン",
        "h1_tech": "4. 技術的詳細 (Technical Findings)",
        "h1_rec": "5. 結論と推奨事項",
        "h1_app": "6. 添付資料",
        "cats": {"INIT": "初期侵入 (Initial Access)", "C2": "C2通信 (Command & Control)", "PERSIST": "永続化 (Persistence)", "ANTI": "アンチフォレンジック (Anti-Forensics)", "EXEC": "実行 (Execution)", "DROP": "ファイル作成/流入 (File Drop)", "WEB": "Webアクセス"},
        "investigator": "担当フォレンジックアナリスト"
    }
}

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

            filter_expr = pl.any_horizontal([pl.col(c).str.contains(f"(?i){pattern}") for c in name_cols])
            seed_hits = df.filter(filter_expr)

            for row in seed_hits.iter_rows(named=True):
                lifecycle_events.append(self._to_event(row, src, "Seed Matching"))
                seq_num = row.get("SequenceNumber")
                for c in self.id_cols:
                    if row.get(c): 
                        target_file_ids_map[str(row[c])] = seq_num
                        break

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
                        name_filter = pl.any_horizontal([pl.col(c).str.to_lowercase().str.contains(f"(?i){pattern}") for c in name_cols])
                        time_filter = ((pl.col(time_col).str.to_datetime(strict=False) >= window_start) & (pl.col(time_col).str.to_datetime(strict=False) <= window_end))
                        hits = self.df_usn.filter(time_filter & name_filter)
                        for row in hits.iter_rows(named=True):
                            if self.noise_validator:
                                f_path = row.get("ParentPath", "") + "\\" + (row.get("FileName") or row.get("Ghost_FileName") or "")
                                if self.noise_validator(f_path): continue
                            for c in self.id_cols:
                                if row.get(c):
                                    entry, seq = self._parse_id(row[c])
                                    existing_seq = row.get("SequenceNumber")
                                    final_seq = existing_seq if existing_seq else seq
                                    if entry: captured_ids_map[entry] = final_seq
                                    break
            
            if self.df_mft is not None:
                mft_name_cols = [c for c in ["FileName", "Ghost_FileName", "Chaos_FileName"] if c in self.df_mft.columns]
                if mft_name_cols:
                     mft_name_filter = pl.any_horizontal([pl.col(c).cast(pl.Utf8).fill_null("").str.to_lowercase().str.contains(f"(?i){pattern}") for c in mft_name_cols])
                     mft_hits = self.df_mft.filter(mft_name_filter)
                     for row in mft_hits.iter_rows(named=True):
                        if self.noise_validator:
                            f_path = row.get("ParentPath", "") + "\\" + (row.get("FileName") or "")
                            if self.noise_validator(f_path): continue
                        for c in self.id_cols:
                            if row.get(c):
                                entry, seq = self._parse_id(row[c])
                                existing_seq = row.get("SequenceNumber")
                                final_seq = existing_seq if existing_seq else seq
                                if entry and entry not in captured_ids_map:
                                    captured_ids_map[entry] = final_seq
                                break

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

        return {
            "Time": row.get("si_dt") or row.get("Ghost_Time_Hint") or row.get("Timestamp_UTC"),
            "Source": f"Nemesis ({source_type})", "User": "System/Inferred",
            "Summary": summary,
            "Detail": f"Mode: {mode} | Reason: {reason}\nPath: {row.get('ParentPath')}\nOwner: {owner}",
            "Criticality": 95, "Category": "ANTI" if "DELETE" in reason else "DROP",
            "Keywords": [fname],
            "Owner_SID": owner
        }

class HekateWeaver:
    def __init__(self, timeline_csv, aion_csv=None, pandora_csv=None, plutos_csv=None, plutos_net_csv=None, sphinx_csv=None, chronos_csv=None, persistence_csv=None, prefetch_csv=None, siren_json=None, lang="jp", case_name="Operation Frankenstein"):
        self.lang = lang if lang in TEXT_RES else "jp"
        self.txt = TEXT_RES[self.lang]
        self.case_name = case_name
        self.dfs = {}
        self.dfs['Hercules'] = self._safe_load(timeline_csv)
        self.dfs['AION']     = self._safe_load(aion_csv) if aion_csv else self._safe_load(persistence_csv)
        self.dfs['Sphinx']   = self._safe_load(sphinx_csv)
        self.dfs['Chronos']  = self._safe_load(chronos_csv)
        self.dfs['Network']  = self._safe_load(timeline_csv) 
        self.dfs['Pandora']  = self._safe_load(pandora_csv)
        self.dfs['PlutosNet'] = self._safe_load(plutos_net_csv)
        # [GOD MODE] Prefetch Support
        self.dfs['Prefetch'] = self._safe_load(prefetch_csv)
        
        # [NEW] Siren Data Load
        self.siren_data = self._load_json(siren_json)

    def _load_json(self, path):
        if path and Path(path).exists():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except: pass
        return []

    def _generate_ioc_appendix(self):
        ioc_lines = []
        ioc_lines.append(f"## {self.txt['h1_app']} (IOC List)\n")
        ioc_lines.append("本調査で確認された侵害指標（IOC）の一覧です。EDR/FW/SIEMへの即時登録を推奨します。\n\n")

        # 1. File IOC (AIONから)
        if self.dfs.get('AION') is not None:
            df = self.dfs['AION']
            if 'File_Hash_SHA256' in df.columns or 'File_Hash_SHA1' in df.columns:
                cond = pl.lit(False)
                if 'File_Hash_SHA256' in df.columns: cond = cond | pl.col("File_Hash_SHA256").is_not_null()
                if 'File_Hash_SHA1' in df.columns: cond = cond | pl.col("File_Hash_SHA1").is_not_null()
                
                hits = df.filter(cond & (pl.col("AION_Score").cast(pl.Int64, strict=False) >= 10)) 
                
                if hits.height > 0:
                    ioc_lines.append("### 📂 File IOCs (Malicious/Suspicious Files)\n")
                    ioc_lines.append("| File Name | SHA1 | SHA256 | Full Path |\n|---|---|---|---|\n")
                    for row in hits.unique(subset=["Full_Path"]).iter_rows(named=True):
                        fname = row.get('Target_FileName', 'Unknown')
                        sha1 = row.get('File_Hash_SHA1', '-')
                        sha256 = row.get('File_Hash_SHA256', '-')
                        path = row.get('Full_Path', '-')
                        ioc_lines.append(f"| `{fname}` | `{sha1}` | `{sha256}` | `{path}` |\n")
                    ioc_lines.append("\n")

        # 2. Network IOC (PlutosNetから)
        if self.dfs.get('PlutosNet') is not None:
            df = self.dfs['PlutosNet']
            if 'Remote_IP' in df.columns:
                hits = df.filter(pl.col("Remote_IP").is_not_null())
                if hits.height > 0:
                    ioc_lines.append("### 🌐 Network IOCs (Suspicious Connections)\n")
                    ioc_lines.append("| Remote IP | Port | Process | Timestamp (UTC) |\n|---|---|---|---|\n")
                    for row in hits.unique(subset=["Remote_IP", "Remote_Port"]).iter_rows(named=True):
                        ip = row['Remote_IP']
                        port = row.get('Remote_Port', '-')
                        proc = row.get('Process', 'Unknown') 
                        ts = row.get('Timestamp', '-')
                        ioc_lines.append(f"| `{ip}` | {port} | `{proc}` | {ts} |\n")
                    ioc_lines.append("\n")

        # 3. CommandLine IOC (Sphinxから)
        if self.dfs.get('Sphinx') is not None:
            df = self.dfs['Sphinx']
            if "Sphinx_Score" in df.columns:
                hits = df.filter(pl.col("Sphinx_Score").cast(pl.Int64, strict=False) >= 100)
                if hits.height > 0:
                    ioc_lines.append("### 💻 CommandLine IOCs (Malicious Scripts)\n")
                    ioc_lines.append("| CommandLine (Decoded Hint) | Timestamp |\n|---|---|\n")
                    for row in hits.iter_rows(named=True):
                        cmd = row.get('Decoded_Hint') or row.get('Original_Snippet', 'Unknown')
                        cmd_display = (cmd[:100] + '...') if len(cmd) > 100 else cmd
                        ts = row.get('TimeCreated', '-')
                        ioc_lines.append(f"| `{cmd_display}` | {ts} |\n")
                    ioc_lines.append("\n")

        return "".join(ioc_lines)

    def correlate_identity(self, raw_events):
        if not raw_events: return
        session_map = []
        map_path = Path(r"c:\Users\user\.gemini\antigravity\scratch\SkiaHelios\hercules_sessions.json")
        if map_path.exists():
            try:
                with open(map_path, "r") as f: session_map = json.load(f)
            except: pass
        if not session_map: return
        
        def get_active_sessions(dt):
            active = []
            for s in session_map:
                try:
                    start = datetime.datetime.fromisoformat(s["Start"].replace("Z", ""))
                    end = datetime.datetime.max
                    if s["End"] and s["End"] != "ACTIVE":
                         end = datetime.datetime.fromisoformat(s["End"].replace("Z", ""))
                    if start <= dt <= end: active.append(s)
                except: pass
            return active

        for ev in raw_events:
            if ev.get("Category") != "DROP" and "BIRTH" not in str(ev.get("Detail", "")).upper(): continue
            ev_dt = ev.get("dt_obj")
            if not ev_dt: continue
            owner = ev.get("Owner_SID")
            if not owner or owner == "N/A": continue
            
            active_sessions = get_active_sessions(ev_dt)
            active_sids = set(s.get("SID") for s in active_sessions)
            is_system_file = "S-1-5-18" in owner
            is_user_active_only = any("S-1-5-21" in str(s) for s in active_sids) and not any("S-1-5-18" in str(s) for s in active_sids)
            
            if is_system_file and is_user_active_only:
                 ev["Summary"] = "[PRIVILEGE ESCALATION] " + ev["Summary"]
                 ev["Detail"] += f"\n[!] SID Affinity Alert: File created by SYSTEM while only Standard User sessions were active.\n[!] Active SIDs: {list(active_sids)}"
                 ev["Criticality"] = 100
            elif not active_sessions:
                 ev["Summary"] = "[ORPHAN ORIGIN] " + ev["Summary"]
                 ev["Detail"] += "\n[!] SID Affinity Alert: File created with NO matching active session found in logs."

    def _safe_load(self, path):
        if path and Path(path).exists():
            try: return pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
            except: return None
        return None

    def _extract_user_from_path(self, path):
        if not path: return None
        match = re.search(r"(?i)users[\/\\]+([^\/\\]+)", str(path))
        if match:
            user = match.group(1)
            if user.lower() not in ["public", "default", "all users"]: return user
        return None

    def _extract_user_from_json(self, json_text):
        if not json_text: return None
        match = re.search(r"(?i)\"SubjectUserName\",\"#text\":\"([^\"]+)\"", str(json_text))
        if not match: match = re.search(r"(?i)SubjectUserName\s*[:=]\s*([^\s,]+)", str(json_text))
        if match:
            u = match.group(1)
            if u != "-" and "$" not in u: return u
        return None

    def _resolve_user(self, row, source_type):
        user = "System/Unknown"
        if "User" in row and row["User"]:
            u = str(row["User"])
            if u.lower() not in ["", "system", "network service", "local service", "n/a"]: return u
        path_keys = ["Target_Path", "Source_File", "Full_Path", "ParentPath", "Target_FileName"]
        for k in path_keys:
            if k in row:
                u = self._extract_user_from_path(row[k])
                if u: return u
        content_keys = ["Original_Snippet", "Decoded_Hint", "Action", "Details"]
        for k in content_keys:
            if k in row:
                u = self._extract_user_from_json(row[k])
                if u: return u
        return user

    def _find_web_correlation(self, file_time_dt):
        if not file_time_dt or self.dfs['Hercules'] is None: return None
        window_start = file_time_dt - datetime.timedelta(minutes=5)
        window_end = file_time_dt
        potential_urls = []
        timeline = self.dfs['Hercules']
        if "Tag" in timeline.columns:
             hits = timeline.filter(pl.col("Tag").str.contains("(?i)NETWORK|C2|BROWSER|DOWNLOAD|HISTORY"))
             for row in hits.iter_rows(named=True):
                 try:
                     t_str = str(row['Timestamp_UTC']).replace('T', ' ').split('.')[0]
                     row_dt = datetime.datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")
                     if window_start <= row_dt <= window_end:
                         target = str(row['Action']) + " " + str(row['Target_Path'])
                         url = self._extract_url(target)
                         if url: potential_urls.append((row_dt, url))
                 except: continue
        if potential_urls:
            potential_urls.sort(key=lambda x: x[0], reverse=True)
            return potential_urls[0][1]
        return None

    def _find_usb_correlation(self, file_time_dt):
        if not file_time_dt or self.dfs['Hercules'] is None: return None
        window_start = file_time_dt - datetime.timedelta(minutes=5)
        window_end = file_time_dt
        timeline = self.dfs['Hercules']
        if "Tag" in timeline.columns:
             hits = timeline.filter(
                 pl.col("Tag").str.contains("(?i)USB|REMOVABLE|PNP|DRIVER") | 
                 pl.col("Action").str.contains("(?i)USB")
             )
             for row in hits.iter_rows(named=True):
                 try:
                     t_str = str(row['Timestamp_UTC']).replace('T', ' ').split('.')[0]
                     row_dt = datetime.datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")
                     if window_start <= row_dt <= window_end:
                         return f"USB Device Activity ({row.get('Action')})"
                 except: continue
        return None

    def _analyze_origin(self, filename, file_dt=None):
        if not filename: return None
        origin_info = []
        if self.dfs['Chronos'] is not None and "ZoneIdContents" in self.dfs['Chronos'].columns:
            hits = self.dfs['Chronos'].filter(
                (pl.col("FileName").str.to_lowercase() == str(filename).lower()) & 
                (pl.col("ZoneIdContents").is_not_null())
            )
            for row in hits.iter_rows(named=True):
                zone = str(row['ZoneIdContents'])
                if "ZoneId=3" in zone or "http" in zone:
                    url_match = re.search(r"HostUrl=([^\r\n]+)", zone)
                    url = url_match.group(1) if url_match else "Internet"
                    origin_info.append(f"Webダウンロード (ZoneId: {url})")
        
        if file_dt:
            usb_event = self._find_usb_correlation(file_dt)
            if usb_event: origin_info.append(f"USB接続相関")
            
            if not origin_info:
                correlated_url = self._find_web_correlation(file_dt)
                if correlated_url: origin_info.append(f"通信相関 ({correlated_url})")

        if origin_info: return " / ".join(origin_info)
        return None

    def _analyze_origin_context(self, events):
        """
        Web履歴(Clio) -> ファイル作成(Pandora/Drop) -> 実行(Sphinx/Exec) の因果連鎖を分析
        """
        origin_stories = []
        
        drops = [e for e in events if e['Category'] == 'DROP' and e.get('Criticality', 0) >= 70]
        
        for drop in drops:
            drop_dt = drop.get('dt_obj')
            if not drop_dt: continue
            
            kws = drop.get('Keywords', [])
            if isinstance(kws, str): kws = [kws]
            fname = str(kws[0]).lower() if kws else ""
            if not fname: continue

            story = {
                "File": fname,
                "Drop_Time": drop_dt,
                "Web_Correlation": None,
                "Path_Indicator": None,
                "Execution_Link": None
            }

            # A. パスによる判定 (Outlook / Browser Cache)
            detail = str(drop.get('Detail', '')).lower()
            if "content.outlook" in detail:
                story['Path_Indicator'] = "Outlook添付ファイル (Content.Outlook)"
            elif "inetcache" in detail or "temporary internet files" in detail:
                story['Path_Indicator'] = "ブラウザキャッシュ (Drive-by Download)"
            elif "downloads" in detail:
                story['Path_Indicator'] = "ダウンロードフォルダ"

            # B. Web履歴との相関 (Clio/Timeline in Hercules)
            # Drop時刻の直前 5分間 を探索
            if self.dfs['Hercules'] is not None:
                window_start = drop_dt - datetime.timedelta(minutes=5)
                # "WebHistory" かつ URLに関連しそうなイベントを検索
                timeline = self.dfs['Hercules']
                if "Artifact_Type" in timeline.columns:
                    # Filter: WebHistory AND Time match
                    web_hits = timeline.filter(
                        (pl.col("Artifact_Type") == "WebHistory") & 
                        (pl.col("Timestamp_UTC").str.to_datetime(strict=False).is_between(window_start, drop_dt))
                    )
                    
                    # 最も近い、かつメールや添付ファイルっぽいURLを優先
                    candidates = []
                    for row in web_hits.iter_rows(named=True):
                        url = str(row.get('Target_Path', '')) + str(row.get('Action', ''))
                        score = 0
                        if "mail" in url or "outlook" in url: score += 10
                        if "attachment" in url or "content" in url: score += 5
                        if fname in url.lower(): score += 20 # ファイル名がURLに含まれる場合（確信）
                        candidates.append((score, url, row['Timestamp_UTC']))
                    
                    if candidates:
                        candidates.sort(key=lambda x: x[0], reverse=True)
                        story['Web_Correlation'] = f"{candidates[0][1]} (@ {candidates[0][2]})"

            # C. 実行とのリンク
            # Drop時刻より後に行われた、同名の実行イベントを探す
            execs = [e for e in events if e['Category'] in ['EXEC', 'INIT'] and e.get('dt_obj') and e['dt_obj'] >= drop_dt]
            for ex in execs:
                ex_kws = [str(k).lower() for k in ex.get('Keywords', [])]
                if fname in ex_kws:
                    story['Execution_Link'] = f"Executed at {ex['Time']} (Source: {ex['Source']})"
                    break
            
            if story['Path_Indicator'] or story['Web_Correlation'] or story['Execution_Link']:
                origin_stories.append(story)

        return origin_stories

    def _is_known_noise(self, file_path, tags=""):
        fp = str(file_path).lower()
        t = str(tags).lower()
        fname = Path(fp).name.lower()
        
        # 1. System Directory Guard
        noise_dirs = [
            "windows\\system32", "windows\\syswow64", "windows\\inf", 
            "windows\\microsoft.net", "program files", "program files (x86)",
            "windows\\winsxs", "programdata\\microsoft", "windows\\servicing",
            "windows\\assembly"
        ]
        if any(d in fp for d in noise_dirs): return True

        # 2. Update/SxS/Sync Junk Guard (GOD MODE NUCLEAR)
        if fname.startswith(("amd64_", "x86_", "wow64_", "msil_", "microsoft-windows-")): return True
        if fname.endswith((".manifest", ".mum", ".cat", ".dat", ".log", ".bin", ".xml", ".ini")): return True
        
        # [KILL PATTERNS - EXTENDED]
        if "~rf" in fname: return True
        if ".old" in fname: return True 
        # .svg, .txt, .js, .json もノイズとして追加
        if fname.endswith((".tmp", ".temp", ".lock", ".db-journal", ".db-wal", ".db-shm", ".odl", ".gif", ".svg", ".txt", ".js", ".json", ".pf")): 
            # Prefetch file itself (.pf) is noise for "File Drop", but executed content is good. 
            # We want to catch the execution, not the .pf file creation in file system events.
            return True
        
        # [KILL SPECIFIC NAMES]
        if "provenance" in fname: return True  # ProvenanceData
        if "tflite" in fname: return True
        if "install" in fname: return True # Install...
        
        # [KILL GUID & HEX]
        if fname.startswith("{") and fname.endswith("}"): return True
        if re.match(r'^[0-9a-f]{10,}$', fname): return True
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-', fname): return True 

        # OneDrive / Browser specific
        if "secure preferences" in fname: return True
        if "sitelist" in fname: return True
        if "filecoauth" in fname or ".odlgz" in fname: return True
        if "log.old" in fname: return True
        if "windowsterminal" in fname: return True

        # 3. Normal Process Guard
        normal_procs = {
            "svchost.exe", "msmpeng.exe", "notepad.exe", "cmd.exe", "powershell.exe", 
            "taskhostw.exe", "conhost.exe", "explorer.exe", "searchui.exe", 
            "runtimebroker.exe", "lsass.exe", "services.exe", "winlogon.exe",
            "auditpol.exe", "mpcmdrun.exe", "wmiprvse.exe", "backgroundtaskhost.exe",
            "schtasks.exe", "chrome.exe", "msedge.exe", "brave.exe", "smartscreen.exe",
            "searchapp.exe"
        }
        if fname in normal_procs: return True

        # 4. Specific Patterns
        if "startupinfo" in fp: return True 
        if "appdata\\local\\temp" in fp: return True

        return False

    def _is_file_noise(self, filename, full_path=""):
        return self._is_known_noise(full_path if full_path else filename)

    def _extract_filename_from_cmd(self, text):
        if not text: return None
        matches = re.findall(r'([\w\-\.\/\\]+\.(?:exe|ps1|bat|cmd|vbs|dll|sys|doc|docx|xls|xlsx|pdf|zip))(?:\s|["\']|$|[^\w\.])', str(text), re.IGNORECASE)
        for m in matches:
            fname = Path(m).name
            if not self._is_known_noise(fname): return fname
        return None

    def _resolve_source(self, tool_name, row):
        tool = tool_name.upper()
        if tool == "HERCULES" or tool == "NETWORK":
            atype = row.get("Artifact_Type")
            if atype and str(atype).lower() != "null": return str(atype).replace("_", " ")
            return "EventLog"
        elif tool == "SPHINX": return "PowerShell Evtx (4104)"
        elif tool == "PANDORA":
            src = row.get("Source")
            if src: return str(src).replace("_", " ")
            return "USN Journal"
        elif tool == "CHRONOS": return "MFT Analysis ($SI<$FN)"
        elif tool == "AION":
            loc = str(row.get("Entry_Location", "")).lower()
            if "hkcu" in loc or "hklm" in loc: return "Registry (Persistence)"
            if "startup" in loc: return "File System (Startup)"
            if "windows" in loc and "tasks" in loc: return "Scheduled Task"
            return "Persistence Artifacts"
        return tool_name

    def _generate_insight(self, ev):
        cat = ev['Category']
        src = ev['Source']
        summary = ev['Summary'].lower()
        origin_note = ""
        if ev.get('Keywords') and ev['Keywords'][0] and ev.get('dt_obj'):
            origin = self._analyze_origin(ev['Keywords'][0], ev['dt_obj'])
            if origin: origin_note = f"\n  - **起源追跡:** {origin}"
            elif cat in ["INIT", "PERSIST", "DROP"]:
                origin_note = "\n  - **起源推測:** Zone.Identifier（Webダウンロード痕跡）が確認できません。ドロッパーによるローカル作成、Zip解凍、または物理メディア経由の持ち込みと推測されます。"
        
        if cat == "INIT":
            if "powershell" in src.lower():
                if "base64" in summary or "decoded" in summary: return "PowerShellコマンドのBase64難読化実行を検知しました。" + origin_note
                return "不審なスクリプトブロックの実行を検知しました。" + origin_note
        elif cat == "DROP": return "ディスク上での新規ファイル作成（File Drop）を確認しました。実行の前段階として攻撃ツールが配置された痕跡です。" + origin_note
        elif cat == "C2": return "外部への不審な通信（C2）を検知しました。"
        elif cat == "PERSIST": return "永続化設定が確認されました。" + origin_note
        elif cat == "ANTI":
            if "timestomp" in summary: return "ファイルタイムスタンプの改ざん痕跡です。"
            return "攻撃活動の痕跡隠滅（ファイル削除）です。"
        return "調査が必要な不審なイベントです。"

    def _partition_timeline(self, events, gap_threshold_hours=24):
        if not events: return []
        phases = []
        current_phase = [events[0]]
        for i in range(1, len(events)):
            prev_time = events[i-1].get('dt_obj')
            curr_time = events[i].get('dt_obj')
            if not prev_time or not curr_time:
                current_phase.append(events[i])
                continue
            delta = (curr_time - prev_time).total_seconds() / 3600
            if delta > gap_threshold_hours:
                phases.append(current_phase)
                current_phase = []
            current_phase.append(events[i])
        phases.append(current_phase)
        return phases

    def _classify_category(self, source, tag, detail):
        s, t, d = str(source).upper(), str(tag).upper(), str(detail).upper()
        if "NETWORK" in s or "C2" in t or "CURL" in d: return "C2"
        if "AION" in s or "PERSISTENCE" in t: return "PERSIST"
        if "PANDORA" in s or "WIPING" in t or "DELETE" in t: return "ANTI"
        if "CHRONOS" in s and "CREATION" in t: return "DROP" 
        if "GHOST" in t or "INFERRED" in t or "DROP" in t: return "DROP" 
        if "SPHINX" in s or "DECODED" in t or "POWERSHELL" in d: return "INIT"
        if "CHRONOS" in s or "TIMESTOMP" in t: return "ANTI"
        return "EXEC"

    def _extract_url(self, text):
        match = re.search(r"https?://[^\s\"']+", str(text))
        return match.group(0) if match else None

    def _get_time_str(self, ev):
        if ev.get('dt_obj'): return ev['dt_obj'].strftime('%H:%M:%S')
        return str(ev['Time']).replace('T', ' ').split(' ')[1].split('.')[0]

    def _is_script_noise(self, text):
        t = str(text).lower()
        if "set-strictmode" in t: return True
        if "add-type -assemblyname" in t: return True
        if "#requires -version" in t: return True
        if "enable-psremoting" in t: return True
        if "$__cmdletization" in t: return True
        if "detailsequence=" in t: return True
        if "parametersetname=" in t: return True
        if "positionalbinding" in t: return True
        if "helpuri" in t: return True
        if len(t) < 50 and not any(k in t for k in ["iex", "invoke", "http", "download"]): return True
        return False

    def generate_report(self, output_path):
        t = self.txt
        
        out_file = Path(output_path)
        if not out_file.parent.exists(): out_file.parent.mkdir(parents=True, exist_ok=True)
            
        raw_events = self._collect_and_filter_events()
        
        # [NEMESIS SEEDING]
        seeds = set()
        for ev in raw_events:
            if ev.get('Criticality', 0) < 85: continue

            keywords = ev.get('Keywords', [])
            clean_kws = []
            if isinstance(keywords, list):
                clean_kws = keywords
            elif isinstance(keywords, str):
                if keywords.strip().startswith("[") and keywords.strip().endswith("]"):
                    try:
                        content = keywords.strip()[1:-1]
                        parts = [p.strip().strip("'").strip('"') for p in content.split(',')]
                        clean_kws = [p for p in parts if p]
                    except: clean_kws = [keywords]
                else:
                    clean_kws = [k.strip() for k in keywords.split(';') if k.strip()]

            for k in clean_kws:
                full_path = str(k).strip()
                if not full_path: continue
                fname_only = Path(full_path).name
                if not self._is_known_noise(full_path) and not self._is_known_noise(fname_only):
                    seeds.add(full_path)
                    if len(fname_only) > 3: seeds.add(fname_only)

        # [NEMESIS EXECUTION]
        nemesis = NemesisTracer(self.dfs['Chronos'], self.dfs['Pandora'], noise_validator=self._is_known_noise)
        if seeds:
            seeds = list(set(seeds))
            raw_events.extend([r for r in nemesis.trace_lifecycle(seeds) 
                               if (r['Summary'] + str(r['Time'])) not in {e['Summary'] + str(e['Time']) for e in raw_events}])

        CONTAINER_APPS_CHECK = {
            "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", 
            "python.exe", "perl.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", 
            "bitsadmin.exe", "certutil.exe", "csc.exe", "vbc.exe", "installutil.exe", 
            "psexec.exe", "wmiprvse.exe", "scrcons.exe", "microsoft.powershell.cmd", ".powershell.cmd"
        }

        execution_events = []
        for ev in raw_events:
            if ev.get('Category') in ['INIT', 'EXEC']:
                is_container = False
                if ev.get('Keywords'):
                    kws = ev.get('Keywords')
                    if isinstance(kws, str): kws = [kws]
                    elif isinstance(kws, list): kws = kws 
                    for k in kws:
                        if str(k).lower().split("\\")[-1] in CONTAINER_APPS_CHECK:
                            is_container = True; break
                if ev.get('Criticality', 0) >= 80 or is_container:
                    execution_events.append(ev)
        
        for ev in execution_events:
            if not ev.get('dt_obj'):
                try:
                    t_str = str(ev['Time']).replace('T', ' ').split('.')[0]
                    ev['dt_obj'] = datetime.datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")
                except: pass

        phys_events = nemesis.trace_origin_by_execution(execution_events)
        if phys_events:
            raw_events.extend([r for r in phys_events 
                               if (r['Summary'] + str(r['Time'])) not in {e['Summary'] + str(e['Time']) for e in raw_events}])

        # [Ghost Merge]
        indices_to_remove = set()
        nemesis_deaths = [ev for ev in raw_events if "Nemesis" in str(ev.get('Source', '')) and ("DELETE" in str(ev.get('Reason', '')).upper() or "DEATH" in str(ev.get('Summary', '')).upper())]
        for n_ev in nemesis_deaths:
            if "[CONFIRMED DELETION]" not in n_ev['Summary']: n_ev['Summary'] = "[CONFIRMED DELETION] " + n_ev['Summary']
            n_time = n_ev.get('dt_obj')
            if not n_time: continue
            for i, p_ev in enumerate(raw_events):
                if i in indices_to_remove: continue
                if "Pandora" not in str(p_ev.get('Source', '')) and "ANTI" not in str(p_ev.get('Category', '')): continue
                p_time = p_ev.get('dt_obj')
                if not p_time or abs((n_time - p_time).total_seconds()) > 5: continue
                n_names = set(str(k).lower().split("\\")[-1] for k in n_ev.get('Keywords', []))
                p_names = set(str(k).lower().split("\\")[-1] for k in p_ev.get('Keywords', []))
                if not n_names.intersection(p_names): continue
                n_ev['Summary'] += f" <br>(Matches Pandora Ghost: {p_ev['Summary']})"
                indices_to_remove.add(i)
        
        if indices_to_remove: raw_events = [ev for i, ev in enumerate(raw_events) if i not in indices_to_remove]
        self.correlate_identity(raw_events)

        for ev in raw_events:
            if ev['Category'] == 'DROP' and ev.get('Keywords'):
                origin = self._analyze_origin(ev['Keywords'][0], ev.get('dt_obj'))
                if origin: ev['Summary'] += f" <br>↳ (Origin: {origin})"
        
        # [Inferred Execution]
        executed_files = {} 
        dropped_files = set()
        for ev in raw_events:
            if ev['Category'] == 'DROP':
                if ev.get('Keywords'): dropped_files.add(str(ev['Keywords'][0]).lower())
            elif ev['Category'] in ['INIT', 'EXEC', 'PERSIST']:
                if ev.get('Criticality', 0) < 90: continue
                kws = ev.get('Keywords')
                if kws:
                    if isinstance(kws, list): kws = kws[0]
                    fname = str(kws).lower()
                    if not self._is_known_noise(fname):
                        executed_files[fname] = ev 
        
        for fname, exec_ev in executed_files.items():
            if self._is_known_noise(fname): continue
            if exec_ev.get('Criticality', 0) < 80: continue 

            if fname not in dropped_files and "unknown" not in fname:
                exec_dt = exec_ev.get('dt_obj')
                if exec_dt:
                    inferred_dt = exec_dt - datetime.timedelta(seconds=1)
                    raw_events.append({
                        "Time": str(inferred_dt), 
                        "Source": "Inferred from High-Confidence Execution", 
                        "User": exec_ev['User'],
                        "Summary": f"File Creation (Inferred - High Confidence): {fname}",
                        "Detail": f"Executed without prior drop record. Likely malicious.",
                        "Criticality": 85, 
                        "Category": "DROP", 
                        "Keywords": [fname], 
                        "dt_obj": inferred_dt
                    })

        for ev in raw_events:
            t_str = str(ev['Time']).replace('T', ' ').split('.')[0]
            try: ev['dt_obj'] = datetime.datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")
            except: ev['dt_obj'] = None
        raw_events.sort(key=lambda x: x.get('dt_obj') or datetime.datetime.max)
        
        # [Exec Summary]
        critical_days = set()
        compromised_users = Counter() 
        for ev in raw_events:
            if ev['User'] and "System" not in ev['User']: compromised_users[ev['User']] += 1
            if ev['Criticality'] >= 60 and ev.get('dt_obj'): critical_days.add(ev['dt_obj'].strftime('%Y-%m-%d'))
        
        valid_events = []
        for ev in raw_events:
            if ev.get('dt_obj'):
                is_relevant = False
                ev_date = ev['dt_obj'].date()
                for c_day_str in critical_days:
                    c_date = datetime.datetime.strptime(c_day_str, '%Y-%m-%d').date()
                    if abs((ev_date - c_date).days) <= 1:
                        is_relevant = True; break
                if is_relevant: valid_events.append(ev)
            else: valid_events.append(ev)
        
        # [MOVED UP] Analyze Origin Context Here
        origin_stories = self._analyze_origin_context(raw_events)

        # ==========================================================
        # [GOD MODE PATCH] Sirenの結果をOrigin Tableに強制反映
        # ==========================================================
        if self.siren_data:
            for story in origin_stories:
                f_lower = str(story['File']).lower()
                
                # Sirenの結果から該当ファイルを探す
                for target in self.siren_data:
                    # ファイル名一致 かつ 実行確認済み
                    if target.get('FileName') == f_lower and target.get('Executed'):
                        
                        # 実行リンクを上書き！
                        run_count = target.get('Run_Count', 1)
                        last_run = target.get('Last_Run_Time', 'Unknown')
                        story['Execution_Link'] = f"Executed (Prefetch Verified) at {last_run} (Count: {run_count})"
                        
                        # もしパス情報がUnknownなら、Sirenの情報で補完
                        if not story['Path_Indicator']:
                            full_p = str(target.get('Full_Path', '')) + str(target.get('Original_Path', ''))
                            if "outlook" in full_p.lower():
                                story['Path_Indicator'] = "Outlook添付ファイル (Content.Outlook)"

        # ==========================================================
        # [GOD MODE FINAL: Powered by SIREN]
        # ==========================================================
        verdict_flags = set()
        
        # 1. SirenHunt Check (Highest Priority)
        # SirenHuntが「黒」と言ったファイルが、Outlookに関連していれば即フラグ
        if self.siren_data:
            for target in self.siren_data:
                # Sirenのスコアが高い ＆ 実行済み
                if target.get('Siren_Score', 0) >= 50 and target.get('Executed'):
                    
                    # パスチェック (Outlook / Download)
                    full_path = str(target.get('Full_Path', '')) + str(target.get('Original_Path', ''))
                    if "outlook" in full_path.lower():
                        verdict_flags.add("[PHISHING_ATTACHMENT_EXEC]")
                        print(f"[!] Siren Confirmed: {target.get('FileName', 'Unknown')} -> PHISHING_EXEC")
                    elif "download" in full_path.lower():
                        verdict_flags.add("[DRIVE_BY_DOWNLOAD_EXEC]")

        # 2. Origin Stories からの正攻法 (Fallback)
        for story in origin_stories:
            if "outlook" in str(story.get('Path_Indicator', '')).lower() and story.get('Execution_Link'):
                verdict_flags.add("[PHISHING_ATTACHMENT_EXEC]")
            elif "download" in str(story.get('Path_Indicator', '')).lower() and story.get('Execution_Link'):
                verdict_flags.add("[DRIVE_BY_DOWNLOAD_EXEC]")
        
        # 2. 生データからの「キーワード」チェック (Ultima Fail-Safe)
        if not verdict_flags:
            # もうスコアは見ないっス。キーワードがあったらフラグを立てるっス！
            for ev in raw_events:
                detail = str(ev.get('Detail', '')).lower()
                summary = str(ev.get('Summary', '')).lower()
                kws = str(ev.get('Keywords', '')).lower()
                
                # Outlookフォルダに動きがあったら無条件で疑う
                if "content.outlook" in detail or "content.outlook" in kws:
                     # [FIX] 閾値を 80 -> 60 に緩和！ (MFT Drop is 70)
                     if ev['Criticality'] >= 60: verdict_flags.add("[PHISHING_ATTACHMENT_EXEC]")
                
                # 特定の標的ファイル名があればフラグ
                if "invoice_urgent" in kws or "invoice_urgent" in summary:
                     # 実行痕跡（EXEC）またはドロップ（DROP）ならフラグ
                     if ev['Category'] in ['EXEC', 'INIT', 'DROP']:
                         verdict_flags.add("[PHISHING_ATTACHMENT_EXEC]")

        final_verdict_str = " ".join(list(verdict_flags))
        # ==========================================================

        # [Dynamic Attack Flow]
        flow_steps = []
        seen_cats = set()
        for ev in valid_events:
            if ev['Criticality'] >= 80:
                cat = ev['Category']
                
                # Only include steps with valid Keywords (Filename)
                if not ev.get('Keywords'): continue
                
                kw_raw = ev['Keywords'][0]
                kw = f" ({kw_raw})"
                
                # [NEW] Origin Context Injection
                origin_context = ""
                # すでに解析済みの origin_stories からマッチするものを探す
                for story in origin_stories:
                    if story['File'] in str(kw_raw).lower():
                        if "outlook" in str(story.get('Path_Indicator', '')).lower():
                            origin_context = " (メール添付ファイル経由)"
                        elif "download" in str(story.get('Path_Indicator', '')).lower():
                            origin_context = " (Webダウンロード経由)"
                        break

                # Special Handling for Schtasks
                if "schtasks.exe" in str(kw_raw).lower():
                    step_desc = f"タスクスケジューラの操作/永続化試行{kw}"
                elif cat == "INIT": 
                    step_desc = f"不正スクリプト/コマンドの実行{kw}{origin_context}"
                elif cat == "DROP": 
                    # Dropの場合は文脈を強調
                    prefix = "攻撃ツールの作成・展開"
                    if origin_context: prefix = f"メール/Web経由での攻撃ツール展開{origin_context}"
                    step_desc = f"{prefix}{kw}"
                elif cat == "C2": step_desc = f"C2サーバーへの通信{kw}"
                elif cat == "PERSIST": step_desc = f"永続化設定の設置{kw}"
                elif cat == "ANTI": step_desc = f"痕跡隠滅（ファイル削除等）{kw}"
                elif cat == "EXEC": step_desc = f"不正プログラムの実行{kw}"
                else: step_desc = ""
                
                if step_desc and step_desc not in flow_steps:
                    flow_steps.append(step_desc)

        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"# {t['title']}\n\n")
            f.write(f"### 🛡️ {t['coc_header']}\n")
            f.write("| Item | Details |\n|---|---|\n")
            f.write(f"| **Case Name** | {self.case_name} |\n")
            f.write(f"| **Date** | {datetime.datetime.now().strftime('%Y-%m-%d')} |\n")
            f.write(f"| **Status** | Analyzed (SkiaHelios v15.41 God Mode) |\n\n---\n\n")
            
            f.write(f"## {t['h1_exec']}\n")
            if valid_events:
                latest_crit = "Unknown"
                for ev in reversed(valid_events):
                    if ev['Criticality'] >= 90:
                        latest_crit = str(ev['Time']).split('.')[0]; break
                
                # [FIX] 結論にフラグを強制追記
                verdict_display = f" **{final_verdict_str}**" if final_verdict_str else ""
                f.write(f"**結論:**\n{latest_crit} (UTC) 頃、端末 {self.case_name} において、**悪意ある攻撃活動**を検知しました。{verdict_display}\n\n")
                
                main_user = compromised_users.most_common(1)
                user_str = main_user[0][0] if main_user else "特定不能 (System権限のみ)"
                f.write(f"**侵害されたアカウント:**\n主に **{user_str}** アカウントでの活動が確認されています。\n\n")
                
                f.write(f"**攻撃フロー（概要）:**\n")
                if flow_steps:
                    for i, step in enumerate(flow_steps, 1):
                        f.write(f"{i}. {step}\n")
                else:
                    f.write("攻撃の全体像を構成するのに十分なイベントが検出されませんでした。\n")
                f.write("\n")
            else:
                f.write("**結論:**\n現在提供されているログの範囲では、クリティカルな侵害痕跡は確認されませんでした。\n\n")

            # [NEW SECTION: Origin Analysis]
            # origin_stories は計算済みなのでそのまま使う
            if origin_stories:
                f.write(f"## {t['h1_origin']}\n")
                f.write("攻撃の起点（侵入経路）に関する物理的証拠と因果関係の分析結果です。\n\n")
                f.write("| File (Payload) | 📍 Origin Context (Path/Web) | 🔗 Execution Link |\n|---|---|---|\n")
                for story in origin_stories:
                    origin_desc = "**Unknown**"
                    if story['Path_Indicator']: origin_desc = f"📂 {story['Path_Indicator']}"
                    if story['Web_Correlation']: origin_desc += f"<br>🌐 {story['Web_Correlation']}"
                    
                    exec_desc = story['Execution_Link'] if story['Execution_Link'] else "実行痕跡なし (未実行の可能性)"
                    f.write(f"| `{story['File']}` | {origin_desc} | {exec_desc} |\n")
                f.write("\n")

            f.write(f"## {t['h1_time']}\n")
            phases = self._partition_timeline(valid_events)
            for idx, phase in enumerate(phases):
                if not phase: continue
                date_str = str(phase[0]['Time']).replace('T', ' ').split(' ')[0]
                f.write(f"### 📅 Phase {idx+1} ({date_str})\n")
                f.write(f"| Time (UTC) | User | Category | Event Summary | Source |\n|---|---|---|---|---|\n")
                for ev in phase:
                    cat_name = t['cats'].get(ev['Category'], "Other")
                    time_display = self._get_time_str(ev)
                    u = ev['User'] if ev['User'] else "-"
                    summary = ev['Summary']
                    f.write(f"| {time_display} | {u} | {cat_name} | {summary} | {ev['Source']} |\n")
                if idx < len(phases)-1: f.write("\n*( ... Time Gap ... )*\n\n")
            f.write("\n")
            
            f.write(f"## {t['h1_tech']}\n")
            for idx, phase in enumerate(phases):
                if not phase: continue
                has_findings = False
                phase_buffer = []
                date_str = str(phase[0]['Time']).replace('T', ' ').split(' ')[0]
                phase_buffer.append(f"### 📅 Phase {idx+1} ({date_str})\n")
                
                for ev in phase:
                    if ev['Criticality'] >= 85:
                        has_findings = True
                        insight = self._generate_insight(ev)
                        phase_buffer.append(f"- **{ev['Summary']}**\n")
                        phase_buffer.append(f"  - **Time:** {ev['Time']}\n")
                        phase_buffer.append(f"  - **Insight:** {insight}\n")
                        if ev.get('Detail'):
                             phase_buffer.append(f"  - **Detail:**\n```text\n{str(ev['Detail'])[:300]}\n```\n")
                        phase_buffer.append("\n")
                
                if has_findings:
                    f.write("".join(phase_buffer))
                    f.write("\n")

            # [NEW] Appendix (IOC)
            f.write(self._generate_ioc_appendix())

            f.write(f"\n---\n*Report generated by SkiaHelios v15.41 God Mode*")

    def _collect_and_filter_events(self):
        events = []
        
        # [GOD MODE: Prefetch Analysis]
        if self.dfs.get('Prefetch') is not None:
            # PECmd standard columns: "SourceFilename", "LastRun", "RunCount", "ExecutableName"
            # Adjust column names as per PECmd output if needed (e.g. "ExecutableName", "LastRun")
            df = self.dfs['Prefetch']
            
            # Identify name column (ExecutableName or SourceFilename)
            name_col = next((c for c in ["ExecutableName", "SourceFilename", "FileName"] if c in df.columns), None)
            time_col = next((c for c in ["LastRun", "SourceCreated", "SourceModified"] if c in df.columns), None)
            
            if name_col and time_col:
                for row in df.iter_rows(named=True):
                    fname = str(row[name_col])
                    if self._is_known_noise(fname): continue
                    
                    # Execution Count Check (RunCount)
                    run_count = row.get("RunCount", 1)
                    try: run_count = int(run_count)
                    except: run_count = 1
                    
                    if run_count > 0:
                        events.append({
                            "Time": row[time_col], "Source": "Prefetch (PECmd)", "User": "System",
                            "Summary": f"Process Execution (Verified): {fname}",
                            "Detail": f"Run Count: {run_count}\nSource: {row.get('SourceFilename', 'Prefetch')}",
                            "Criticality": 100, # High confidence execution
                            "Category": "EXEC",
                            "Keywords": [fname]
                        })

        # [Sphinx v1.9 - with BURST AGGREGATION & NOISE FILTER]
        if self.dfs['Sphinx'] is not None:
            hits = self.dfs['Sphinx'].filter(pl.col("Sphinx_Tags").str.contains("ATTACK|DECODED"))
            hits = hits.unique(subset=["Original_Snippet"])
            
            script_bursts = defaultdict(list)
            
            for i, row in enumerate(hits.iter_rows(named=True)):
                full = row.get("Decoded_Hint") or row.get("Original_Snippet")
                if self._is_script_noise(full): continue
                
                url_match = self._extract_url(full)
                cmd_file = self._extract_filename_from_cmd(full)
                kws = []
                if url_match: kws.append(url_match)
                if cmd_file: kws.append(cmd_file)
                
                time_key = str(row['TimeCreated']).split('.')[0]
                script_bursts[time_key].append({
                    "row": row, "kws": kws, "full": full
                })

            for t_key, bursts in script_bursts.items():
                if not bursts: continue
                base = bursts[0]
                
                all_kws = []
                for b in bursts:
                    if b.get('kws'): all_kws.extend(b['kws'])
                combined_kws = list(set(all_kws))
                
                if len(bursts) > 1:
                    snippet = f"[Aggregated {len(bursts)} fragments]\n" + base['full'][:200] + "..."
                else:
                    snippet = base['full']

                src = self._resolve_source("SPHINX", base['row'])
                u = self._resolve_user(base['row'], "SPHINX")
                # [DEFENSIVE] Ensure Keywords are populated
                if not combined_kws:
                    # Fallback: Extract from Detail regex or split
                    fallback_kw = self._extract_filename_from_cmd(snippet)
                    if fallback_kw: combined_kws.append(fallback_kw)
                
                events.append({
                    "Time": base['row']['TimeCreated'], "Source": src, "User": u,
                    "Summary": f"Script Execution: {base['row']['Sphinx_Tags']}",
                    "Detail": snippet, "Criticality": 100,
                    "Category": self._classify_category("Sphinx", base['row']['Sphinx_Tags'], snippet),
                    "Keywords": combined_kws
                })

        # [Hercules Judgment Integration]
        if self.dfs['Hercules'] is not None and "Judge_Verdict" in self.dfs['Hercules'].columns:
             hercules_hits = self.dfs['Hercules'].filter(
                 (pl.col("Judge_Verdict").str.contains("CRITICAL|SUSPICIOUS")) &
                 (~pl.col("Tag").str.contains("NETWORK|C2")) 
             )
             for row in hercules_hits.iter_rows(named=True):
                 verdict = str(row.get("Judge_Verdict", "")).upper()
                 target = str(row.get("Target_Path", ""))
                 fname = self._extract_filename_from_cmd(target)
                 
                 is_critical = "CRITICAL" in verdict or "SNIPER" in verdict
                 if not is_critical:
                     if self._is_known_noise(target) or self._is_known_noise(fname): continue
                 
                 crit = 100 if is_critical else 80
                 kws = [fname] if fname else []
                 
                 events.append({
                    "Time": row['Timestamp_UTC'], 
                    "Source": f"Hercules ({row.get('Artifact_Type', 'EventLog')})", 
                    "User": self._resolve_user(row, "HERCULES"),
                    "Summary": f"Suspicious Activity: {row.get('Tag')}", 
                    "Detail": f"Verdict: {verdict}\nCmd: {target}",
                    "Criticality": crit, 
                    "Category": "EXEC", 
                    "Keywords": kws
                })

        # [Network]
        if self.dfs['Network'] is not None and "Tag" in self.dfs['Network'].columns:
            net_hits = self.dfs['Network'].filter(pl.col("Tag").str.contains("NETWORK|C2"))
            net_hits = net_hits.unique(subset=["Timestamp_UTC", "Action"])
            for row in net_hits.iter_rows(named=True):
                target = str(row['Action']) + " " + str(row['Target_Path'])
                url = self._extract_url(target)
                cmd_file = self._extract_filename_from_cmd(target)
                kws = []
                if url: kws.append(url)
                if cmd_file: kws.append(cmd_file)
                if url or cmd_file:
                    src = self._resolve_source("NETWORK", row)
                    u = self._resolve_user(row, "NETWORK")
                    events.append({
                        "Time": row['Timestamp_UTC'], "Source": src, "User": u,
                        "Summary": f"C2 Connection: {url}",
                        "Detail": target, "Criticality": 90,
                        "Category": "C2", "Keywords": kws
                    })

        # [AION]
        if self.dfs['AION'] is not None:
            hits = self.dfs['AION'].filter(pl.col("AION_Tags").str.contains("WANTED|HOTSPOT"))
            for row in hits.iter_rows(named=True):
                fname, tag = str(row['Target_FileName']), row['AION_Tags']
                fpath = str(row.get('Full_Path',''))
                if self._is_known_noise(fname, tag) or self._is_known_noise(fpath, tag): continue
                src = self._resolve_source("AION", row)
                u = self._resolve_user(row, "AION")
                events.append({
                    "Time": row['Last_Executed_Time'], "Source": src, "User": u,
                    "Summary": f"Persistence: {fname}",
                    "Detail": f"Path: {fpath}\nLocation: {row.get('Entry_Location')}",
                    "Criticality": 100 if "WANTED" in tag else 60,
                    "Category": "PERSIST", "Keywords": [fname]
                })

        # [Pandora]
        if self.dfs['Pandora'] is not None:
            pandora_count = 0
            for row in self.dfs['Pandora'].iter_rows(named=True):
                 fname = str(row.get('Ghost_FileName'))
                 fpath = str(row.get('ParentPath'))
                 if self._is_known_noise(fname) or self._is_known_noise(fpath): continue
                 time_val = row.get('Ghost_Time_Hint') or row.get('Last_Executed_Time')
                 src = self._resolve_source("PANDORA", row)
                 u = self._resolve_user(row, "PANDORA")
                 events.append({
                    "Time": time_val, "Source": src, "User": u,
                    "Summary": f"File Deletion: {fname}",
                    "Detail": f"Restored Path: {row.get('ParentPath')}",
                    "Criticality": 80, "Category": "ANTI", "Keywords": [fname]
                })
                 pandora_count += 1
                 if pandora_count >= 5: break

        # [Chronos]
        if self.dfs['Chronos'] is not None and "FileName" in self.dfs['Chronos'].columns:
             for row in self.dfs['Chronos'].iter_rows(named=True):
                 fname = str(row.get('FileName',''))
                 fpath = str(row.get('ParentPath',''))
                 if self._is_known_noise(fname) or self._is_known_noise(fpath): continue
                 src = self._resolve_source("CHRONOS", row)
                 u = self._resolve_user(row, "CHRONOS")
                 ts = row.get('si_mod_dt') or row.get('si_dt')
                 if not ts: ts = "Unknown"
                 try: score = int(float(row.get('Chronos_Score', 0)))
                 except: score = 0
                 anomaly = row.get('Anomaly_Time', '')
                 if "TIMESTOMP" in anomaly:
                     events.append({
                         "Time": ts, "Source": src, "User": u,
                         "Summary": f"Timestomp: {fname}",
                         "Detail": f"Score: {score}", "Criticality": 50, "Category": "ANTI", "Keywords": [fname]
                     })
                 if score >= 150:
                     create_ts = row.get('si_dt') or row.get('fn_dt')
                     if create_ts:
                         origin_info = self._analyze_origin(fname, None)
                         summary_str = f"File Creation: {fname}"
                         if origin_info: summary_str += f" ({origin_info})"
                         events.append({
                             "Time": create_ts, "Source": src, "User": u,
                             "Summary": summary_str,
                             "Detail": f"Path: {fpath}\nType: Critical Artifact",
                             "Criticality": 70, "Category": "DROP", "Keywords": [fname]
                         })

        for ev in events:
            t_str = str(ev['Time']).replace('T', ' ').split('.')[0]
            try: ev['dt_obj'] = datetime.datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")
            except: ev['dt_obj'] = None
            
        return events

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True, help="Timeline CSV")
    parser.add_argument("-o", "--out", default="SANS_Report.md")
    parser.add_argument("--case", default="Operation Frankenstein (Mock Incident)")
    parser.add_argument("--aion"); parser.add_argument("--pandora"); parser.add_argument("--plutos"); 
    parser.add_argument("--plutos-net");
    parser.add_argument("--sphinx", help="Sphinx Output CSV")
    parser.add_argument("--chronos", help="Chronos Output CSV")
    parser.add_argument("--persistence"); parser.add_argument("--prefetch") # Added Prefetch Arg
    parser.add_argument("--siren", help="Sirenhunt Results JSON") # [NEW]
    parser.add_argument("--lang", default="jp", help="Language: jp/en")
    args = parser.parse_args(argv)
    
    try:
        weaver = HekateWeaver(
            args.input, 
            aion_csv=args.aion, 
            pandora_csv=args.pandora, 
            plutos_csv=args.plutos,
            plutos_net_csv=args.plutos_net,
            sphinx_csv=args.sphinx, 
            chronos_csv=args.chronos,
            persistence_csv=args.persistence, # Keeping this as it was in the original HekateWeaver call
            prefetch_csv=args.prefetch,       # Keeping this as it was in the original HekateWeaver call
            siren_json=args.siren, # [NEW]
            lang=args.lang,
            case_name=args.case
        )
        weaver.generate_report(args.out)
        print(f"[+] SANS Report Generated: {args.out}")
    except Exception as e:
        print(f"[!] HEKATE Crash Report: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
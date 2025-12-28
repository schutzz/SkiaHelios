import polars as pl
import argparse
from pathlib import Path
import sys
import datetime
import re
import json

from collections import defaultdict, Counter

def print_logo():
    print(r"""
      | | | | | |
    -- HEKATE  --   [ True Target v15.23 ]
      | | | | | |   "Lock on."
    """)

TEXT_RES = {
    "en": {
        "title": "Incident Investigation Report",
        "coc_header": "Chain of Custody & Case Info",
        "h1_exec": "1. Executive Summary",
        "h1_time": "2. Investigation Timeline",
        "h1_tech": "3. Technical Findings",
        "h1_rec": "4. Conclusion & Recommendations",
        "h1_app": "5. Appendices",
        "cats": {"INIT": "Initial Access", "C2": "Command & Control", "PERSIST": "Persistence", "ANTI": "Anti-Forensics", "EXEC": "Execution", "DROP": "File Creation (Origin)"},
        "investigator": "Forensic Analyst"
    },
    "jp": {
        "title": "インシデント調査報告書",
        "coc_header": "証拠保全および案件情報 (Chain of Custody)",
        "h1_exec": "1. エグゼクティブ・サマリー",
        "h1_time": "2. 調査タイムライン",
        "h1_tech": "3. 技術的詳細 (Technical Findings)",
        "h1_rec": "4. 結論と推奨事項",
        "h1_app": "5. 添付資料",
        "cats": {"INIT": "初期侵入 (Initial Access)", "C2": "C2通信 (Command & Control)", "PERSIST": "永続化 (Persistence)", "ANTI": "アンチフォレンジック (Anti-Forensics)", "EXEC": "実行 (Execution)", "DROP": "ファイル作成/流入 (File Drop)"},
        "investigator": "担当フォレンジックアナリスト"
    }
}

class NemesisTracer:
    def __init__(self, df_mft, df_usn, noise_validator=None):
        self.df_mft = df_mft
        self.df_usn = df_usn
        self.noise_validator = noise_validator
        # ID系カラムの優先順位リスト
        self.id_cols = ["EntryNumber", "MftRecordNumber", "FileReferenceNumber", "ReferenceNumber"]

    def trace_lifecycle(self, attack_seeds):
        """SeedからFile IDを特定し、リネーム先・削除を芋づる式に抽出"""
        if not attack_seeds: return []
        pattern = "|".join([re.escape(s) for s in attack_seeds if len(s) > 2])
        if not pattern: return []

        lifecycle_events = []
        target_file_ids_map = {} # {ID: SequenceNumber}

        # Phase A: あらゆる名前カラムから ID を強引に採取する
        for df, src in [(self.df_mft, "MFT"), (self.df_usn, "USN")]:
            if df is None: continue
            name_cols = [c for c in ["FileName", "Ghost_FileName", "OldFileName", "Target_FileName"] if c in df.columns]
            if not name_cols: continue

            filter_expr = pl.any_horizontal([pl.col(c).str.contains(f"(?i){pattern}") for c in name_cols])
            seed_hits = df.filter(filter_expr)

            for row in seed_hits.iter_rows(named=True):
                lifecycle_events.append(self._to_event(row, src, "Seed Matching"))
                # その行から ID (MFT Record Number) を採取
                seq_num = row.get("SequenceNumber")
                for c in self.id_cols:
                    if row.get(c): 
                        # 既存のエントリがあれば上書きせず、Noneなら更新するかもだが、
                        # 基本的に取得できたシーケンスを採用
                        target_file_ids_map[str(row[c])] = seq_num
                        break

        # Phase B: Shared Logic
        lifecycle_events.extend(self._recover_lifecycle_by_ids(target_file_ids_map, "ID-Chain Recovery"))
        return lifecycle_events

    def _parse_id(self, val):
        """Standardize ID and extract (EntryNumber, SequenceNumber) from 64-bit FileReferenceNumber if needed."""
        if not val: return None, None
        try:
            # If explicit SequenceNumber column exists, we rely on that.
            # But if 'val' is a raw 64-bit FileRef, we split it.
            # MFT Entry is lower 48 bits, Seq is upper 16 bits.
            val_int = int(val)
            if val_int > 0xFFFFFFFFFFFF: # Larger than 48 bits
                entry = val_int & 0xFFFFFFFFFFFF
                seq = (val_int >> 48) & 0xFFFF
                return str(entry), str(seq)
            return str(val_int), None
        except:
            return str(val), None

    def _recover_lifecycle_by_ids(self, target_ids_dict, mode_label="ID-Chain Recovery"):
        """共通のIDリカバリロジック (Phase B) - Sequence Number対応版 + Hybrid Birth"""
        events = []
        if not target_ids_dict: return events

        # 1. Collect Valid Events
        for df, src in [(self.df_usn, "USN"), (self.df_mft, "MFT")]:
            if df is None: continue
            found_col = next((c for c in self.id_cols if c in df.columns), None)
            if not found_col: continue

            seq_col = "SequenceNumber" if "SequenceNumber" in df.columns else None
            
            # Filter efficiently
            # Note: Polars string matching is safer than int comparison for mixed types
            # But for 64-bit handling, we scan relevant rows.
            # Optimization: Try to filter by IDs first if they are simple numbers
            # If target_ids_dict keys are purely Entry Numbers, we can match directly.
            
            # Since we can't easily perform bitwise query in Polars basic filter without custom expr,
            # We fetch potential candidates.
            # Simplified approach: Filter by string containment or exact match on EntryNumber if separated.
            
            # Assuming found_col contains the EntryNumber (Chronos usually splits it or provides it),
            # or it is the 64-bit Ref. 
            # We'll rely on our _parse_id applied to the dataframe if needed, but that's slow.
            # FAST PATH: We assume `target_ids_dict` keys are consistently formatted (e.g. as EntryIndex).
            
            target_keys = list(target_ids_dict.keys())
            chain_hits = df.filter(pl.col(found_col).cast(pl.Utf8).is_in(target_keys))
            
            for row in chain_hits.iter_rows(named=True):
                # [Anti-Reuse] Sequence Number Validation
                row_raw_id = row[found_col]
                row_entry, row_packed_seq = self._parse_id(row_raw_id)
                
                # Determine Target Seq
                # target_ids_dict maps EntryID -> Expected Seq
                target_seq = target_ids_dict.get(row_entry) # strict match on entry
                
                check_seq = row.get(seq_col) or row_packed_seq
                
                if target_seq is not None and check_seq is not None:
                     try:
                         if int(check_seq) != int(target_seq) and int(target_seq) != 0:
                             continue # Reuse detected (Mismatch)
                     except: pass 

                events.append(self._to_event(row, src, mode_label))
        
        # 2. [Anti-Forensics] Hybrid Birth Fallback & Grouping
        # IDごとにイベントを整理し、Birth(作成)があるか確認
        # (Already flattened structure here, dealing with 1 unified timeline per call usually)
        
        has_birth = any("BIRTH" in str(ev.get('Reason', '')).upper() or "CREATE" in str(ev.get('Reason', '')).upper() for ev in events)
        
        if events and not has_birth:
            # Sort by Time
            events.sort(key=lambda x: x.get('dt_obj') or datetime.datetime.max)
            oldest_ev = events[0]
            # マーク付与 (Source強調)
            src_hint = str(oldest_ev.get('Source', 'Unknown')).replace('Nemesis ', '').strip('()')
            oldest_ev['Summary'] += " [PROVISIONAL ORIGIN]"
            oldest_ev['Detail'] += f" (Reason: Oldest Trace / Birth Missing | Reliability Source: {src_hint})"
            oldest_ev['Criticality'] = 85 # Elevate importance

        return events

    def trace_origin_by_execution(self, execution_events):
        """実行イベント(成功・失敗問わず)からIDを特定し、Birthを逆引きする (Recursive discovery)"""
        if not execution_events: return []
        
        # [Container-Aware Trace]
        # 実行主体が「器(Container)」の場合、引数から「中身(Seed)」を取り出してID特定に使う
        CONTAINER_APPS = {
            "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", 
            "python.exe", "perl.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", 
            "bitsadmin.exe", "certutil.exe", "csc.exe", "vbc.exe", "installutil.exe", 
            "psexec.exe", "wmiprvse.exe", "scrcons.exe", "microsoft.powershell.cmd"
        }

        captured_ids_map = {}
        lifecycle_events = []
        
        # ログから動的に抽出した新たなSeed（Attack_Chain.bat等）を保持するセット
        dynamic_seeds = set()

        for ev in execution_events:
            exec_dt = ev.get('dt_obj')
            if not exec_dt: continue
            
            # 1. コマンドラインや詳細ログ（エラーメッセージ含む）から「中身」を徹底的に抜き出す
            # 成功した引数だけでなく、ID:121のような「失敗メッセージ」の中にあるファイル名も対象
            raw_text = str(ev.get('Detail', '')) + " " + str(ev.get('Summary', ''))
            new_discovered = self._extract_seeds_from_args(raw_text)
            dynamic_seeds.update(new_discovered)

            # 現在のイベントに関連する候補（既存のKeywords + 今回見つけた名前）
            candidates = set()
            if ev.get('Keywords'):
                for k in ev['Keywords']:
                    k_lower = str(k).lower()
                    fname_only = k_lower.split("\\")[-1]
                    # ノイズ以外を追加
                    if not (self.noise_validator and self.noise_validator(fname_only)):
                        candidates.add(fname_only)
                        candidates.add(k_lower)
            
            candidates.update(dynamic_seeds)
            # Remove short/noise
            candidates = {c for c in candidates if len(c) > 2 and not (self.noise_validator and self.noise_validator(c))}

            if not candidates: continue

            # 2. 捜査窓を10秒に拡大（ログの書き込み遅延対策）
            window_start = exec_dt - datetime.timedelta(seconds=5)
            window_end = exec_dt + datetime.timedelta(seconds=5)

            # 3. USN/MFT スキャン (名前が何であれ、この時刻に動いたIDを特定)
            pattern = "|".join([re.escape(c) for c in candidates])
            if not pattern: continue

            if self.df_usn is not None:
                # [物理ID特定ロジック]
                time_col = next((c for c in ["Timestamp_UTC", "Last_Executed_Time", "Ghost_Time_Hint", "Time"] if c in self.df_usn.columns), None)
                if time_col: 
                    name_cols = [c for c in ["FileName", "Ghost_FileName", "Chaos_FileName"] if c in self.df_usn.columns]
                    if name_cols:
                        name_filter = pl.any_horizontal([pl.col(c).str.to_lowercase().str.contains(f"(?i){pattern}") for c in name_cols])
                        
                        # 時刻フィルタ
                        time_filter = (
                            (pl.col(time_col).str.to_datetime(strict=False) >= window_start) & 
                            (pl.col(time_col).str.to_datetime(strict=False) <= window_end)
                        )
                        
                        hits = self.df_usn.filter(time_filter & name_filter)
                        for row in hits.iter_rows(named=True):
                            # ノイズチェック
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
            
            # [FALLBACK] MFT (Live File)
            if self.df_mft is not None:
                mft_name_cols = [c for c in ["FileName", "Ghost_FileName", "Chaos_FileName"] if c in self.df_mft.columns]
                if mft_name_cols:
                     mft_name_filter = pl.any_horizontal([pl.col(c).cast(pl.Utf8).fill_null("").str.to_lowercase().str.contains(f"(?i){pattern}") for c in mft_name_cols])
                     mft_hits = self.df_mft.filter(mft_name_filter)
                     for row in mft_hits.iter_rows(named=True):
                        # ノイズチェック
                        if self.noise_validator:
                            f_path = row.get("ParentPath", "") + "\\" + (row.get("FileName") or "")
                            if self.noise_validator(f_path): continue

                        for c in self.id_cols:
                            if row.get(c):
                                entry, seq = self._parse_id(row[c])
                                existing_seq = row.get("SequenceNumber")
                                final_seq = existing_seq if existing_seq else seq
                                if entry: 
                                    # MFTからの採用（上書きOKだが、USN優先でも良い。ここでは単純に追加）
                                    if entry not in captured_ids_map:
                                        captured_ids_map[entry] = final_seq
                                break

        # 4. 採取したID(鎖)を使い、全期間から履歴を回収 (Birthを含む)
        if captured_ids_map:
            lifecycle_events.extend(self._recover_lifecycle_by_ids(captured_ids_map, "Origin Trace (Execution)"))
        
        return lifecycle_events

    def _extract_seeds_from_args(self, text):
        """Argumentsからファイルパス/名前を抽出する (Container-Aware対応)"""
        if not text: return []
        
        # [ROBUSTNESS] Handle quoted paths (e.g. "C:\Temp\Script.ps1")
        # Remove quotes to ensure regex matches the content cleanly
        clean_text = str(text).replace('"', '')
        
        # 拡張子を持つトークンを抽出 (User provided pattern + typical ones)
        # Note: Added boundary check `(?:\s|["']|$|[^\w\.])` to avoid matching prefixes like .Cmdletization -> .Cmd
        matches = re.findall(r'([\w\-\.\\/:~]+\.(?:exe|ps1|bat|cmd|vbs|dll|sys|doc|docx|xls|xlsx|pdf|zip|js|hta|wsf))(?:\s|["\']|$|[^\w\.])', clean_text, re.IGNORECASE)
        results = set()
        for m in matches:
            # パス区切り除去してファイル名のみにする
            # m is now the group 1 (filename), not including the boundary char
            fname = Path(m).name
            if len(fname) > 2: # 短すぎるゴミ除外
                results.add(fname.lower())
        return list(results)

    def _to_event(self, row, source_type, mode):
        # リネーム情報の抽出を強化
        fname = row.get("FileName") or row.get("Ghost_FileName") or "Unknown"
        old_name = row.get("OldFileName") # USNレコードにある場合
        reason = str(row.get("Reason") or row.get("UpdateReason") or "N/A").upper()
        
        # [NEW] Owner/SID Extraction for Identity Correlation
        owner = row.get("SI_SID") or row.get("SID") or row.get("Owner") or "N/A"
        
        action_map = {
            "FILE_CREATE": "Birth", "FILE_DELETE": "Termination",
            "RENAME_OLD_NAME": "Identity Change (Renamed FROM)", 
            "RENAME_NEW_NAME": "Identity Change (Renamed TO)",
            "DATA_EXTEND": "Modified"
        }
        spec = action_map.get(next((k for k in action_map if k in reason), ""), "Activity")
        
        # リネーム元・先が判明している場合はSummaryを書き換え
        summary = f"Lifecycle Trace [{spec}]: {fname}"
        if old_name and old_name != fname:
            summary = f"Lifecycle Trace [Identity Shift]: {old_name} -> {fname}"

        return {
            "Time": row.get("si_dt") or row.get("Ghost_Time_Hint") or row.get("Timestamp_UTC"),
            "Source": f"Nemesis ({source_type})", "User": "System/Inferred",
            "Summary": summary,
            "Detail": f"Mode: {mode} | Reason: {reason}\nPath: {row.get('ParentPath')}\nOwner: {owner}",
            "Criticality": 95, "Category": "ANTI" if "DELETE" in reason else "DROP",
            "Keywords": [fname],
            "Owner_SID": owner # Key for correlation
        }

class HekateWeaver:
    def __init__(self, timeline_csv, aion_csv=None, pandora_csv=None, plutos_csv=None, plutos_net_csv=None, sphinx_csv=None, chronos_csv=None, persistence_csv=None, lang="jp", case_name="Operation Frankenstein"):
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

    def correlate_identity(self, raw_events):
        """Phase 4: Identity & Privilege Correlation (SID Affinity Mapping)"""
        if not raw_events: return
        
        # 1. Load Session Map
        session_map = []
        map_path = Path(r"c:\Users\user\.gemini\antigravity\scratch\SkiaHelios\hercules_sessions.json")
        if map_path.exists():
            try:
                with open(map_path, "r") as f: session_map = json.load(f)
            except: pass
        
        if not session_map: return

        # Helper: Find active sessions at time T
        def get_active_sessions(dt):
            active = []
            for s in session_map:
                try:
                    start = datetime.datetime.fromisoformat(s["Start"].replace("Z", ""))
                    end = datetime.datetime.max
                    if s["End"] and s["End"] != "ACTIVE":
                         end = datetime.datetime.fromisoformat(s["End"].replace("Z", ""))
                    
                    if start <= dt <= end:
                         active.append(s)
                except: pass
            return active

        # 2. Iterate File Creation Events
        for ev in raw_events:
            # Creation events only (DROP category or Birth reason)
            if ev.get("Category") != "DROP" and "BIRTH" not in str(ev.get("Detail", "")).upper():
                continue
            
            ev_dt = ev.get("dt_obj")
            if not ev_dt: continue
            
            owner = ev.get("Owner_SID")
            if not owner or owner == "N/A": continue
            
            # 3. SID Affinity Analysis
            # Compare File Owner vs Active Sessions
            active_sessions = get_active_sessions(ev_dt)
            active_sids = set(s.get("SID") for s in active_sessions)
            
            # Condition A: Privilege Escalation
            # File is SYSTEM/Root (S-1-5-18) BUT Only User Session Active
            is_system_file = "S-1-5-18" in owner
            is_user_active_only = any("S-1-5-21" in str(s) for s in active_sids) and not any("S-1-5-18" in str(s) for s in active_sids)
            
            if is_system_file and is_user_active_only:
                 ev["Summary"] = "[PRIVILEGE ESCALATION] " + ev["Summary"]
                 ev["Detail"] += f"\n[!] SID Affinity Alert: File created by SYSTEM while only Standard User sessions were active.\n[!] Active SIDs: {list(active_sids)}"
                 ev["Criticality"] = 100
            
            # Condition B: Orphan Origin
            # File created but NO session active (e.g. Scheduled Task context not captured or Stealth)
            elif not active_sessions:
                 ev["Summary"] = "[ORPHAN ORIGIN] " + ev["Summary"]
                 ev["Detail"] += "\n[!] SID Affinity Alert: File created with NO matching active session found in logs."

    def _safe_load(self, path):
        if path and Path(path).exists():
            try:
                return pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
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

    def _is_known_noise(self, file_path, tags=""):
        fp = str(file_path).lower()
        t = str(tags).lower()
        fname = Path(fp).name.lower()
        
        if "winsxs" in fp: return True
        if fp.endswith(".manifest") or fp.endswith(".mum"): return True
        if "pathunknown" in fp and ("microsoft" in fp or "updateservices" in fp): return True
        if "microsoft.build" in fp or "gac_msil" in fp: return True
        if "machine.config" in fp: return True
        if "microsoft.cognitiveservices" in fp: return True 

        is_update_pattern = (
            fname.startswith(("amd64_", "x86_", "wow64_")) or 
            "_netfx" in fname or 
            "_microsoft-" in fname
        )
        if is_update_pattern:
            suspicious_exts = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".zip")
            if fname.endswith(suspicious_exts): return False 
            return True 

        if fname.endswith(".tmp"):
            if "appdata\\local\\temp" in fp or "windows\\temp" in fp: return True
            return False 

        if "attack" not in t and "encoded" not in t and "webshell" not in t:
            noise_bins = [
                "winhlp32", "manage-bde", "repair-bde", 
                "fvenotify", "bitlocker", "bdechangepin", 
                "bdeunlock", "fveprompt", "bdeuisrv",
                "hh.exe", "bfsvc.exe", "flashplayerinstaller", "isburn",
                "fveapi", "bluetooth.userservice", "appxalluserstore"
            ]
            for nb in noise_bins:
                if nb in fp: return True
        return False

    def _is_file_noise(self, filename, full_path=""):
        fn = str(filename).lower()
        fp = str(full_path).lower()
        
        # システム標準の管理ツールのみを除外対象とする（パスも厳格にチェック）
        admin_tools = {"auditpol.exe", "whoami.exe", "ipconfig.exe", "net.exe", "sc.exe"}
        if fn in admin_tools and ("system32" in fp or not fp):
            return True

        # スクリプト・バッチファイル関連は、名前が何であれ「種(Seed)」として残すため、ここではノイズとしない
        if any(ext in fn for ext in [".ps1", ".bat", ".cmd", ".vbs", ".tmp"]):
            return False

        # PowerShellの内部名称や特定のシステム挙動
        if fn in {"microsoft.powershell.cmd", ".powershell.cmd"}:
            # ただし、これ自体を「種」にしたい場合があるので False に寄せる
            return False 
            
        return False

    def _extract_filename_from_cmd(self, text):
        """Extracts significant filenames from command lines."""
        if not text: return None
        # [FIX] Added boundary check `(?:\s|["']|$|[^\w\.])` to avoid .Cmdletization -> .Cmd
        matches = re.findall(r'([\w\-\.\/\\]+\.(?:exe|ps1|bat|cmd|vbs|dll|sys|doc|docx|xls|xlsx|pdf|zip))(?:\s|["\']|$|[^\w\.])', str(text), re.IGNORECASE)
        for m in matches:
            fname = Path(m).name
            if not self._is_known_noise(fname):
                return fname
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
        # Check Origin
        if ev.get('Keywords') and ev['Keywords'][0] and ev.get('dt_obj'):
            origin = self._analyze_origin(ev['Keywords'][0], ev['dt_obj'])
            if origin:
                origin_note = f"\n  - **起源追跡:** {origin}"
            elif cat in ["INIT", "PERSIST", "DROP"]:
                origin_note = "\n  - **起源推測:** Zone.Identifier（Webダウンロード痕跡）が確認できません。ドロッパーによるローカル作成、Zip解凍、または物理メディア経由の持ち込みと推測されます。"

        if cat == "INIT":
            if "powershell" in src.lower():
                if "base64" in summary or "decoded" in summary:
                    return "PowerShellコマンドのBase64難読化実行を検知しました。" + origin_note
                return "不審なスクリプトブロックの実行を検知しました。" + origin_note
        elif cat == "DROP":
            return "ディスク上での新規ファイル作成（File Drop）を確認しました。実行の前段階として攻撃ツールが配置された痕跡です。" + origin_note
        elif cat == "C2":
            return "外部への不審な通信（C2）を検知しました。"
        elif cat == "PERSIST":
            return "永続化設定が確認されました。" + origin_note
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
        if "SPHINX" in s or "DECODED" in t or "POWERSHELL" in d: return "INIT"
        if "CHRONOS" in s or "TIMESTOMP" in t: return "ANTI"
        if "CHRONOS" in s and "CREATION" in t: return "DROP" 
        if "GHOST" in t or "INFERRED" in t: return "DROP" 
        return "EXEC"

    def _extract_url(self, text):
        match = re.search(r"https?://[^\s\"']+", str(text))
        return match.group(0) if match else None

    def _get_time_str(self, ev):
        if ev.get('dt_obj'): return ev['dt_obj'].strftime('%H:%M:%S')
        raw = str(ev['Time']).replace('T', ' ')
        parts = raw.split(' ')
        return parts[1] if len(parts) > 1 else raw

    def generate_report(self, output_path):
        t = self.txt
        out_file = Path(output_path)
        if not out_file.parent.exists(): out_file.parent.mkdir(parents=True, exist_ok=True)
            
        raw_events = self._collect_and_filter_events()
        
        # [NEMESIS SEEDING]
        seeds = set()
        for ev in raw_events:
            # 1. 攻撃確定(Criticality 90+)のキーワード
            if ev.get('Criticality', 0) >= 90 and ev.get('Keywords'):
                for k in ev['Keywords']:
                    if not self._is_file_noise(k):
                        seeds.add(str(k))
            
            # 2. 【重要】初期侵入(INIT)フェーズのスクリプトファイルを強制追加
            if ev.get('Category') == 'INIT' and ev.get('Keywords'):
                for k in ev['Keywords']:
                    # 拡張子がスクリプト系なら、名前の長さやノイズ判定を無視してSeed化
                    if any(ext in k.lower() for ext in ['.ps1', '.bat', '.cmd', '.vbs', '.tmp']):
                        seeds.add(str(k))
        
        # [NEMESIS EXECUTION]
        # 1. Initialize Nemesis with Noise Validator
        nemesis = NemesisTracer(self.dfs['Chronos'], self.dfs['Pandora'], noise_validator=self._is_known_noise)

        # 2. Trace Lifecycle by Seeds
        if seeds:
            raw_events.extend([r for r in nemesis.trace_lifecycle(list(seeds)) 
                               if (r['Summary'] + str(r['Time'])) not in {e['Summary'] + str(e['Time']) for e in raw_events}])

        # 3. Trace by Execution Origin (New: Execution-First Reverse Lookup)
        # 実行イベント(INIT, EXEC)を抽出し、その時間+名前から物理的な実体を特定する
        # [FIX] Container Appであれば、Criticalityが低くても解析対象とする (引数解析のため)
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
                    for k in ev['Keywords']:
                        if str(k).lower().split("\\")[-1] in CONTAINER_APPS_CHECK:
                            is_container = True
                            break
                
                # Criticality 80以上 OR Container Appなら採用
                if ev.get('Criticality', 0) >= 80 or is_container:
                    execution_events.append(ev)
        
        # 時刻情報(dt_obj)を事前に補完
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

        # [ROBUSTNESS: Ghost Merge & Death Confirmation]
        # Nemesisが特定した「削除(Death)」と、Pandoraが検出した「残骸(Ghost)」を統合する
        indices_to_remove = set()
        nemesis_deaths = [ev for ev in raw_events if "Nemesis" in str(ev.get('Source', '')) and ("DELETE" in str(ev.get('Reason', '')).upper() or "DEATH" in str(ev.get('Summary', '')).upper())]
        
        for n_ev in nemesis_deaths:
            # 1. Deletion Confirmation (Highlighting)
            if "[CONFIRMED DELETION]" not in n_ev['Summary']:
                n_ev['Summary'] = "[CONFIRMED DELETION] " + n_ev['Summary']
                n_ev['Detail'] += " (Verified by Nemesis Trace)"
            
            # 2. Ghost Deduplication
            # 同じファイル・近い時刻のPandoraイベントを探す
            n_time = n_ev.get('dt_obj')
            if not n_time: continue
            
            for i, p_ev in enumerate(raw_events):
                if i in indices_to_remove: continue
                if "Pandora" not in str(p_ev.get('Source', '')) and "ANTI" not in str(p_ev.get('Category', '')): continue
                
                # 時刻チェック (±5秒)
                p_time = p_ev.get('dt_obj')
                if not p_time or abs((n_time - p_time).total_seconds()) > 5: continue
                
                # 名前チェック (Keyword or Summary)
                n_names = set(str(k).lower().split("\\")[-1] for k in n_ev.get('Keywords', []))
                p_names = set(str(k).lower().split("\\")[-1] for k in p_ev.get('Keywords', []))
                if not n_names.intersection(p_names): continue
                
                # Merge!
                n_ev['Summary'] += f" <br>(Matches Pandora Ghost: {p_ev['Summary']})"
                indices_to_remove.add(i)
        
        # [ROBUSTNESS: Ghost Merge & Death Confirmation]
        # (Ghost Merge logic continues...)
        if indices_to_remove:
            raw_events = [ev for i, ev in enumerate(raw_events) if i not in indices_to_remove]
            
        # 2. Identity Correlation (SID Affinity Mapping)
        self.correlate_identity(raw_events)

        # 3. Origin Analysis Integration
        for ev in raw_events:
            if ev['Category'] == 'DROP' and ev.get('Keywords'):
                origin = self._analyze_origin(ev['Keywords'][0], ev.get('dt_obj'))
                if origin: ev['Summary'] += f" <br>↳ (Origin: {origin})"

        # 3. Time Normalization & Sort (Final)
        for ev in raw_events:
            t_str = str(ev['Time']).replace('T', ' ').split('.')[0]
            try: ev['dt_obj'] = datetime.datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")
            except: ev['dt_obj'] = None
        raw_events.sort(key=lambda x: x.get('dt_obj') or datetime.datetime.max)
        
        # [NEW] Execution-Based Inference (Refined)
        executed_files = {} 
        dropped_files = set()
        
        for ev in raw_events:
            if ev['Category'] == 'DROP':
                if ev.get('Keywords'): dropped_files.add(str(ev['Keywords'][0]).lower())
            elif ev['Category'] in ['INIT', 'EXEC', 'PERSIST']:
                # Safe Access for Keywords
                kws = ev.get('Keywords')
                if kws:
                    fname = str(kws[0]).lower()
                    if "." in fname and fname not in executed_files:
                        executed_files[fname] = ev 

        for fname, exec_ev in executed_files.items():
            # Suppress inference for known noise (e.g. StartupInfo)
            if "startupinfo" in fname.lower(): continue
            if self._is_file_noise(fname): continue

            if fname not in dropped_files and "unknown" not in fname:
                exec_dt = exec_ev.get('dt_obj')
                if exec_dt:
                    inferred_dt = exec_dt - datetime.timedelta(seconds=1)
                    summary_str = f"File Creation (Inferred): {fname}"
                    origin_info = self._analyze_origin(fname, inferred_dt)
                    if origin_info: summary_str += f" ({origin_info})"
                    else: summary_str += " (Origin: Local/Consistent Timestamp)"

                    raw_events.append({
                        "Time": str(inferred_dt), 
                        "Source": "Inferred from Execution (Log)", 
                        "User": exec_ev['User'],
                        "Summary": summary_str,
                        "Detail": f"File '{fname}' executed but has no anomaly record.\nCreation inferred from first execution time.",
                        "Criticality": 70, "Category": "DROP", "Keywords": [fname],
                        "dt_obj": inferred_dt
                    })

        raw_events.sort(key=lambda x: str(x['Time']) if x['Time'] else "9999")
        
        # Calculate valid_events BEFORE using it
        critical_days = set()
        compromised_users = Counter() 

        for ev in raw_events:
            if ev['User'] and "System" not in ev['User']:
                compromised_users[ev['User']] += 1
            if ev['Criticality'] >= 60 and ev.get('dt_obj'):
                critical_days.add(ev['dt_obj'].strftime('%Y-%m-%d'))
        
        valid_events = []
        for ev in raw_events:
            if ev.get('dt_obj'):
                is_relevant = False
                ev_date = ev['dt_obj'].date()
                for c_day_str in critical_days:
                    c_date = datetime.datetime.strptime(c_day_str, '%Y-%m-%d').date()
                    if abs((ev_date - c_date).days) <= 1:
                        is_relevant = True
                        break
                if is_relevant: valid_events.append(ev)
            else: valid_events.append(ev)
        
        cats = set([ev['Category'] for ev in valid_events])
        
        impact_summary = []
        if "C2" in cats: impact_summary.append("C2通信")
        if "PERSIST" in cats: impact_summary.append("永続化設定")
        if "ANTI" in cats: impact_summary.append("証拠隠滅")
        if "INIT" in cats: impact_summary.append("不正スクリプトの実行")
        if "DROP" in cats: impact_summary.append("不正ツールの作成")

        conclusion_type = "悪意ある攻撃活動"
        if "INIT" in cats and "C2" in cats:
            conclusion_type = "悪意あるスクリプトの実行を起点とした攻撃活動"
        elif "PERSIST" in cats and "ANTI" not in cats:
            conclusion_type = "システムへの不正な永続化設定の設置"
        elif "C2" in cats and "INIT" not in cats:
            conclusion_type = "外部C2サーバーへの不審な通信活動"

        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"# {t['title']}\n\n")
            f.write(f"### 🛡️ {t['coc_header']}\n")
            f.write("| Item | Details |\n|---|---|\n")
            f.write(f"| **Case Name** | {self.case_name} |\n")
            f.write(f"| **Date** | {datetime.datetime.now().strftime('%Y-%m-%d')} |\n")
            f.write(f"| **Examiner** | {t['investigator']} |\n")
            f.write(f"| **Status** | Analyzed (SkiaHelios v15.23) |\n\n")
            f.write("---\n\n")

            f.write(f"## {t['h1_exec']}\n")
            if valid_events:
                # Find pivot time from Criticality > 90
                latest_crit = "Unknown"
                for ev in reversed(valid_events):
                    if ev['Criticality'] >= 90:
                        latest_crit = str(ev['Time']).split('.')[0]
                        break
                f.write(f"**結論:**\n{latest_crit} (UTC) 頃、端末 {self.case_name} において、**{conclusion_type}**を検知しました。\n\n")
                
                main_user = compromised_users.most_common(1)
                user_str = main_user[0][0] if main_user else "特定不能 (System権限のみ)"
                f.write(f"**侵害されたアカウント:**\n主に **{user_str}** アカウントでの活動が確認されています。\n\n")
                f.write(f"**被害範囲:**\n攻撃者により、以下の活動が行われた痕跡を確認しました。\n")
                f.write(f"* **{'、'.join(impact_summary)}**\n\n")
            else:
                f.write("**結論:**\n現在提供されているログの範囲では、クリティカルな侵害痕跡は確認されませんでした。\n\n")

            f.write(f"## {t['h1_time']}\n")
            phases = self._partition_timeline(valid_events)
            for idx, phase in enumerate(phases):
                if not phase: continue
                date_str = str(phase[0]['Time']).replace('T', ' ').split(' ')[0]
                f.write(f"### 📅 Phase {idx+1} ({date_str})\n")
                f.write(f"| Time (UTC) | User | フェーズ | イベント概要 | 証拠ソース |\n|---|---|---|---|---|\n")
                for ev in phase:
                    cat_name = t['cats'].get(ev['Category'], "その他").split("(")[0].strip()
                    time_display = self._get_time_str(ev)
                    u = ev['User'] if ev['User'] else "-"
                    summary = ev['Summary']
                    
                    # [FIX] Safe Access for Origin Analysis
                    kws = ev.get('Keywords')
                    kw = kws[0] if kws else ""
                    
                    origin_info = self._analyze_origin(kw, ev.get('dt_obj'))
                    if origin_info and "Creation" in summary: summary += f" <br>↳ ({origin_info})"
                    f.write(f"| {time_display} | {u} | {cat_name} | {summary} | {ev['Source']} |\n")
                if idx < len(phases)-1: f.write("\n*( ... Time Gap ... )*\n\n")
            f.write("\n")

            f.write(f"## {t['h1_tech']}\n")
            tech_groups = {k: [] for k in ["INIT", "DROP", "C2", "PERSIST", "ANTI"]}
            for ev in valid_events:
                if ev['Category'] in tech_groups: tech_groups[ev['Category']].append(ev)
            
            def write_finding(ev):
                insight = self._generate_insight(ev)
                timestamp = str(ev['Time']).replace('T', ' ').split('.')[0]
                f.write(f"- **検出事項:** {ev['Summary']}\n")
                f.write(f"  - **検知日時:** {timestamp} (UTC)\n")
                f.write(f"  - **実行ユーザー:** {ev['User']}\n")
                f.write(f"  - **分析:** {insight}\n")
                f.write(f"  - **証拠:** {ev['Source']}\n")
                if ev.get('Keywords') and ev['Keywords'][0]:
                    f.write(f"  - **関連要素:** `{ev['Keywords'][0]}`\n")
                if len(str(ev['Detail'])) > 10:
                    f.write(f"  - **詳細ログ:**\n```text\n{str(ev['Detail'])[:300]}...\n```\n")
                f.write("\n")

            f.write(f"### 3.1. {t['cats']['INIT']}\n")
            if tech_groups["INIT"]:
                for ev in tech_groups["INIT"][:3]: write_finding(ev)
            else: f.write("該当なし\n")

            f.write(f"\n### 3.2. {t['cats']['DROP']}\n")
            if tech_groups["DROP"]:
                for ev in tech_groups["DROP"][:5]: write_finding(ev)
            else: f.write("該当なし\n")
            
            f.write(f"\n### 3.3. {t['cats']['C2']}\n")
            if tech_groups["C2"]:
                for ev in tech_groups["C2"][:5]: write_finding(ev)
            else: f.write("該当なし\n")

            f.write(f"\n### 3.4. {t['cats']['PERSIST']}\n")
            if tech_groups["PERSIST"]:
                for ev in tech_groups["PERSIST"]: write_finding(ev)
            else: f.write("該当なし\n")

            f.write(f"\n### 3.5. {t['cats']['ANTI']}\n")
            if tech_groups["ANTI"]:
                for ev in tech_groups["ANTI"]: write_finding(ev)
            else: f.write("該当なし\n")

            f.write(f"\n## {t['h1_rec']}\n")
            f.write(f"**封じ込め:**\n端末をネットワークから切断し、全社環境において同様のIoC（ファイルハッシュ、通信先）を持つ端末がないかスキャンを実施してください。\n\n")
            f.write(f"**根絶:**\n特定された永続化ファイル（UpdateService.exe等）および関連するレジストリキー、タスクスケジューラ設定を削除してください。\n\n")
            f.write(f"**回復:**\nバックアップから削除されたファイル（Confidential_Design.docx等）を復元し、**影響を受けたアカウント（{user_str}）**のパスワードリセットを行ってください。\n\n")

            f.write(f"## {t['h1_app']}\n")
            f.write("Appendix A: Master Timeline CSV\n")
            f.write("Appendix B: Tool Output Logs\n")
            f.write(f"\n---\n*Report generated by SkiaHelios v15.23*")

    def _collect_and_filter_events(self):
        events = []
        
        # [Sphinx]
        if self.dfs['Sphinx'] is not None:
            hits = self.dfs['Sphinx'].filter(pl.col("Sphinx_Tags").str.contains("ATTACK|DECODED"))
            hits = hits.unique(subset=["Original_Snippet"])
            for row in hits.iter_rows(named=True):
                full = row.get("Decoded_Hint") or row.get("Original_Snippet")
                url_match = self._extract_url(full)
                # [FIX] Extract filename from command line
                cmd_file = self._extract_filename_from_cmd(full)
                
                kws = []
                if url_match: kws.append(url_match)
                if cmd_file: kws.append(cmd_file)
                
                src = self._resolve_source("SPHINX", row)
                u = self._resolve_user(row, "SPHINX")
                events.append({
                    "Time": row['TimeCreated'], "Source": src, "User": u,
                    "Summary": f"Script Execution: {row['Sphinx_Tags']}",
                    "Detail": full, "Criticality": 100,
                    "Category": self._classify_category("Sphinx", row['Sphinx_Tags'], full),
                    "Keywords": kws
                })

        # [Network]
        if self.dfs['Network'] is not None and "Tag" in self.dfs['Network'].columns:
            net_hits = self.dfs['Network'].filter(pl.col("Tag").str.contains("NETWORK|C2"))
            net_hits = net_hits.unique(subset=["Timestamp_UTC", "Action"])
            for row in net_hits.iter_rows(named=True):
                target = str(row['Action']) + " " + str(row['Target_Path'])
                url = self._extract_url(target)
                # [FIX] Extract filename from command line
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
                        "Category": "C2",
                        "Keywords": kws
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
                    "Category": "PERSIST",
                    "Keywords": [fname]
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

        # [Chronos] - Keep Timestomp logic
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
                         "Detail": f"Score: {score}", 
                         "Criticality": 50, "Category": "ANTI", "Keywords": [fname]
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
    parser.add_argument("--plutos-net"); parser.add_argument("--sphinx"); parser.add_argument("--chronos")
    parser.add_argument("--persistence"); parser.add_argument("--lang", default="jp")
    args = parser.parse_args(argv)
    
    try:
        weaver = HekateWeaver(
            args.input, args.aion, args.pandora, args.plutos, args.plutos_net, 
            args.sphinx, args.chronos, args.persistence, args.lang, args.case
        )
        weaver.generate_report(args.out)
        print(f"[+] SANS Report Generated: {args.out}")
    except Exception as e:
        print(f"[!] HEKATE Crash Report: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
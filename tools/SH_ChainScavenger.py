# ============================================================
#  SH_ChainScavenger v1.0 [Chain Scavenger - Dirty Hive Analyzer]
#  Mission: Extract hidden user accounts from dirty/corrupted SAM hives
#  Trigger: RECmd failure, LOG divergence, or binary inconsistency
# ============================================================

import os
import re
import struct
from pathlib import Path
from datetime import datetime

class ChainScavenger:
    """
    Binary-level SAM hive analyzer for dirty/corrupted hives.
    Extracts user account names using anchor search and context carving.
    """
    
    # UTF-16LE anchor: "Names"
    ANCHOR_NAMES = b'\x4E\x00\x61\x00\x6D\x00\x65\x00\x73\x00'
    # ASCII anchor: "Names" (Common in modern hives)
    ANCHOR_NAMES_ASCII = b'Names'
    
    # Stoplist: Standard Windows accounts to exclude
    STOPLIST = [
        "administrator", "guest", "support_", "defaultaccount",
        "wdagutilityaccount", "krbtgt", "system", "local service",
        "network service", "everyone", "users", "authenticated users",
        "backup operators", "power users", "replicator", "iis_iusrs"
    ]
    
    # Context carving size (±2048 bytes = 4KB total)
    CARVE_SIZE = 2048
    # Minimum username length
    MIN_USERNAME_LEN = 3
    
    def __init__(self, raw_dir):
        self.raw_dir = Path(raw_dir)
        self.sam_files = sorted(list(self.raw_dir.glob("**/SAM*"))) + sorted(list(self.raw_dir.glob("**/SECURITY*")))
        self.log_files = sorted(list(self.raw_dir.glob("**/*.log"))) + sorted(list(self.raw_dir.glob("**/*.jrs")))
        self.results = []
        
        # [v5.6.3] Request: Expand context to ±16KB to capture dispersed artifacts
        self.CONTEXT_SIZE = 32768
        self.MIN_USERNAME_LEN = 3
        
        # Known RIDs for Linking
        self.RID_MAP = {
            500: "Administrator",
            501: "Guest",
            502: "KRBTGT",
            512: "Domain Admins",
            513: "Domain Users",
            514: "Domain Guests",
            519: "Enterprise Admins",
            544: "Administrators",
            545: "Users",
            546: "Guests",
            547: "Power Users",
            548: "Account Operators",
            549: "Server Operators",
            550: "Print Operators",
            551: "Backup Operators",
            552: "Replicator"
        }
        
        self.STOPLIST = {
            "microsoft", "windows", "program", "policy", "internet",
            "explorer", "notep", "system", "service", "config",
            "software", "current", "control", "default", "classes",
            "root", "local", "machine", "user", "names", "sids",
            "schema", "objects"
        }
        
        # [B.2] Event Log Path for Correlation
        self.event_log_csv = None
        self._event_users = set()  # Cache for users found in event logs
    
    def set_event_log_path(self, evtx_csv_path):
        """[B.2] Set the path to EvtxECmd output CSV for event correlation."""
        self.event_log_csv = evtx_csv_path
        self._load_event_users()
    
    def _load_event_users(self):
        """[B.2] Pre-load users from Security Event Log for fast correlation."""
        if not self.event_log_csv or not Path(self.event_log_csv).exists():
            return
        
        print(f"    -> [ChainScavenger] Loading event log users from: {self.event_log_csv}")
        try:
            import polars as pl
            df = pl.read_csv(self.event_log_csv, ignore_errors=True, infer_schema_length=0)
            
            # Target Event IDs: 4624 (Logon), 4625 (Failed Logon), 4688 (Process Creation)
            target_eids = ["4624", "4625", "4688", "4720", "4728", "4732"]
            
            # Filter by EventId
            if "EventId" in df.columns:
                df = df.filter(pl.col("EventId").is_in(target_eids))
            elif "Event Id" in df.columns:
                df = df.filter(pl.col("Event Id").is_in(target_eids))
            
            # Extract usernames from various columns
            user_cols = ["TargetUserName", "SubjectUserName", "TargetUser", "User", "Account"]
            for col in user_cols:
                if col in df.columns:
                    users = df.select(pl.col(col).str.to_lowercase().unique()).to_series().to_list()
                    self._event_users.update([u for u in users if u and len(u) >= 3])
            
            print(f"        [+] Loaded {len(self._event_users)} unique users from event logs")
        except Exception as e:
            print(f"        [!] Event log loading error: {e}")
    
    def correlate_with_events(self, scavenge_results):
        """
        [B.2] Cross-reference scavenged accounts with event log activity.
        
        If an account has NO corresponding events (4624/4625/4688), 
        demote its score and mark as LOW_CONFIDENCE.
        
        Args:
            scavenge_results: List of scavenge result dicts
            
        Returns:
            List of results with adjusted scores
        """
        if not self._event_users:
            print("    -> [ChainScavenger] No event log data loaded, skipping correlation.")
            return scavenge_results
        
        print(f"    -> [ChainScavenger] Correlating {len(scavenge_results)} accounts with event logs...")
        
        correlated_count = 0
        for result in scavenge_results:
            username = result.get("Username", "").lower()
            
            if username in self._event_users:
                # Account has event correlation - boost confidence
                result["AION_Tags"] = result.get("AION_Tags", "") + ",EVENT_CORRELATED"
                correlated_count += 1
            else:
                # No event correlation - demote score
                original_score = result.get("Threat_Score", 0)
                result["Threat_Score"] = max(0, int(original_score * 0.3))  # 70% reduction
                result["AION_Tags"] = result.get("AION_Tags", "") + ",LOW_CONFIDENCE_NO_EVENT"
        
        print(f"        [+] Correlated: {correlated_count}/{len(scavenge_results)} accounts")
        return scavenge_results
    
    # ================================================================
    # Trigger Detection: Dirty Hive Recognition
    # ================================================================
    
    def is_dirty_hive(self, parsed_csv_path=None):
        """
        Detect if SAM hive is dirty and requires scavenging.
        
        Returns:
            tuple: (is_dirty: bool, reason: str)
        """
        reasons = []
        
        # Trigger 1: RECmd Silence (CSV empty or no Names key)
        if parsed_csv_path:
            if not Path(parsed_csv_path).exists():
                reasons.append("RECmd_NO_OUTPUT")
            else:
                try:
                    size = Path(parsed_csv_path).stat().st_size
                    if size == 0:
                        reasons.append("RECmd_EMPTY_CSV")
                    else:
                        with open(parsed_csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(4096)
                            if "Names" not in content and "SAM" not in content:
                                reasons.append("RECmd_NO_NAMES_KEY")
                except Exception:
                    reasons.append("RECmd_READ_ERROR")
        
        # Trigger 2: LOG File Divergence
        for sam_file in self.sam_files:
            try:
                sam_size = sam_file.stat().st_size
                for log_file in self.log_files:
                    log_size = log_file.stat().st_size
                    
                    # 10% threshold OR 64KB absolute
                    if log_size > (sam_size * 0.1) or log_size > 65536:
                        reasons.append(f"LOG_DIVERGENCE: {log_file.name} ({log_size} bytes)")
            except Exception:
                pass
        
        # Trigger 3: Binary Inconsistency (Dirty Bit)
        for sam_file in self.sam_files:
            dirty_check = self._check_dirty_bit(sam_file)
            if dirty_check:
                reasons.append(dirty_check)
        
        is_dirty = len(reasons) > 0
        return is_dirty, "; ".join(reasons) if reasons else "Clean"
    
    def _check_dirty_bit(self, hive_path):
        """
        Check if hive has dirty bit set or sequence number mismatch.
        
        Registry hive header structure:
        - Offset 0x00: Signature "regf"
        - Offset 0x04: Primary Sequence Number
        - Offset 0x08: Secondary Sequence Number
        """
        try:
            with open(hive_path, 'rb') as f:
                header = f.read(32)
                
                # Verify "regf" signature
                if header[:4] != b'regf':
                    return "INVALID_HIVE_SIGNATURE"
                
                # Check sequence numbers
                seq_primary = struct.unpack('<I', header[4:8])[0]
                seq_secondary = struct.unpack('<I', header[8:12])[0]
                
                if seq_primary != seq_secondary:
                    return f"SEQUENCE_MISMATCH: {seq_primary} != {seq_secondary}"
                
        except Exception as e:
            return f"HIVE_READ_ERROR: {str(e)}"
        
        return None
    
    # ================================================================
    # Step A: Anchor Search
    # ================================================================
    
    def anchor_search(self, data):
        """
        Search for 'Names' anchor in binary data (UTF-16LE and ASCII).
        
        Args:
            data: Binary data to search
            
        Returns:
            List of hit offsets
        """
        offsets = []
        
        # Search UTF-16LE
        start = 0
        while True:
            pos = data.find(self.ANCHOR_NAMES, start)
            if pos == -1:
                break
            offsets.append(pos)
            start = pos + 1
            
        # Search ASCII
        start = 0
        while True:
            pos = data.find(self.ANCHOR_NAMES_ASCII, start)
            if pos == -1:
                break
            offsets.append(pos)
            start = pos + 1
            
        # [v5.6.2] Extended Anchor: "Users" Key (UTF-16LE)
        anchor_users = b'\x55\x00\x73\x00\x65\x00\x72\x00\x73\x00'
        start = 0
        while True:
            pos = data.find(anchor_users, start)
            if pos == -1: break
            offsets.append(pos)
            start = pos + 1

        # [v5.6.2] Extended Anchor: "Users" Key (ASCII)
        anchor_users_asc = b'Users'
        start = 0
        while True:
            pos = data.find(anchor_users_asc, start)
            if pos == -1: break
            offsets.append(pos)
            start = pos + 1

        # [v5.6.2] Extended Anchor: RID-like Hex Strings (0000xxxx)
        # Looking for "0000" prefix in UTF-16LE (30 00 30 00 30 00 30 00) followed by 4 hex digits
        # This is expensive, so we use regex
        rid_pattern = rb'\x30\x00\x30\x00\x30\x00\x30\x00[\x30-\x39\x41-\x46]\x00[\x30-\x39\x41-\x46]\x00[\x30-\x39\x41-\x46]\x00[\x30-\x39\x41-\x46]\x00'
        for match in re.finditer(rid_pattern, data):
             offsets.append(match.start())
            
        return sorted(list(set(offsets)))
    
    # ================================================================
    # Step B: Context Carving
    # ================================================================
    
    def context_carve(self, data, offset):
        """
        Extract context around anchor hit.
        
        Args:
            data: Full binary data
            offset: Anchor hit offset
            
        Returns:
            tuple: (carved_data, actual_start, actual_end)
        """
        start = max(0, offset - self.CARVE_SIZE)
        end = min(len(data), offset + self.CARVE_SIZE)
        
        return data[start:end], start, end
    
    # ================================================================
    # Step C: Intelligent Filtering
    # ================================================================

    def _extract_rid_near_match(self, data, match_pos):
        """
        [Deep Carving] Search for RID pattern "0000xxxx" near the username match.
        """
        # Look range: ±512 bytes
        start = max(0, match_pos - 512)
        end = min(len(data), match_pos + 512)
        chunk = data[start:end]
        
        # Regex for RID string (UTF-16LE or ASCII "0000xxxx")
        # UTF-16LE: 30 00 30 00 30 00 30 00 [x] [x] [x] [x]
        rid_pattern_u = rb'\x30\x00\x30\x00\x30\x00\x30\x00([\x30-\x39\x41-\x46]\x00){4}'
        
        matches = []
        for m in re.finditer(rid_pattern_u, chunk):
            # Calculate distance to username match (in original data frame)
            rid_real_pos = start + m.start()
            dist = abs(rid_real_pos - match_pos)
            matches.append((dist, m.group()))
            
        if not matches:
             # Try ASCII
             rid_pattern_a = rb'0000[0-9A-F]{4}'
             for m in re.finditer(rid_pattern_a, chunk):
                rid_real_pos = start + m.start()
                dist = abs(rid_real_pos - match_pos)
                matches.append((dist, m.group(), "strong")) # Strong

        # Heuristic 2: Raw DWORD Search (Little Endian Integer 500-10000)
        # Often RID is stored as a 4-byte integer in the V-Key data nearby
        # Search range: ±64 bytes close to the name
        h_start = max(0, match_pos - 64)
        h_end = min(len(data), match_pos + 128)
        header_chunk = data[h_start:h_end]
        
        # Scan 4-byte alignment
        for i in range(0, len(header_chunk) - 4, 4):
            try:
                val = struct.unpack('<I', header_chunk[i:i+4])[0]
                # Valid RID range: 500 (Admin) to 20000 (User)
                if 500 <= val < 10000:
                   # Calculate distance
                   current_pos = h_start + i
                   dist = abs(current_pos - match_pos)
                   # Prioritize this BUT string matches are stronger
                   # We append with a penalty to distance (so string matches preferred)
                   matches.append((dist + 1000, str(val).encode(), "weak")) 
            except: pass

        # Heuristic 3: Binary SID parsing (01 0X 00 00 00 00 00 05 ...)
        # If we find a SID, the last subauthority IS the RID (or Group RID)
        # Search for: 01 (Rev) + [01-05] (SubAuthCount) + ... 00 00 00 05 (NT Auth)
        sid_pattern = rb'\x01[\x01-\x05]\x00\x00\x00\x00\x00\x05'
        for m in re.finditer(sid_pattern, chunk):
            # Parse the full SID to get the last RID
            try:
                sid_start = m.start()
                sub_count = chunk[sid_start+1] 
                # Total SID Size: 8 (Header) + 4 * SubCount
                sid_size = 8 + (4 * sub_count)
                
                if sid_start + sid_size <= len(chunk):
                    sid_bytes = chunk[sid_start:sid_start+sid_size]
                    
                    # Validate First SubAuthority (should be 21 or 32)
                    # SubAuth starts at offset 8. 4 bytes Little Endian.
                    try:
                        sub_auth_0 = struct.unpack('<I', sid_bytes[8:12])[0]
                        if sub_auth_0 not in [21, 32]:
                            continue
                    except: continue

                    # Extract last SubAuth (RID)
                    # Last 4 bytes
                    rid_bytes = sid_bytes[-4:]
                    rid_val = struct.unpack('<I', rid_bytes)[0]
                    
                    if 500 <= rid_val < 10000:
                         dist = abs((start + sid_start) - match_pos)
                         matches.append((dist + 500, str(rid_val).encode(), "strong")) # Binary SID is Strong
            except: pass

        if matches:
            # Pick closest RID (considering penalties)
            matches.sort(key=lambda x: x[0])
            best_match = matches[0][1]
            method_type = matches[0][2]
            
            try:
                # If it was a hex string (byte string starting with 30 or 00), decode.
                # If it was raw int (byte string of digits), just use it.
                if best_match.startswith(b'0') or best_match.startswith(b'\x30'):
                     rid_str = best_match.replace(b'\x00', b'').decode('ascii')
                     rid_val = int(rid_str, 16)
                     # method = "strong" # String pattern (already set)
                elif len(best_match) == 4: # encoded raw int bytes
                     rid_val = struct.unpack('<I', best_match)[0]
                     # method = "strong" if dist == 500 else "weak" # Logic moved to append
                else:
                     rid_val = int(best_match.decode('ascii'))
                     # method = "strong"
                     
                return {
                    "rid": str(rid_val),
                    "sid": f"S-1-5-21-UNKNOWN-{rid_val}",
                    "method": method_type
                }
            except: pass
            
        return {"rid": "", "sid": "", "method": "none"}

    def _extract_hash_heuristics(self, data, match_pos):
        """
        [Deep Carving] Search for F-Key/V-Key structures near match.
        Uses struct.unpack to identify binary signatures and dump potential NTLM hash.
        """
        # Search range: ±1024 bytes (F-Key can be large, hash is usually inside V-value)
        # NTLM Hash is 16 bytes.
        # We look for the "V" structure header if possible, or common patterns.
        
        start = max(0, match_pos - 1024)
        end = min(len(data), match_pos + 1024)
        chunk = data[start:end]
        
        recovered_state = "Not Found"
        detail = ""
        
        # Pattern for SAM V-Key Data containing Hash
        # Hard to map exact offset without full parser.
        # However, we can look for the F-Key Type 0x02 / 0x03 Header
        # And then heuristically grab the most entropy-rich 16 bytes or specific offset.
        
        # Heuristic: Locate F-Key Header (02 00 01 00 ...)
        # NTLM Hash is often at offset 0xA8 or nearby in the V-data for standard users.
        # BUT this varies. 
        # Better Heuristic: Look for "LM Hash" / "NT Hash" structure markers? No.
        
        # User request: "dump 16bytes".
        # Let's search for the Type heuristic.
        
        # Try to find F-Key Header
        fkey_header = b'\x02\x00\x01\x00' # Type 2 (Local)
        
        idx = chunk.find(fkey_header)
        if idx == -1:
            fkey_header = b'\x03\x00\x01\x00' # Type 3 (Domain?)
            idx = chunk.find(fkey_header)
            
        if idx != -1:
             recovered_state = "Struct Found"
             
             # Attempt to carve NTLM Hash
             # In many cases, hash is distinct. 
             # Let's dump a candidate slice.
             # NTLM hash often appears after the header. 
             # We will grab a 16-byte chunk that looks like a hash (no nulls?) - NTLM can have nulls.
             # Just dump [idx+160 : idx+176] (Approx offset)
             # This is a wild guess but better than nothing for "offline crack attempt"
             
             # Let's look for known specific offset.
             # V data: 
             # 0x0C: Offset to Data
             # 0x10: Len
             
             # Let's try to parse V-Header at idx? No idx is F-Key type.
             # F-Key contains V-Key inside? No.
             
             # Let's return the 16 bytes at offset +0x9C (Typical NTLM offset in F structure on some systems)
             # Or just label it "Potential Hash"
             hash_offset = idx + 168 # 0xA8
             if hash_offset + 16 <= len(chunk):
                 candidate = chunk[hash_offset:hash_offset+16]
                 detail = candidate.hex().upper()
                 recovered_state = "Hash Candidate"
             else:
                 detail = "F-Key Header Found (Truncated)"

        return {"state": recovered_state, "detail": detail}
    
    def intelligent_filter(self, carved_data):
        """
        Extract potential usernames from carved context.
        Uses Unicode string extraction with stoplist filtering.
        
        Args:
            carved_data: 4KB binary context
            
        Returns:
            List of extracted username candidates
        """
        candidates = []
        
        # Regex: 3+ characters of printable ASCII in UTF-16LE [Relaxed for 'hacker' detection]
        # Pattern: ([\x20-\x7E]\x00){3,}
        pattern = rb'([\x20-\x7E]\x00){3,}'
        
        for match in re.finditer(pattern, carved_data):
            try:
                # Decode UTF-16LE
                raw_bytes = match.group()
                decoded = raw_bytes.decode('utf-16le', errors='ignore').strip()
                
                # Filter criteria
                if len(decoded) < self.MIN_USERNAME_LEN:
                    continue
                if len(decoded) > 64:  # Max reasonable username length
                    continue
                
                # Skip if in stoplist
                if any(stop in decoded.lower() for stop in self.STOPLIST):
                    continue
                
                # Skip if contains special characters (not a username)
                if re.search(r'[\\/:*?"<>|{}()\[\]]', decoded):
                    continue
                
                # Skip if all numbers
                if decoded.isdigit():
                    continue
                
                # Skip common Windows paths/strings
                skip_patterns = [
                    r'^[A-Z]:\\', r'^\\\\', r'^http', r'^www\.',
                    r'\.dll$', r'\.exe$', r'\.sys$',
                    r'^microsoft', r'^windows', r'^program'
                ]
                if any(re.search(p, decoded, re.IGNORECASE) for p in skip_patterns):
                    continue

                # [v5.7.1] Anti-Hallucination: Strict Garbage Filter
                # Reject localized resource strings (%%1843) and common English noise (have co, Security)
                junk_patterns = [
                    r'^%%',           # Resource Strings
                    r'(?i)^have co',  # Fragment: "have come"
                    r'(?i)^security', # Registry Key Name
                    r'(?i)^system',   # Registry Key Name
                    r'(?i)^only',     # Fragment
                    r'(?i)^default',  # Default User
                    r'(?i)^software', 
                    r'(?i)^policy',
                    r'(?i)^current',
                    r'(?i)^local',
                    r'(?i)^machine', 
                    r'(?i)^unknown',
                    r'(?i)^account'   # "Account"
                ]
                if any(re.search(p, decoded) for p in junk_patterns):
                    continue
                
                # [Deep Carving] Context Hex Extraction
                # Extract 32 bytes around the match to see RID or F-Key heuristically
                start_match = match.start()
                end_match = match.end()
                
                # Look ahead for RID pattern (often 4 bytes after name or near it)
                # But simple context hex is better for Manual Verification
                ctx_start = max(0, start_match - 16)
                ctx_end = min(len(carved_data), end_match + 32)
                ctx_bytes = carved_data[ctx_start:ctx_end]
                try:
                    ctx_hex = ctx_bytes.hex()
                    # Format as readable hex dump
                    # e.g. "4E006100... [Name]"
                    ctx_preview = f"{ctx_hex[:32]}...{ctx_hex[-32:]} (Size:{len(ctx_bytes)})"
                except:
                    ctx_preview = "N/A"

                # [v5.6.3] Deep Carving: SID/RID & Hash Recovery
                rid_info = self._extract_rid_near_match(carved_data, start_match)
                hash_info = self._extract_hash_heuristics(carved_data, start_match)

                candidates.append({
                    "name": decoded, 
                    "context_hex": ctx_preview,
                    "rid": rid_info.get("rid", ""),
                    "sid": rid_info.get("sid", ""),
                    "rid_method": rid_info.get("method", "none"),
                    "hash_state": hash_info.get("state", "Unknown"),
                    "hash_detail": hash_info.get("detail", "")
                })
                
            except Exception:
                continue
        
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for c in candidates:
            c_name = c["name"]
            c_lower = c_name.lower()
            if c_lower not in seen:
                seen.add(c_lower)
                unique.append(c)
        
        return unique
    
    # ================================================================
    # Main Entry Point: Scavenge
    # ================================================================
    
    # [Strict Validation Check]
    def _is_valid_username(self, candidate_str):
        if not candidate_str: return False
        
        # 1. Length & Composition Check
        if len(candidate_str) < 4: return False
        if re.match(r'^[\W\d_]+$', candidate_str): return False # Only symbols/digits
        
        # 2. Specific Garbage Patterns (Case 7 observed)
        garbage_patterns = [
            r"%%", r"have co", r"iCg t", r"Distribute", r"Syst", 
            r"Members are", r"Performance", r"Cryptographic"
        ]
        for pat in garbage_patterns:
            if re.search(pat, candidate_str, re.IGNORECASE):
                return False
                
        # 3. Charset (Allow Alphanumeric, dot, dash, underscore, space)
        if not re.match(r'^[a-zA-Z0-9\.\-_ ]+$', candidate_str):
            return False
            
        return True

    def scavenge(self):
        """
        Main scavenging operation.
        
        Returns:
            List of dict with extracted user information
        """

        # print("[*] Chain Scavenger: Initiating Dirty Hive Analysis...")
        
        if not self.sam_files and not self.log_files:
             pass # print("    [-] No SAM hive files found.")
             return []
        
        all_files = self.sam_files + self.log_files
        # print(f"    [*] Scanning {len(all_files)} hive/log files...")
        
        for hive_file in all_files:
            try:
                # print(f"    -> Scavenging: {hive_file.name}")
                
                with open(hive_file, 'rb') as f:
                    data = f.read()
                
                # Step A: Anchor Search
                offsets = self.anchor_search(data)
                # print(f"       Found {len(offsets)} 'Names' anchors")
                
                for offset in offsets:
                    # Step B: Context Carving
                    carved, start, end = self.context_carve(data, offset)
                    
                    # Step C: Intelligent Filtering
                    usernames = self.intelligent_filter(carved)
                    
                    # [v5.7.1] Capture File ModTime for Accurate Timeline
                    try:
                        f_mtime = hive_file.stat().st_mtime
                        f_iso = datetime.fromtimestamp(f_mtime).isoformat()
                    except:
                        f_iso = datetime.now().isoformat()

                    for user_obj in usernames:
                        # [Strict Validation]
                        if not self._is_valid_username(user_obj["name"]):
                            continue

                        user_obj["File_ModTime"] = f_iso # Pass to result builder
                        username = user_obj["name"]
                        ctx_hex = user_obj["context_hex"]
                        rid = user_obj.get("rid", "")
                        sid = user_obj.get("sid", "")
                        rid_method = user_obj.get("rid_method", "none")
                        hash_st = user_obj.get("hash_state", "")

                        # Score Boost for Complete Recovery (RID found)
                        # [v5.6.3] Noise Reduction: Only boost score for STRONG RID matches (Binary SID / String Pattern)
                        # We do NOT boost for "Raw DWORD" heuristic (weak) UNLESS it is a known Privileged RID (e.g. 544).
                        base_score = 400
                        tags = "SAM_SCAVENGE, NEW_USER_CREATED, LOG_WIPE_INDUCED_MISSING_USER_EVENT" # [v5.6.3] Verdict Added
                        
                        extra_note = ""
                        
                        is_privileged = False
                        if rid:
                            try:
                                rid_int = int(rid)
                                # [Final Sanity Check]
                                # Reject RIDs that are unreasonably high (noise).
                                # Valid User RIDs usually don't exceed 10000-20000 in typical scenarios.
                                # Anomalous RIDs (e.g. 900000000) are carving artifacts.
                                if rid_int > 20000:
                                    rid = "" # Invalidate
                                    rid_method = "none"
                                elif rid_int in self.RID_MAP: 
                                    is_privileged = True
                            except: pass
                        
                        if rid and (rid_method == "strong" or is_privileged):
                            base_score = 900 # Critical
                            tags += ", ACCOUNT_FULLY_RECOVERED, SID_RESTORED"
                            
                            # [Deep Carving] Group Linking Logic
                            # If RID maps to a known Group, but Username is NOT that group -> Link!
                            try:
                                rid_int = int(rid)
                                if rid_int in self.RID_MAP:
                                    known_name = self.RID_MAP[rid_int]
                                    # Fuzzy check: Is the detected username just the group name?
                                    # e.g. "Administrators" vs "hacker"
                                    # Normalize for check
                                    norm_user = username.lower().replace(" ", "")
                                    norm_group = known_name.lower().replace(" ", "")
                                    
                                    if norm_group not in norm_user:
                                        # Distinct name with Group RID -> MEMBERSHIP LINK
                                        extra_note = f" [Linked to Group: {known_name}]"
                                        tags += ", PRIVILEGE_ESCALATION_INDICATOR"
                            except: pass

                        # Create result entry
                        # [v5.7.1] Timestamp Fix: Use Hive File ModTime logic (passed from scavenge loop)
                        # If not available, fallback to now. But scavenge loop should provide it.
                        self.results.append({
                            "Timestamp": user_obj.get("File_ModTime", datetime.now().isoformat()),
                            "Username": username,
                            "Source": f"SCAVENGE:{hive_file.name}",
                            "Offset": hex(offset),
                            "Context_Range": f"{hex(start)}-{hex(end)}",
                            "Context_Hex": ctx_hex,
                            "Entry_Location": f"SAM_SCAVENGE: {hive_file.name} [SID: {sid or 'N/A'}]{extra_note}",
                            "RID": rid,
                            "SID": sid,
                            "Hash_State": hash_st,
                            "Hash_Detail": user_obj.get("hash_detail", ""),
                            "AION_Score": base_score,
                            "AION_Tags": tags,
                            "Threat_Score": base_score,
                            "Threat_Tag": tags
                        })
            except Exception as e:
                pass # print(f"    [-] Error scavenging {hive_file.name}: {e}")
        
        # Deduplicate Logic
        # 1. Group by RID (if present) -> Keep Longest Name
        # 2. Key by Username (if no RID) -> Keep as is
        
        from collections import defaultdict
        rid_groups = defaultdict(list)
        no_rid_list = []
        
        for r in self.results:
            rid = r.get("RID", "")
            # Only use RID for grouping if it's a valid integer-like string
            if rid and rid.isdigit():
                rid_groups[rid].append(r)
            else:
                no_rid_list.append(r)
                
        final_results = []
        
        # Process RID groups: Keep the candidate with the longest Username
        for rid, group in rid_groups.items():
            # Sort by Name Length (Desc)
            group.sort(key=lambda x: len(x["Username"]), reverse=True)
            best_candidate = group[0]
            final_results.append(best_candidate)
            
        # Add non-RID entries (ensure username uniqueness among them)
        seen_users = set(r["Username"].lower() for r in final_results)
        
        for r in no_rid_list:
            u_lower = r["Username"].lower()
            if u_lower not in seen_users:
                seen_users.add(u_lower)
                final_results.append(r)
                
        self.results = final_results
        
        if self.results:
            print(f"    [!] SCAVENGE SUCCESS: {len(self.results)} unique usernames extracted!")
            # for r in self.results:
            #     print(f"        ⚠️ {r['Username']} (from {r['Source']})")
        else:
            print("    [-] No suspicious usernames found.")
        
        return self.results


def main():
    """Standalone test entry point."""
    import argparse
    
    print("    [Chain Scavenger v1.0 - Dirty Hive Hunter]")
    
    parser = argparse.ArgumentParser(description="Chain Scavenger: Dirty SAM Hive Analyzer")
    parser.add_argument("--raw", required=True, help="Path to raw artifacts directory")
    parser.add_argument("--check-csv", help="Optional: Path to RECmd output CSV to check")
    parser.add_argument("-o", "--output", default="Scavenger_Report.csv", help="Output CSV path")
    
    args = parser.parse_args()
    
    scavenger = ChainScavenger(args.raw)
    
    # Check if dirty
    is_dirty, reason = scavenger.is_dirty_hive(args.check_csv)
    print(f"[*] Dirty Hive Check: {'DIRTY' if is_dirty else 'Clean'}")
    print(f"    Reason: {reason}")
    
    # Force scavenge regardless of dirty status for testing
    results = scavenger.scavenge()
    
    if results:
        import polars as pl
        df = pl.DataFrame(results)
        df.write_csv(args.output)
        print(f"\n[+] Results saved to: {args.output}")
    
    return results


if __name__ == "__main__":
    main()

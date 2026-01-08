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
            552: "Replicator",
            1000: "Interactive",
            1001: "Network Service",
            1002: "Local Service"
        }
        
        self.STOPLIST = {
            "microsoft", "windows", "program", "policy", "internet",
            "explorer", "notep", "system", "service", "config",
            "software", "current", "control", "default", "classes",
            "root", "local", "machine", "user", "names", "sids",
            "schema", "objects"
        }
    
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
                matches.append((dist, m.group()))

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
                   matches.append((dist + 1000, str(val).encode())) 
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
                    # Extract last SubAuth (RID)
                    # Last 4 bytes
                    rid_bytes = sid_bytes[-4:]
                    rid_val = struct.unpack('<I', rid_bytes)[0]
                    
                    if 500 <= rid_val < 10000:
                         dist = abs((start + sid_start) - match_pos)
                         matches.append((dist + 500, str(rid_val).encode())) # Penalty 500 (Better than raw, worse than string)
            except: pass

        if matches:
            # Pick closest RID (considering penalties)
            matches.sort(key=lambda x: x[0])
            best_match = matches[0][1]
            try:
                # If it was a hex string (byte string starting with 30 or 00), decode.
                # If it was raw int (byte string of digits), just use it.
                if best_match.startswith(b'0') or best_match.startswith(b'\x30'):
                     rid_str = best_match.replace(b'\x00', b'').decode('ascii')
                     rid_val = int(rid_str, 16)
                else:
                     rid_val = int(best_match.decode('ascii'))
                     
                return {
                    "rid": str(rid_val),
                    "sid": f"S-1-5-21-UNKNOWN-{rid_val}"
                }
            except: pass
            
        return {"rid": "", "sid": ""}

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
    
    def scavenge(self):
        """
        Main scavenging operation.
        
        Returns:
            List of dict with extracted user information
        """
        print("[*] Chain Scavenger: Initiating Dirty Hive Analysis...")
        
        if not self.sam_files and not self.log_files:
            print("    [-] No SAM hive files found.")
            return []
        
        all_files = self.sam_files + self.log_files
        print(f"    [*] Scanning {len(all_files)} hive/log files...")
        
        for hive_file in all_files:
            try:
                print(f"    -> Scavenging: {hive_file.name}")
                
                with open(hive_file, 'rb') as f:
                    data = f.read()
                
                # Step A: Anchor Search
                offsets = self.anchor_search(data)
                print(f"       Found {len(offsets)} 'Names' anchors")
                
                for offset in offsets:
                    # Step B: Context Carving
                    carved, start, end = self.context_carve(data, offset)
                    
                    # Step C: Intelligent Filtering
                    usernames = self.intelligent_filter(carved)
                    
                    for user_obj in usernames:
                        username = user_obj["name"]
                        ctx_hex = user_obj["context_hex"]
                        rid = user_obj.get("rid", "")
                        sid = user_obj.get("sid", "")
                        hash_st = user_obj.get("hash_state", "")

                        # Score Boost for Complete Recovery (RID found)
                        base_score = 400
                        tags = "SAM_SCAVENGE, NEW_USER_CREATED, LOG_WIPE_INDUCED_MISSING_USER_EVENT" # [v5.6.3] Verdict Added
                        
                        extra_note = ""
                        
                        if rid:
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
                        self.results.append({
                            "Timestamp": datetime.now().isoformat(),
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
                print(f"    [-] Error scavenging {hive_file.name}: {e}")
        
        # Deduplicate by username
        seen_users = set()
        unique_results = []
        for r in self.results:
            user_lower = r["Username"].lower()
            if user_lower not in seen_users:
                seen_users.add(user_lower)
                unique_results.append(r)
        
        self.results = unique_results
        
        if self.results:
            print(f"    [!] SCAVENGE SUCCESS: {len(self.results)} unique usernames extracted!")
            for r in self.results:
                print(f"        ⚠️ {r['Username']} (from {r['Source']})")
        else:
            print("    [-] No suspicious usernames found.")
        
        return self.results


def main():
    """Standalone test entry point."""
    import argparse
    
    print("""
    ╔═══════════════════════════════════════════╗
    ║   Chain Scavenger v1.0 - Dirty Hive Hunter ║
    ║   "When RECmd fails, we dig deeper."      ║
    ╚═══════════════════════════════════════════╝
    """)
    
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

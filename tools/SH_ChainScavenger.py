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
        "interactive", "remote desktop users", "administrators",
        "backup operators", "power users", "replicator", "iis_iusrs"
    ]
    
    # Context carving size (±2048 bytes = 4KB total)
    CARVE_SIZE = 2048
    
    # Minimum username length
    MIN_USERNAME_LEN = 3
    
    def __init__(self, raw_dir):
        """
        Initialize Chain Scavenger.
        
        Args:
            raw_dir: Path to raw artifacts directory (containing SAM hive)
        """
        self.raw_dir = Path(raw_dir) if raw_dir else None
        self.sam_files = []
        self.log_files = []
        self.results = []
        
        if self.raw_dir:
            self._discover_hive_files()
    
    def _discover_hive_files(self):
        """Discover SAM hive and LOG files in raw directory."""
        if not self.raw_dir or not self.raw_dir.exists():
            return
        
        # Search for SAM files (case-insensitive)
        for f in self.raw_dir.rglob("*"):
            if f.is_file():
                name_lower = f.name.lower()
                if name_lower == "sam":
                    self.sam_files.append(f)
                elif name_lower.startswith("sam.log"):
                    self.log_files.append(f)
    
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
                
                candidates.append(decoded)
                
            except Exception:
                continue
        
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for c in candidates:
            c_lower = c.lower()
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
                    
                    for username in usernames:
                        # Create result entry
                        self.results.append({
                            "Timestamp": datetime.now().isoformat(),
                            "Username": username,
                            "Source": f"SCAVENGE:{hive_file.name}",
                            "Offset": hex(offset),
                            "Context_Range": f"{hex(start)}-{hex(end)}",
                            "Entry_Location": f"SAM_SCAVENGE: {hive_file.name}",
                            "AION_Score": 400,
                            "AION_Tags": "SAM_SCAVENGE, NEW_USER_CREATED, DIRTY_HIVE",
                            "Threat_Score": 400,
                            "Threat_Tag": "NEW_USER_CREATED,PRIVILEGE_ESCALATION"
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

"""
SH_YaraScanner v1.0 [WebShell Hunter]
Mission: Dual-mode YARA scanning for live files and ghost entries
Activation: --enable-yara-webshell flag (optional, off by default)

Features:
- Live Scan: Actual files in htdocs, wwwroot, inetpub
- Ghost Scan: Entries from Ghost_Report.csv (deleted files)
- Built-in WebShell signatures (China Chopper, b374k, c99, r57, WSO)
- Score escalation: YARA hit → Score = 300, Tag = WebShell_Detected
"""

import os
import glob
import re
import polars as pl
from pathlib import Path

# ============================================================
#  Built-in WebShell Signatures (No external YARA dependency)
#  These patterns are derived from common WebShell characteristics
# ============================================================

WEBSHELL_SIGNATURES = {
    "china_chopper": {
        "name": "China Chopper WebShell",
        "patterns": [
            rb"<%eval\s*request",
            rb"<%execute\s*request",
            rb"eval\(Request\.",
            rb"execute\(Request\.",
            rb"<%@\s*Page\s+Language\s*=\s*[\"']?Jscript",
            rb"Response\.Write\(eval",
        ],
        "extensions": [".asp", ".aspx", ".php", ".jsp"],
        "severity": "CRITICAL",
        "score": 300
    },
    "b374k": {
        "name": "b374k WebShell",
        "patterns": [
            rb"b374k",
            rb"shell_exec\s*\(",
            rb"passthru\s*\(",
            rb"system\s*\(\$_(GET|POST|REQUEST)",
            rb"\$_FILES\[.+\]\[.?tmp_name.?\]",
        ],
        "extensions": [".php"],
        "severity": "CRITICAL",
        "score": 300
    },
    "c99_r57": {
        "name": "C99/R57 WebShell",
        "patterns": [
            rb"c99shell",
            rb"r57shell",
            rb"phpinfo\s*\(\s*\)",
            rb"safe_mode_exec_dir",
            rb"ini_restore\s*\(",
            rb"dl\s*\(\s*['\"]",
        ],
        "extensions": [".php"],
        "severity": "CRITICAL",
        "score": 300
    },
    "wso": {
        "name": "WSO WebShell",
        "patterns": [
            rb"WSO\s+\d+",
            rb"FilesMan",
            rb"<\?php\s*\$[a-z]=",
            rb"preg_replace\s*\(.*/e",
            rb"assert\s*\(\s*\$_(GET|POST|REQUEST)",
        ],
        "extensions": [".php"],
        "severity": "CRITICAL",
        "score": 300
    },
    "generic_php_shell": {
        "name": "Generic PHP WebShell",
        "patterns": [
            rb"eval\s*\(\s*base64_decode",
            rb"eval\s*\(\s*gzinflate",
            rb"eval\s*\(\s*gzuncompress",
            rb"assert\s*\(\s*base64_decode",
            rb"create_function\s*\(\s*['\"]",
            rb"call_user_func\s*\(\s*\$",
            rb"preg_replace\s*\(.*/e",
        ],
        "extensions": [".php"],
        "severity": "HIGH",
        "score": 250
    },
    "generic_asp_shell": {
        "name": "Generic ASP WebShell",
        "patterns": [
            rb"Execute\s*\(\s*Request",
            rb"Eval\s*\(\s*Request",
            rb"CreateObject\s*\(\s*[\"']WScript\.Shell",
            rb"CreateObject\s*\(\s*[\"']Scripting\.FileSystemObject",
            rb"adodb\.stream",
        ],
        "extensions": [".asp", ".aspx"],
        "severity": "HIGH",
        "score": 250
    },
    "generic_jsp_shell": {
        "name": "Generic JSP WebShell",
        "patterns": [
            rb"Runtime\.getRuntime\(\)\.exec",
            rb"ProcessBuilder",
            rb"<%\s*out\.print\s*\(\s*Runtime",
        ],
        "extensions": [".jsp", ".jspx"],
        "severity": "HIGH",
        "score": 250
    }
}

# Common web root directories to scan
WEB_ROOTS = [
    "htdocs", "wwwroot", "inetpub", "www", "public_html", 
    "web", "webapps", "webapp", "html", "sites"
]

WEB_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".jspx", ".cfm", ".cgi", ".pl"]


class YaraScanner:
    def __init__(self, kape_raw_dir=None, ghost_csv=None):
        """
        Initialize YARA-like scanner for WebShell detection.
        Args:
            kape_raw_dir: Path to KAPE raw output (for live file scanning)
            ghost_csv: Path to Ghost_Report.csv (for deleted file scanning)
        """
        self.kape_raw_dir = Path(kape_raw_dir) if kape_raw_dir else None
        self.ghost_csv = ghost_csv
        self.results = []
        
    def scan_live_files(self):
        """Scan actual files in web root directories for WebShell patterns."""
        print("[*] YARA Scanner: Scanning live web files...")
        
        if not self.kape_raw_dir or not self.kape_raw_dir.exists():
            print("    [*] No raw directory specified or found. Skipping live scan.")
            return []
        
        hits = []
        files_scanned = 0
        
        # Find web root directories
        for web_root in WEB_ROOTS:
            for root_path in self.kape_raw_dir.rglob(f"*{web_root}*"):
                if root_path.is_dir():
                    for ext in WEB_EXTENSIONS:
                        for file_path in root_path.rglob(f"*{ext}"):
                            if file_path.is_file():
                                result = self._scan_file(file_path)
                                if result:
                                    hits.append(result)
                                files_scanned += 1
        
        print(f"    [+] Live scan complete: {files_scanned} files scanned, {len(hits)} hits")
        return hits
    
    def scan_ghost_entries(self):
        """Scan Ghost_Report.csv entries for WebShell indicators in filenames/paths."""
        print("[*] YARA Scanner: Analyzing ghost (deleted) file entries...")
        
        if not self.ghost_csv or not os.path.exists(self.ghost_csv):
            print("    [*] No Ghost_Report.csv found. Skipping ghost scan.")
            return []
        
        hits = []
        
        try:
            df = pl.read_csv(self.ghost_csv, ignore_errors=True, infer_schema_length=0)
            
            # Identify filename/path columns
            schema = df.columns
            name_col = next((c for c in ["Ghost_FileName", "FileName", "Name", "File"] if c in schema), None)
            path_col = next((c for c in ["ParentPath", "Path", "FullPath", "Directory"] if c in schema), None)
            
            if not name_col:
                print("    [!] Cannot identify filename column in Ghost_Report.")
                return []
            
            for row in df.iter_rows(named=True):
                filename = str(row.get(name_col, "")).lower()
                filepath = str(row.get(path_col, "")).lower()
                
                # Check for suspicious web file extensions in non-web locations
                for ext in WEB_EXTENSIONS:
                    if filename.endswith(ext):
                        # Check for WebShell-like filenames
                        webshell_names = [
                            "shell", "cmd", "backdoor", "c99", "r57", "wso", "b374k",
                            "phpspy", "pwn", "hack", "root", "admin_", "0day",
                            "exploit", "payload", "upload", "exec"
                        ]
                        
                        for ws_name in webshell_names:
                            if ws_name in filename:
                                hits.append({
                                    "Type": "GHOST_WEBSHELL_INDICATOR",
                                    "FileName": row.get(name_col, ""),
                                    "Path": row.get(path_col, ""),
                                    "Signature": f"Suspicious filename pattern: {ws_name}",
                                    "Severity": "CRITICAL",
                                    "Score": 300,
                                    "Tag": "WebShell_Detected"
                                })
                                break
                        
                        # Check for web files in unusual locations
                        suspicious_paths = ["temp", "tmp", "upload", "uploads", "cache", "logs"]
                        for sus_path in suspicious_paths:
                            if sus_path in filepath and ext in [".php", ".asp", ".aspx", ".jsp"]:
                                hits.append({
                                    "Type": "GHOST_SUSPICIOUS_WEBFILE",
                                    "FileName": row.get(name_col, ""),
                                    "Path": row.get(path_col, ""),
                                    "Signature": f"Web script in suspicious location: {sus_path}",
                                    "Severity": "HIGH",
                                    "Score": 250,
                                    "Tag": "WebShell_Suspected"
                                })
                                break
            
            print(f"    [+] Ghost scan complete: {df.height} entries analyzed, {len(hits)} hits")
            
        except Exception as e:
            print(f"    [!] Ghost scan error: {e}")
        
        return hits
    
    def _scan_file(self, file_path):
        """Scan a single file for WebShell patterns."""
        try:
            ext = file_path.suffix.lower()
            
            # Read file content
            with open(file_path, "rb") as f:
                content = f.read(512 * 1024)  # Read first 512KB only
            
            # Check against all signatures
            for sig_id, sig_data in WEBSHELL_SIGNATURES.items():
                if ext in sig_data["extensions"]:
                    for pattern in sig_data["patterns"]:
                        if re.search(pattern, content, re.IGNORECASE):
                            return {
                                "Type": "LIVE_WEBSHELL_DETECTED",
                                "FileName": file_path.name,
                                "Path": str(file_path),
                                "Signature": sig_data["name"],
                                "Severity": sig_data["severity"],
                                "Score": sig_data["score"],
                                "Tag": "WebShell_Detected"
                            }
            
        except Exception as e:
            pass  # Skip files that can't be read
        
        return None
    
    def run_full_scan(self):
        """Run both live and ghost scans, returning combined results."""
        print("\n" + "="*60)
        print("  SH_YaraScanner v1.0 [WebShell Hunter]")
        print("="*60)
        
        all_hits = []
        
        # Live file scan
        live_hits = self.scan_live_files()
        all_hits.extend(live_hits)
        
        # Ghost entry scan
        ghost_hits = self.scan_ghost_entries()
        all_hits.extend(ghost_hits)
        
        if all_hits:
            print(f"\n[!] TOTAL WEBSHELL INDICATORS: {len(all_hits)}")
            return pl.DataFrame(all_hits)
        
        print("\n[*] No WebShell indicators detected.")
        return None


def main(argv=None):
    import argparse
    
    parser = argparse.ArgumentParser(description="YARA-like WebShell Scanner")
    parser.add_argument("--raw", help="KAPE Raw Directory (for live file scan)")
    parser.add_argument("--ghost", help="Ghost_Report.csv path (for deleted file scan)")
    parser.add_argument("-o", "--out", default="yara_webshell_results.csv", help="Output CSV path")
    
    args = parser.parse_args(argv)
    
    scanner = YaraScanner(args.raw, args.ghost)
    results = scanner.run_full_scan()
    
    if results is not None and results.height > 0:
        results.write_csv(args.out)
        print(f"[*] Results saved to: {args.out}")


if __name__ == "__main__":
    main()

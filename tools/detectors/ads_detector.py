# tools/detectors/ads_detector.py
# ===========================================================
#  ADSDetector v1.2 [ADS Hunter - Zero False Negative]
#  Mission: Detect malicious NTFS Alternate Data Streams
#  Targets: MFT ($MFT) and USN Journal ($J) from KAPE output
#  
#  Detection Logic:
#    A. Masquerade ADS (txt:exe hiding)
#    B. Reserved Device Names (LPT1, CON, NUL abuse)
#    C. USN Stream Injection (StreamChange on text files)
# ===========================================================
import polars as pl
import re
from tools.detectors.base_detector import BaseDetector


class ADSDetector(BaseDetector):
    """
    Detects NTFS Alternate Data Streams (ADS) attacks:
    - Masquerade: Executable hidden in text/image files
    - Reserved Device Names: LPT1, CON, NUL abuse
    - USN Stream Injection: StreamChange on non-executable files
    
    Noise Reduction:
    - Zone.Identifier (download markers)
    - Cloud sync metadata (Dropbox, OneDrive)
    - System/browser legitimate ADS
    - WSL/Docker metadata
    """
    
    # ===========================================
    # Whitelist: Legitimate ADS stream names
    # ===========================================
    IGNORE_STREAM_SUFFIXES = [
        ":Zone.Identifier",      # Download marker (skip for hiding detection)
        ":favicon",              # Browser favorites
        ":SmartScreen",          # Windows security
        ":com.dropbox.attributes",  # Dropbox sync
        ":com.apple.quarantine", # Mac interop
        ":ms-properties",        # OneDrive
        ":$DATA",                # Default data stream
        ":OECustomProperty",     # Outlook Express legacy
        ":encryptable",          # Encryption attribute
        ":AFP_AfpInfo",          # Apple Filing Protocol
        ":AFP_Resource",         # Apple resource fork
    ]
    
    # ===========================================
    # Whitelist: Path patterns to ignore (NOISE)
    # ===========================================
    # WSL, Docker, Git, Thumbnails
    NOISE_PATH_PATTERN = r"(?i)(\\lxss\\|\\wsl\\|\\ubuntu\\|\\docker\\|thumbs\.db|\\.git\\)"
    
    # ===========================================
    # Whitelist: System paths (low priority ADS)
    # These are legitimate system ADS, not attack indicators
    # ===========================================
    SYSTEM_PATH_PATTERN = r"(?i)(\\Windows\\|\\Program Files\\|\\Program Files \(x86\)\\|\\ProgramData\\)"
    
    # ===========================================
    # Whitelist: Known legitimate ADS producers
    # ===========================================
    LEGITIMATE_ADS_PATHS = [
        r"(?i)Windows Defender",     # Defender signatures
        r"(?i)Microsoft\\OneDrive",  # OneDrive sync
        r"(?i)Microsoft\\Edge",      # Edge browser
        r"(?i)Google\\Chrome",       # Chrome browser
        r"(?i)Mozilla\\Firefox",     # Firefox browser
        r"(?i)\\AppData\\Local\\Temp\\",  # Temp files
    ]
    
    # ===========================================
    # Detection: Safe parent extensions
    # ===========================================
    SAFE_PARENT_EXTENSIONS = [
        "txt", "log", "ini", "cfg", "md", "json", "xml", "csv", "rtf",
        "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "jpg", "jpeg", "png", "bmp", "gif", "ico",
        "html", "htm", "css"
    ]
    
    # ===========================================
    # Detection: Dangerous child extensions
    # ===========================================
    EXEC_CHILD_EXTENSIONS = [
        "exe", "dll", "ps1", "vbs", "js", "bat", "cmd",
        "scr", "pif", "com", "msi", "hta", "wsf", "jse", "vbe"
    ]
    
    # ===========================================
    # Detection: Reserved device names
    # ===========================================
    RESERVED_DEVICE_PATTERN = r"(?i)^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\.[^:]*)?(:.*)?$"
    
    def __init__(self, config: dict):
        super().__init__(config)
        # Build pattern strings for Polars (no pre-compile needed)
        safe_ext = "|".join(self.SAFE_PARENT_EXTENSIONS)
        exec_ext = "|".join(self.EXEC_CHILD_EXTENSIONS)
        self._has_exec_child_pattern = rf"(?i):.*\.({exec_ext})$"
        self._safe_parent_re = rf"(?i)^[^:]+\.({safe_ext}):"
    
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        print("    -> [Detector] Running ADSDetector v1.0 (ADS Hunter with Noise Reduction)...")
        cols = df.columns
        
        # Require FileName column for ADS detection
        if "FileName" not in cols:
            print("       [!] FileName column not found, skipping ADS detection")
            return df
        
        # ===========================================
        # 🚫 STEP 0: Noise Reduction (The Filter)
        # ===========================================
        
        # Build noise stream pattern for Polars
        noise_stream_regex = r"(?i)(" + "|".join([re.escape(s).replace("\\:", ":") for s in self.IGNORE_STREAM_SUFFIXES]) + r")$"
        
        # Check if file is a legitimate ADS (Zone.Identifier, etc.)
        is_noise_stream = pl.col("FileName").str.contains(noise_stream_regex)
        
        # Check if path is in noise locations (WSL, Docker, .git)
        is_noise_path = pl.lit(False)
        is_system_path = pl.lit(False)
        is_legit_app = pl.lit(False)
        
        if "ParentPath" in cols:
            is_noise_path = pl.col("ParentPath").str.contains(self.NOISE_PATH_PATTERN)
            
            # System paths: Windows, Program Files, ProgramData
            is_system_path = pl.col("ParentPath").str.contains(self.SYSTEM_PATH_PATTERN)
            
            # Legitimate ADS producers: Defender, OneDrive, Browsers
            legit_path_regex = "|".join(self.LEGITIMATE_ADS_PATHS)
            is_legit_app = pl.col("ParentPath").str.contains(legit_path_regex)
        
        # Combined noise filter (FULL - for general ADS)
        is_noise_full = is_noise_stream | is_noise_path | is_system_path | is_legit_app
        
        # LIGHT noise filter (for Masquerade - DO NOT exclude system paths!)
        # Masquerade (txt:exe) is ALWAYS malicious, even in system folders
        is_noise_light = is_noise_stream | is_noise_path
        
        # ===========================================
        # 🐺 STEP 1: Logic A - Masquerade Detection
        # (Safe Parent + Executable Child hidden in ADS)
        # CRITICAL: Uses LIGHT noise filter to catch system path attacks!
        # ===========================================
        
        # Check if filename contains colon (indicates ADS)
        has_colon = pl.col("FileName").str.contains(":")
        
        # Check for masquerade pattern: safe_ext:exec_ext
        # e.g., welcome.txt:putty.exe, C:\ProgramData\..\log.txt:malware.exe
        is_masquerade = (
            has_colon & 
            (~is_noise_light) &  # LIGHT filter: still detects system path attacks!
            pl.col("FileName").str.contains(self._safe_parent_re) &
            pl.col("FileName").str.contains(self._has_exec_child_pattern)
        )
        
        # ===========================================
        # 👻 STEP 2: Logic B - Reserved Device Names
        # (LPT1.txt, CON.exe, NUL, etc.)
        # ===========================================
        
        # Extract base filename (before colon if exists)
        # Reserved names are suspicious even without ADS
        is_reserved = pl.col("FileName").str.contains(self.RESERVED_DEVICE_PATTERN)
        
        # ===========================================
        # 📜 STEP 3: Logic C - USN Stream Injection
        # (StreamChange/NamedDataExtend on text files)
        # ===========================================
        
        is_suspicious_write = pl.lit(False)
        
        # Check columns that might contain USN update reasons
        usn_reason_cols = [c for c in ["UpdateReasons", "Action", "Reason"] if c in cols]
        
        if usn_reason_cols:
            # USN reasons indicating stream modification
            stream_change_pattern = r"(?i)(StreamChange|NamedDataExtend|NamedDataOverwrite)"
            
            # Check any reason column for stream changes
            reason_check = pl.any_horizontal([
                pl.col(c).str.contains(stream_change_pattern) for c in usn_reason_cols
            ])
            
            # Parent file is a text/document type (potential hiding target)
            text_ext_pattern = r"(?i)\.(txt|log|ini|cfg|md|json|xml|csv|rtf|doc|docx)$"
            parent_is_text = pl.col("FileName").str.contains(text_ext_pattern)
            
            # Suspicious: Stream change on text file, not noise
            # Use FULL noise filter for USN (system paths = noise for streaming)
            is_suspicious_write = reason_check & parent_is_text & (~is_noise_full)
        
        # ===========================================
        # 🎯 STEP 4: Scoring & Tagging
        # ===========================================
        
        df = df.with_columns([
            # Threat Score
            pl.when(is_masquerade | is_reserved)
              .then(300)  # Critical: Hidden executable or device name abuse
              .when(is_suspicious_write)
              .then(200)  # High: Suspicious stream write
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score"),
            
            # Tags
            pl.when(is_masquerade)
              .then(pl.format("{},CRITICAL_ADS_MASQUERADE", pl.col("Tag")))
              .when(is_reserved)
              .then(pl.format("{},CRITICAL_RESERVED_DEVICE", pl.col("Tag")))
              .when(is_suspicious_write)
              .then(pl.format("{},SUSPICIOUS_ADS_WRITE", pl.col("Tag")))
              .otherwise(pl.col("Tag"))
              .alias("Tag")
        ])
        
        # Log detection summary
        masq_count = df.filter(pl.col("Tag").str.contains("ADS_MASQUERADE")).height
        rsvd_count = df.filter(pl.col("Tag").str.contains("RESERVED_DEVICE")).height
        write_count = df.filter(pl.col("Tag").str.contains("ADS_WRITE")).height
        
        if masq_count + rsvd_count + write_count > 0:
            print(f"       >> [!] ADS Threats Found: Masquerade={masq_count}, Reserved={rsvd_count}, StreamWrite={write_count}")
        
        # 🚀 Universal Signatures (Engine v5.4)
        df = self.apply_threat_signatures(df)
        
        return df

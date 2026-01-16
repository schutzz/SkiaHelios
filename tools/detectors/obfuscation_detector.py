# tools/detectors/obfuscation_detector.py
# ===========================================================
#  ObfuscationDetector v2.0 [Sphinx's Soul + Deobfuscation Engine]
#  Mission: Detect encoded commands, script seeds, high-entropy strings,
#           and advanced obfuscation techniques (XOR, reversal, normalization)
#  Origin: Migrated from SH_SphinxDeciphering.py
# ===========================================================
import polars as pl
import re
import base64
import math
from tools.detectors.base_detector import BaseDetector

# --- Regex Definitions (from Sphinx) ---
RE_B64_CMD = re.compile(
    r"[-eE](?:ncodedCommand)?\s+([A-Za-z0-9+/=]{20,})",
    re.IGNORECASE
)

RE_SEED_PATH = re.compile(
    r"(?i)(?:^|[\s\"'>/\\])([a-zA-Z]:\\[^\"'>\s]*\.(?:bat|ps1|vbs|js|hta|jse|wsf|sh|py|exe)|([\w\-\.]+\.(?:bat|ps1|vbs|js|hta|jse|wsf|sh|py|exe)))(?:[\s\"'<]|$)"
)


class ObfuscationDetector(BaseDetector):
    """
    Detects obfuscated commands including:
    - Base64 encoded PowerShell commands
    - Script file references (.bat, .ps1, .vbs, etc.)
    - High entropy strings
    - Attack signature keywords
    - Normalized obfuscation (Tick/Caret removal, string concatenation)
    - Reversed strings
    - XOR encrypted payloads
    """
    
    ATTACK_KEYWORDS = [
        "powershell", "bypass", "-enc", "http", "curl", "wget",
        "invoke-expression", "iex", "downloadstring", "hidden",
        "noprofile", "executionpolicy", "frombase64string"
    ]
    
    REVERSED_KEYWORDS = [
        "lehsrewop",  # powershell
        "dmcexe",      # execmd
        "gnirtsdaolnwod",  # downloadstring
        "ssecorpetaerc",   # createprocess
        "noisserpxe-ekovi"  # invoke-expression
    ]
    
    # XOR Known plaintext keywords
    XOR_KNOWN_KEYWORDS = [
        b"http", b"https", b"powershell", b"cmd.exe", 
        b"CreateObject", b"Invoke-Expression", b"wscript",
        b"This program", b"MZ",  # PE Header
        b"wget", b"curl", b"downloadstring"
    ]
    
    # Environment variable expansion map
    ENV_VAR_MAP = {
        '%comspec%': 'cmd.exe',
        '%appdata%': 'AppData\\Roaming',
        '%temp%': 'Temp',
        '%tmp%': 'Temp',
        '%systemroot%': 'C:\\Windows',
        '%windir%': 'C:\\Windows',
        '%programfiles%': 'C:\\Program Files'
    }
    
    def __init__(self, config: dict):
        super().__init__(config)
        # Pre-compile patterns for performance
        self._attack_pattern = re.compile(
            "(?i)(" + "|".join([re.escape(k) for k in self.ATTACK_KEYWORDS]) + ")"
        )
        self._reversed_pattern = re.compile(
            "(?i)(" + "|".join([re.escape(k) for k in self.REVERSED_KEYWORDS]) + ")"
        )
    
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        print("    -> [Detector] Running ObfuscationDetector v2.0 (Sphinx's Soul + Deobfuscation)...")
        cols = df.columns
        
        # Identify text columns to analyze
        text_cols = [c for c in ["CommandLine", "Message", "ScriptBlockText", 
                                  "Payload", "EventData", "ContextInfo", "Properties"] 
                     if c in cols]
        
        if not text_cols:
            return df
        
        # Create a combined text column for analysis
        df = df.with_columns(
            pl.concat_str(
                [pl.col(c).fill_null("") for c in text_cols],
                separator=" | "
            ).alias("_obf_combined_text")
        )
        
        # --- STEP 1: Base64 Detection (Vectorized Pre-check) ---
        # [OPTIMIZATION] Only map if looks like Base64 (>20 chars of b64 set)
        looks_like_b64 = pl.col("_obf_combined_text").str.contains(r"[A-Za-z0-9+/=]{20,}")
        
        df = df.with_columns(
            pl.when(looks_like_b64)
            .then(
                pl.col("_obf_combined_text").map_elements(
                    self._detect_base64,
                    return_dtype=pl.Struct([
                        pl.Field("score", pl.Int64),
                        pl.Field("tag", pl.Utf8),
                        pl.Field("decoded", pl.Utf8)
                    ])
                )
            )
            .otherwise(
                pl.struct([
                    pl.lit(0, dtype=pl.Int64).alias("score"), 
                    pl.lit("", dtype=pl.Utf8).alias("tag"), 
                    pl.lit("", dtype=pl.Utf8).alias("decoded")
                ])
            )
            .alias("_b64_result")
        )
        
        df = df.with_columns([
            (pl.col("Threat_Score") + pl.col("_b64_result").struct.field("score")).alias("Threat_Score"),
            pl.when(pl.col("_b64_result").struct.field("tag") != "")
              .then(pl.format("{},{}", pl.col("Tag"), pl.col("_b64_result").struct.field("tag")))
              .otherwise(pl.col("Tag"))
              .alias("Tag")
        ])
        
        # --- STEP 2: Script Seed Detection (Vectorized Pre-check) ---
        # Only run if contains extensions
        looks_like_script = pl.col("_obf_combined_text").str.to_lowercase().str.contains(r"\.(bat|ps1|vbs|js|hta|jse|wsf|sh|py|exe)")
        
        df = df.with_columns(
            pl.when(looks_like_script)
            .then(
                pl.col("_obf_combined_text").map_elements(
                    self._detect_script_seeds,
                    return_dtype=pl.Struct([
                        pl.Field("score", pl.Int64),
                        pl.Field("tag", pl.Utf8),
                        pl.Field("seeds", pl.Utf8)
                    ])
                )
            )
            .otherwise(
                pl.struct([
                   pl.lit(0, dtype=pl.Int64).alias("score"), 
                   pl.lit("", dtype=pl.Utf8).alias("tag"), 
                   pl.lit("", dtype=pl.Utf8).alias("seeds")
                ])
            )
            .alias("_seed_result")
        )
        
        df = df.with_columns([
            (pl.col("Threat_Score") + pl.col("_seed_result").struct.field("score")).alias("Threat_Score"),
            pl.when(pl.col("_seed_result").struct.field("tag") != "")
              .then(pl.format("{},{}", pl.col("Tag"), pl.col("_seed_result").struct.field("tag")))
              .otherwise(pl.col("Tag"))
              .alias("Tag")
        ])
        
        # --- STEP 3: Entropy Detection (Length Gated) ---
        # [OPTIMIZATION] Only calc entropy on strings > 50 chars
        is_long_enough = pl.col("_obf_combined_text").str.len_bytes() > 50
        
        df = df.with_columns(
            pl.when(is_long_enough)
            .then(
                pl.col("_obf_combined_text").map_elements(
                    self._check_entropy,
                    return_dtype=pl.Struct([
                        pl.Field("score", pl.Int64),
                        pl.Field("tag", pl.Utf8)
                    ])
                )
            )
            .otherwise(
                 pl.struct([
                    pl.lit(0, dtype=pl.Int64).alias("score"), 
                    pl.lit("", dtype=pl.Utf8).alias("tag")
                ])
            )
            .alias("_entropy_result")
        )
        
        df = df.with_columns([
            (pl.col("Threat_Score") + pl.col("_entropy_result").struct.field("score")).alias("Threat_Score"),
            pl.when(pl.col("_entropy_result").struct.field("tag") != "")
              .then(pl.format("{},{}", pl.col("Tag"), pl.col("_entropy_result").struct.field("tag")))
              .otherwise(pl.col("Tag"))
              .alias("Tag")
        ])
        
        # --- STEP 4: Attack Keyword Detection (Vectorized) ---
        has_attack_keyword = pl.col("_obf_combined_text").str.contains(self._attack_pattern.pattern)
        
        df = df.with_columns([
            pl.when(has_attack_keyword)
              .then(pl.col("Threat_Score") + 50)
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score"),
            pl.when(has_attack_keyword)
              .then(pl.format("{},ATTACK_SIG", pl.col("Tag")))
              .otherwise(pl.col("Tag"))
              .alias("Tag")
        ])
        
        # --- STEP 5: Normalization + Re-scan [NEW] ---
        # [OPTIMIZATION] Only normalize if contains obfuscation chars (^, `) or concatenation (+)
        needs_normalization = pl.col("_obf_combined_text").str.contains(r"[\^`+]")
        
        df = df.with_columns(
            pl.when(needs_normalization)
            .then(
                pl.col("_obf_combined_text").map_elements(
                    self._check_normalization,
                    return_dtype=pl.Struct([
                        pl.Field("score", pl.Int64),
                        pl.Field("tag", pl.Utf8)
                    ])
                )
            )
            .otherwise(
                pl.struct([
                    pl.lit(0, dtype=pl.Int64).alias("score"), 
                    pl.lit("", dtype=pl.Utf8).alias("tag")
                ])
            )
            .alias("_norm_result")
        )
        
        df = df.with_columns([
            (pl.col("Threat_Score") + pl.col("_norm_result").struct.field("score")).alias("Threat_Score"),
            pl.when(pl.col("_norm_result").struct.field("tag") != "")
              .then(pl.format("{},{}", pl.col("Tag"), pl.col("_norm_result").struct.field("tag")))
              .otherwise(pl.col("Tag"))
              .alias("Tag")
        ])
        
        # --- STEP 6: Reversed String Detection [NEW] ---
        has_reversed = pl.col("_obf_combined_text").str.contains(self._reversed_pattern.pattern)
        
        df = df.with_columns([
            pl.when(has_reversed)
              .then(pl.col("Threat_Score") + 80)
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score"),
            pl.when(has_reversed)
              .then(pl.format("{},REVERSED_CMD", pl.col("Tag")))
              .otherwise(pl.col("Tag"))
              .alias("Tag")
        ])
        
        # --- STEP 7: XOR Brute Force [NEW] (High Entropy Only) ---
        df = df.with_columns(
            pl.when(pl.col("_entropy_result").struct.field("score") >= 40)
              .then(
                  pl.col("_obf_combined_text").map_elements(
                      self._xor_brute_force,
                      return_dtype=pl.Struct([
                          pl.Field("score", pl.Int64),
                          pl.Field("tag", pl.Utf8),
                          pl.Field("decoded", pl.Utf8)
                      ])
                  )
              )
              .otherwise(pl.struct([
                  pl.lit(0).alias("score"),
                  pl.lit("").alias("tag"),
                  pl.lit("").alias("decoded")
              ]))
              .alias("_xor_result")
        )
        
        df = df.with_columns([
            (pl.col("Threat_Score") + pl.col("_xor_result").struct.field("score")).alias("Threat_Score"),
            pl.when(pl.col("_xor_result").struct.field("tag") != "")
              .then(pl.format("{},{}", pl.col("Tag"), pl.col("_xor_result").struct.field("tag")))
              .otherwise(pl.col("Tag"))
              .alias("Tag")
        ])
        
        # Cleanup temporary columns
        df = df.drop(["_obf_combined_text", "_b64_result", "_seed_result", 
                      "_entropy_result", "_norm_result", "_xor_result"])
        
        # 🚀 Universal Signatures
        df = self.apply_threat_signatures(df)
        
        return df
    
    @staticmethod
    def _entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if len(s) < 15:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = float(len(s))
        return -sum((count / length) * math.log(count / length, 2) for count in freq.values())
    
    def _detect_base64(self, text: str) -> dict:
        """Detect and decode Base64 encoded commands."""
        if not text or len(text) < 20:
            return {"score": 0, "tag": "", "decoded": ""}
        
        match = RE_B64_CMD.search(text)
        if not match:
            return {"score": 0, "tag": "", "decoded": ""}
        
        try:
            raw_b64 = match.group(1)
            decoded_bytes = base64.b64decode(raw_b64)
            decoded_str = ""
            
            # Try UTF-16-LE first (common for PowerShell), then UTF-8
            try:
                decoded_str = decoded_bytes.decode('utf-16-le')
            except:
                try:
                    decoded_str = decoded_bytes.decode('utf-8')
                except:
                    pass
            
            if decoded_str and len(decoded_str) > 5:
                return {"score": 100, "tag": "DECODED_B64", "decoded": decoded_str[:200]}
        except:
            pass
        
        return {"score": 0, "tag": "", "decoded": ""}
    
    def _detect_script_seeds(self, text: str) -> dict:
        """Detect script file references."""
        if not text or len(text) < 10:
            return {"score": 0, "tag": "", "seeds": ""}
        
        matches = RE_SEED_PATH.findall(text)
        if not matches:
            return {"score": 0, "tag": "", "seeds": ""}
        
        candidates = []
        for m in matches:
            if m[0]:
                candidates.append(m[0])
            elif m[1]:
                candidates.append(m[1])
        
        if candidates:
            clean_seeds = list(set([s.strip("'\"") for s in candidates if len(s) > 4]))
            if clean_seeds:
                return {"score": 70, "tag": "CONTAINER_SEED", "seeds": ";".join(clean_seeds)}
        
        return {"score": 0, "tag": "", "seeds": ""}
    
    def _check_entropy(self, text: str) -> dict:
        """Check for high entropy strings."""
        if not text or len(text) < 20:
            return {"score": 0, "tag": ""}
        
        # Check entropy on first 500 chars to avoid slow processing
        sample = text[:500]
        entropy = self._entropy(sample)
        
        if entropy > 5.5:
            return {"score": 40, "tag": "HIGH_ENTROPY"}
        
        return {"score": 0, "tag": ""}
    
    # ============================================================
    # v2.0 NEW METHODS: Normalization, Reversal, XOR Detection
    # ============================================================
    
    def _normalize_command(self, cmd: str) -> str:
        """
        Normalize obfuscated commands by:
        1. Removing Caret (^) and Backtick (`) characters
        2. Resolving string concatenation ("str"+"ing" -> string)
        3. Expanding environment variables (%ComSpec% -> cmd.exe)
        """
        if not cmd or len(cmd) < 5:
            return cmd
        
        # 1. Remove obfuscation characters
        normalized = re.sub(r'[\^`]', '', cmd)
        
        # 2. Resolve string concatenation (simple cases)
        # "str"+"ing" or 'str'+'ing' -> string
        normalized = re.sub(r'["\']\s*\+\s*["\']', '', normalized)
        
        # 3. Expand common environment variables
        normalized_lower = normalized.lower()
        for var, val in self.ENV_VAR_MAP.items():
            normalized_lower = normalized_lower.replace(var, val.lower())
        
        return normalized_lower
    
    def _check_normalization(self, text: str) -> dict:
        """
        Apply normalization and re-scan for attack keywords.
        If normalized text reveals hidden keywords, flag it.
        """
        if not text or len(text) < 10:
            return {"score": 0, "tag": ""}
        
        normalized = self._normalize_command(text)
        
        # Skip if normalization didn't change anything
        if normalized == text.lower():
            return {"score": 0, "tag": ""}
        
        # Check if normalization revealed attack keywords
        if self._attack_pattern.search(normalized):
            # Only flag if original text didn't already have the keyword
            if not self._attack_pattern.search(text.lower()):
                return {"score": 60, "tag": "DEOBFUSCATED_CMD"}
        
        return {"score": 0, "tag": ""}
    
    def _xor_brute_force(self, text: str) -> dict:
        """
        Brute-force XOR decryption using single-byte keys (0x01-0xFF).
        Only processes high-entropy strings to avoid performance issues.
        Uses known plaintext attack with predefined keywords.
        """
        if not text or len(text) < 20:
            return {"score": 0, "tag": "", "decoded": ""}
        
        # Convert to bytes (try different encodings)
        try:
            data_bytes = text.encode('latin-1')
        except:
            try:
                data_bytes = text.encode('utf-8', errors='ignore')
            except:
                return {"score": 0, "tag": "", "decoded": ""}
        
        # Limit search to first 512 bytes for performance
        if len(data_bytes) > 512:
            data_bytes = data_bytes[:512]
        
        # Try each single-byte XOR key
        for key in range(1, 256):
            try:
                # XOR decrypt
                decrypted = bytes([b ^ key for b in data_bytes])
                
                # Check for known keywords
                decrypted_lower = decrypted.lower()
                for keyword in self.XOR_KNOWN_KEYWORDS:
                    if keyword in decrypted_lower:
                        # Try to decode as readable string
                        try:
                            decoded_str = decrypted.decode('utf-8', errors='ignore')
                            # Ensure it's mostly printable
                            printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded_str) / len(decoded_str)
                            if printable_ratio > 0.6:
                                return {
                                    "score": 120,
                                    "tag": "XOR_DECODED",
                                    "decoded": f"[XOR:0x{key:02X}] {decoded_str[:150]}"
                                }
                        except:
                            pass
            except:
                continue
        
        return {"score": 0, "tag": "", "decoded": ""}

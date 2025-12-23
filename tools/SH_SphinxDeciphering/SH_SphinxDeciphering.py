import polars as pl
import argparse
import sys
import base64
import re
import math
import os

# ==========================================
#  SH_SphinxDeciphering v0.3 [Verified Final]
#  Mission: Decode the Riddle of Logs
# ==========================================

def print_logo():
    print(r"""
         ^
        / \
       /   \     (Sphinx of the Logs)
      /  O  \    "Answer my riddle, 
     /_______\    or be consumed."
    
      [ 🦁 SH_SphinxDeciphering v0.3 ]
    """)

class SphinxEngine:
    def __init__(self, file_path):
        self.file_path = file_path
        print(f"[*] Awakening Sphinx on: {file_path}")
        self.lf = self._load_data(file_path)

    def _load_data(self, path):
        try:
            if path.lower().endswith('.json'):
                print("    -> Detected JSON format")
                return pl.scan_ndjson(path, infer_schema_length=0, ignore_errors=True)
            else:
                print("    -> Detected CSV format (Scanning...)")
                return pl.scan_csv(path, infer_schema_length=0, ignore_errors=True, encoding='utf8-lossy')
        except Exception as e:
            print(f"[!] Error loading file: {e}")
            sys.exit(1)

    def _shannon_entropy(self, data):
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    # === Level 2 De-obfuscation Logic ===
    def _peel_obfuscation(self, text):
        """文字列操作系の難読化を解除する"""
        if not text: return text, False
        original_len = len(text)
        
        # 1. バッククォート削除 (`s`e`t -> set)
        text = text.replace("`", "")
        
        # 2. 文字列結合の解除 ('A'+'B' -> AB)
        text = re.sub(r"(['\"])\s*\+\s*\1", "", text)
        text = re.sub(r"(['\"])\s*\+\s*(['\"])", "", text)

        is_modified = len(text) < original_len
        return text, is_modified

    def _decode_base64(self, text):
        if not text: return None
        # Base64パターン抽出 (少し緩和)
        pattern = r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        matches = re.findall(pattern, text)
        decoded_results = []
        
        for m in matches:
            try:
                decoded = base64.b64decode(m).decode('utf-8', errors='ignore')
                if self._is_readable(decoded):
                    clean = decoded.replace('\r', '').replace('\n', ' ')[:80]
                    decoded_results.append(f"[B64]: {clean}...")
            except:
                pass
        return " | ".join(decoded_results) if decoded_results else None

    def _is_readable(self, text, threshold=0.7):
        if not text: return False
        printable = sum(1 for c in text if 32 <= ord(c) <= 126)
        return (printable / len(text)) > threshold

    def analyze(self):
        print("[*] Phase 1: Scanning for Anomalies (Polars High-Speed Scan)...")
        
        schema_cols = self.lf.collect_schema().names()
        
        eid_col = next((c for c in schema_cols if c.lower() in ['eventid', 'id']), None)
        target_col = None
        candidates = ['PayloadData1', 'ScriptBlockText', 'Message', 'Payload', 'Data']
        for c in candidates:
            if c in schema_cols:
                target_col = c
                break
        
        if not target_col or not eid_col:
            print("[!] Error: Critical columns (EventID or Script) not found.")
            return None
            
        print(f"    -> Targeting Script Column: '{target_col}'")

        # フィルタリング
        lf_target = self.lf.filter(
            pl.col(eid_col).cast(pl.Int64, strict=False).is_in([4104, 4103, 800])
        )

        # 特徴量計算
        lf_features = lf_target.select([
            pl.col("TimeCreated").alias("Time"),
            pl.col(eid_col).alias("EventID"),
            pl.col(target_col).alias("Raw_Script"),
            pl.col(target_col).str.len_bytes().alias("Length"),
            (pl.col(target_col).str.count_matches(r"[\+\-\%\^`\(\)\{\}\[\],;]")).alias("Symbol_Count"),
            # Keyword Tuning: Added -Enc, EncodedCommand
            pl.col(target_col).str.contains(r"(?i)(IEX|Invoke-Expression|FromBase64String|GzipStream|-join|::Decompress|-Enc|EncodedCommand)").alias("Has_Keyword")
        ])

        # 異常値の絞り込み (Tuned Thresholds)
        # Symbol_Count > 15 (Shorter concatenation chains)
        lf_suspicious = lf_features.filter(
            (pl.col("Length") > 1000) | 
            (pl.col("Symbol_Count") > 15) |
            (pl.col("Has_Keyword") == True)
        )

        print("[*] Phase 2: Materializing & Peeling Layers (Python Logic)...")
        try:
            df = lf_suspicious.collect()
        except Exception as e:
            print(f"[!] Polars Collection Error: {e}")
            return None
        
        if df.height == 0:
            print("[-] No suspicious script blocks found.")
            return None

        print(f"    -> Analyzing {df.height} suspicious blocks...")

        results = []
        for row in df.iter_rows(named=True):
            script = str(row["Raw_Script"]) if row["Raw_Script"] else ""
            if len(script) < 10: continue

            # === Level 2: De-obfuscation ===
            peeled_script, is_peeled = self._peel_obfuscation(script)
            
            # Entropy Check
            entropy = self._shannon_entropy(peeled_script)
            
            # Risk Scoring
            score = 0
            tags = []
            
            if entropy > 5.0: 
                score += 30
                tags.append("HIGH_ENTROPY")
            if row["Has_Keyword"]: 
                score += 50
                tags.append("DANGEROUS_KEYWORD")
            if "GzipStream" in peeled_script or "::Decompress" in peeled_script:
                score += 20
                tags.append("COMPRESSED")
            if row["Length"] > 5000:
                score += 20
                tags.append("MASSIVE_LENGTH")
            if is_peeled:
                score += 15
                tags.append("OBFUSCATION_PEELED
import polars as pl
import argparse
import sys
import os
import re
import base64
import zlib
import math

# ============================================================
#  SH_SphinxDeciphering v1.3 [Chronicle Link Edition]
#  Mission: Decode and PRESERVE Evidence Context (Timestamps)
#  Fix: Linked TimeCreated to Decoded Riddles for Hekate Storyline
# ============================================================

def print_logo():
    print(r"""
          ^
         / \
        /   \     (Sphinx of the Logs)
       /  O  \    "Answer my riddle,
      /_______\    or be consumed."

       [ 🦁 SH_SphinxDeciphering v1.3 ]
    """)

class SphinxEngine:
    def __init__(self, target_file):
        self.target_file = target_file
        self.min_entropy = 3.0 
        self.results = []

    def _calculate_entropy(self, data):
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _try_decode(self, text):
        candidates = []
        try:
            clean_text = re.sub(r'\s+', '', text)
            missing_padding = len(clean_text) % 4
            if missing_padding: clean_text += '=' * (4 - missing_padding)
            decoded_bytes = base64.b64decode(clean_text, validate=True)
            
            # UTF-16LE
            try:
                decoded_str = decoded_bytes.decode('utf-16le')
                if len(decoded_str) > 5: candidates.append(("Base64_UTF16", decoded_str))
            except: pass
            
            # UTF-8
            try:
                decoded_str = decoded_bytes.decode('utf-8')
                if len(decoded_str) > 5 and decoded_str.isprintable(): candidates.append(("Base64_UTF8", decoded_str))
            except: pass

            # Gzip
            try:
                decompressed = zlib.decompress(decoded_bytes, 16+zlib.MAX_WBITS)
                candidates.append(("Gzip_Base64", decompressed.decode('utf-8', errors='ignore')))
            except: pass
        except: pass
        return candidates

    def analyze(self):
        print(f"[*] Awakening Sphinx on: {self.target_file}")
        try:
            df = pl.read_csv(self.target_file, ignore_errors=True, infer_schema_length=0)
            cols = df.columns
            
            # 1. 証拠能力維持のための重要カラムを特定っス！
            target_col = next((c for c in cols if c in ['PayloadData1', 'ScriptBlockText', 'Message', 'Details']), None)
            time_col = next((c for c in cols if c in ['TimeCreated', 'EventTime', 'Timestamp']), None)
            eid_col = next((c for c in cols if 'Id' in c), None)
            
            if not target_col:
                print("[!] Warning: No standard script column found.")
                return None

            print(f"    -> Targeting Column: '{target_col}'")
            if time_col: print(f"    -> Preserving Timeline via: '{time_col}'")
            
            # 2. PowerShell関連イベント(4104等)にフィルタリング
            if eid_col:
                df = df.filter(pl.col(eid_col).cast(pl.Utf8).str.contains(r"4104|800|400"))

            # 3. [修正] 時刻カラムを残したままユニーク抽出を行うっス！
            # 以前のコードでは .select(target_col) で時刻を捨てていたっスね。
            select_cols = [target_col]
            if time_col: select_cols.append(time_col)
            
            suspicious_df = df.filter(
                pl.col(target_col).str.len_chars() > 20
            ).select(select_cols).unique(subset=[target_col])

            row_count = len(suspicious_df)
            print(f"[*] Phase 2: Analyzing {row_count} blocks while maintaining context...")

            results = []
            for row in suspicious_df.iter_rows(named=True):
                original_text = row[target_col]
                event_time = row.get(time_col, "N/A") # 時刻を取得！
                
                if not original_text: continue

                ent = self._calculate_entropy(original_text)
                decoded_candidates = self._try_decode(original_text)
                
                if decoded_candidates or ent > 4.0:
                    score = int(ent * 10)
                    hint = original_text[:50] + "..."
                    tags = "SUSPICIOUS"
                    
                    if decoded_candidates:
                        method, decoded_text = decoded_candidates[0]
                        if any(k in decoded_text for k in ["Sphinx", "Payload", "Invoke-", "Download"]):
                            score += 100
                            tags = "OBFUSCATED_CMD"
                        else:
                            score += 20
                            tags = f"DECODED({method})"
                        hint = f"[{method}] {decoded_text[:80]}"
                    
                    results.append({
                        "TimeCreated": event_time, # ここに時刻を戻したっス！！
                        "Sphinx_Score": score,
                        "Original_Snippet": original_text[:30],
                        "Decoded_Hint": hint,
                        "Sphinx_Tags": tags
                    })

            if not results: return None
            return pl.DataFrame(results).sort("Sphinx_Score", descending=True)

        except Exception as e:
            print(f"[!] Sphinx Critical Failure: {e}")
            return None

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-o", "--out", default="Sphinx_Decoded.csv")
    args = parser.parse_args(argv)

    engine = SphinxEngine(args.file)
    df_result = engine.analyze()

    if df_result is not None and len(df_result) > 0:
        print(f"\n[+] SPHINX SOLVED THE RIDDLE: {len(df_result)} items")
        df_result.write_csv(args.out)
    else: print("[-] No riddles solved.")

if __name__ == "__main__":
    main()
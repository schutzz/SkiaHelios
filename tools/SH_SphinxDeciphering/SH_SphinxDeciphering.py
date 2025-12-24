import polars as pl
import argparse
import sys
import os
import re
import base64
import zlib
import math

# ==========================================
#  SH_SphinxDeciphering v1.2 [Paranoid Mode]
#  Mission: Decode obfuscated scripts & logs
#  Fix: Lower entropy threshold & Force report
# ==========================================

def print_logo():
    print(r"""
          ^
         / \
        /   \     (Sphinx of the Logs)
       /  O  \    "Answer my riddle,
      /_______\    or be consumed."

       [ 🦁 SH_SphinxDeciphering v1.2 ]
    """)

class SphinxEngine:
    def __init__(self, target_file):
        self.target_file = target_file
        # 感度を最大化（閾値を下げる）
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
        # 1. Base64
        try:
            # Clean up potential whitespace or cmdline artifacts
            clean_text = re.sub(r'\s+', '', text)
            # パディング補正
            missing_padding = len(clean_text) % 4
            if missing_padding:
                clean_text += '=' * (4 - missing_padding)
                
            decoded_bytes = base64.b64decode(clean_text, validate=True)
            
            # Try UTF-16LE (PowerShell default)
            try:
                decoded_str = decoded_bytes.decode('utf-16le')
                # 意味のある文字列かチェック（英数字率が高いか）
                if len(decoded_str) > 5:
                    candidates.append(("Base64_UTF16", decoded_str))
            except: pass
            
            # Try UTF-8
            try:
                decoded_str = decoded_bytes.decode('utf-8')
                if len(decoded_str) > 5 and decoded_str.isprintable():
                     candidates.append(("Base64_UTF8", decoded_str))
            except: pass

            # Try Gzip (Compressed stream)
            try:
                decompressed = zlib.decompress(decoded_bytes, 16+zlib.MAX_WBITS)
                candidates.append(("Gzip_Base64", decompressed.decode('utf-8', errors='ignore')))
            except: pass

        except:
            pass

        return candidates

    def analyze(self):
        print(f"[*] Awakening Sphinx on: {self.target_file}")
        
        try:
            # Load CSV lazily
            df = pl.read_csv(self.target_file, ignore_errors=True, infer_schema_length=0)
            
            # Auto-detect column
            cols = df.columns
            target_col = next((c for c in cols if c in ['PayloadData1', 'ScriptBlockText', 'Message', 'Details']), None)
            
            if not target_col:
                print("[!] Warning: No standard script column found.")
                return None

            print(f"    -> Targeting Column: '{target_col}'")
            
            # Filter for PowerShell/Suspicious events
            eid_col = next((c for c in cols if 'Id' in c), None)
            if eid_col:
                # 4104: ScriptBlock, 800: Pipeline Exec, 400: Engine Lifecycle
                df = df.filter(pl.col(eid_col).cast(pl.Utf8).str.contains(r"4104|800|400"))

            # [Paranoid] 少しでも長い文字列は全部怪しむ
            suspicious_df = df.filter(
                pl.col(target_col).str.len_chars() > 20
            ).select(target_col).unique()

            row_count = len(suspicious_df)
            print(f"[*] Phase 2: Materializing & Peeling Layers...")
            print(f"    -> Analyzing {row_count} suspicious blocks (Paranoid Mode)...")

            results = []
            for row in suspicious_df.iter_rows():
                original_text = row[0]
                if not original_text: continue

                # Entropy Check
                ent = self._calculate_entropy(original_text)
                decoded_candidates = self._try_decode(original_text)
                
                # [Paranoid] デコードできたら即採用、エントロピーが高ければ採用
                if decoded_candidates or ent > 4.0:
                    score = int(ent * 10)
                    hint = original_text[:50] + "..."
                    tags = "SUSPICIOUS"
                    
                    if decoded_candidates:
                        method, decoded_text = decoded_candidates[0]
                        # デコード結果に不審なキーワードがあればスコア激増
                        if "Sphinx" in decoded_text or "Payload" in decoded_text:
                            score += 100
                            tags = "CONFIRMED_TEST_ARTIFACT"
                        elif "Invoke-" in decoded_text or "Write-Host" in decoded_text:
                            score += 50
                            tags = "OBFUSCATED_SCRIPT"
                        else:
                            score += 20
                            tags = f"DECODED({method})"

                        hint = f"[{method}] {decoded_text[:80]}"
                    
                    # 結果リストに追加
                    results.append({
                        "Sphinx_Score": score,
                        "Original_Snippet": original_text[:30],
                        "Decoded_Hint": hint,
                        "Sphinx_Tags": tags
                    })

            if not results:
                print("    [-] The Sphinx remains silent (No anomalies found).")
                return None
            
            print(f"    [+] Solved {len(results)} riddles!")
            return pl.DataFrame(results).sort("Sphinx_Score", descending=True)

        except Exception as e:
            print(f"[!] Sphinx Analysis Error: {e}")
            return None

def main():
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, help="Target Log CSV (PowerShell/Evtx)")
    parser.add_argument("-o", "--out", default="Sphinx_Decoded.csv")
    args = parser.parse_args()

    engine = SphinxEngine(args.file)
    df_result = engine.analyze()

    if df_result is not None and len(df_result) > 0:
        print(f"\n[+] SPHINX SOLVED THE RIDDLE: {len(df_result)} items")
        df_result.write_csv(args.out)
    else:
        print("[-] No riddles solved.")

if __name__ == "__main__":
    main()
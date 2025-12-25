import polars as pl
import argparse
import sys
import os
import re
import base64
import zlib
import math

# ============================================================
#  SH_SphinxDeciphering v1.4 [Context Hunter]
#  Mission: Decode and PRESERVE Evidence Context (Parent/ID)
#  Fix: Capture ProcessId/ThreadId for Parent Process Hunting
# ============================================================

def print_logo():
    print(r"""
          ^
         / \
        /   \     (Sphinx of the Logs)
       /  O  \    "Answer my riddle,
      /_______\    or be consumed."

       [ 🦁 SH_SphinxDeciphering v1.4 ]
    """)

class SphinxEngine:
    def __init__(self, target_file):
        self.target_file = target_file
        self.min_entropy = 3.0 
        self.results = []

    def _entropy(self, s):
        if len(s) < 15: return 0.0
        import math
        p, lns = {}, float(len(s))
        for c in s:
            p[c] = p.get(c, 0) + 1
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

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
            
            target_col = next((c for c in cols if c in ['PayloadData1', 'ScriptBlockText', 'Message', 'Details']), None)
            time_col = next((c for c in cols if c in ['TimeCreated', 'EventTime', 'Timestamp']), None)
            
            # [Fix] Identify Context Columns for Parent Hunting
            pid_col = next((c for c in cols if c in ['ProcessId', 'ExecutionProcessID']), None)
            tid_col = next((c for c in cols if c in ['ThreadId', 'ExecutionThreadID']), None)
            pname_col = next((c for c in cols if c in ['ProviderName', 'Channel']), None)

            if not target_col:
                print("[!] Warning: No standard script column found.")
                return None

            print(f"    -> Targeting Column: '{target_col}'")
            if time_col: print(f"    -> Preserving Timeline via: '{time_col}'")
            if pid_col: print(f"    -> Preserving Execution Context: '{pid_col}'")
            
            row_count = len(df)
            print(f"[*] Phase 2: Analyzing {row_count} blocks while maintaining context...")

            NOISE_GUID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"
            ATTACK_SIGS_REGEX = r"(?i)(bypass|hidden|-enc|payload|dwbo)" 

            results = []

            # Helper to extract context
            def get_context(row):
                return {
                    "TimeCreated": row.get(time_col, "N/A"),
                    "ProcessId": row.get(pid_col, "N/A"),
                    "ThreadId": row.get(tid_col, "N/A"),
                    "Provider": row.get(pname_col, "N/A")
                }

            # 1. 攻撃シグネチャ（最優先）
            keyword_hits = df.filter(pl.col(target_col).str.contains(ATTACK_SIGS_REGEX))
            
            for row in keyword_hits.iter_rows(named=True):
                 item = get_context(row)
                 item.update({
                    "Sphinx_Score": 150,
                    "Original_Snippet": row[target_col][:30],
                    "Decoded_Hint": f"[FORCE DECODE] Attack Keyword Found: {row[target_col][:50]}...",
                    "Sphinx_Tags": "ATTACK_SIG_DETECTED"
                })
                 results.append(item)

            # 2. その他（エントロピー検査）
            remaining_df = df.filter(~pl.col(target_col).str.contains(ATTACK_SIGS_REGEX))
            suspicious_df = remaining_df.filter(pl.col(target_col).is_not_null())
            
            # 4104 only if mixed logs
            eid_col = next((c for c in cols if 'Id' in c), None)
            if eid_col:
                 suspicious_df = suspicious_df.filter(pl.col(eid_col).cast(pl.Utf8).str.contains(r"4104|800|400"))

            for row in suspicious_df.iter_rows(named=True):
                original_text = row[target_col]
                if not original_text: continue
                if NOISE_GUID in original_text: continue

                ent = self._entropy(original_text)
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
                    
                    item = get_context(row)
                    item.update({
                        "Sphinx_Score": score,
                        "Original_Snippet": original_text[:30],
                        "Decoded_Hint": hint,
                        "Sphinx_Tags": tags
                    })
                    results.append(item)
            
            if not results: return None
            # [Fix] Sort by score but keep ProcessId visible
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
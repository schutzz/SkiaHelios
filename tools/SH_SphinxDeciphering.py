import polars as pl
import argparse
import sys
import os
import re
import base64
import zlib
import math
from urllib.parse import unquote

# ============================================================
#  SH_SphinxDeciphering v1.9 [Integrator Edition]
#  Mission: Decode and PRESERVE Evidence Context
#  Update: Enhanced Regex, Lower Threshold, Robust Keywords
# ============================================================

def print_logo():
    print(r"""
          ^
         / \
        /   \     (Sphinx of the Logs)
       /  O  \    "No riddle is too long.
      /_______\    The full truth remains."

       [ 🦁 SH_SphinxDeciphering v1.9 ]
    """)

# --- Regex Definitions ---
RE_COMMAND_LINE = re.compile(
    r"(?:<Data Name=[\"']CommandLine[\"'][^>]*>(.*?)</Data>|\"CommandLine\"\s*:\s*\"(.*?)\")",
    re.IGNORECASE | re.DOTALL
)

RE_B64_CMD = re.compile(
    r"[-eE](?:ncodedCommand)?\s+([A-Za-z0-9+/=]{20,})",
    re.IGNORECASE
)

# [UPDATE] 相対パス・ファイル名のみも許容する強力な正規表現
RE_SEED_PATH = re.compile(
    r"(?i)(?:^|[\s\"'>/\\])([a-zA-Z]:\\[^\"'>\s]*\.(?:bat|ps1|vbs|js|hta|jse|wsf|sh|py|exe)|([\w\-\.]+\.(?:bat|ps1|vbs|js|hta|jse|wsf|sh|py|exe)))(?:[\s\"'<]|$)"
)

class SphinxEngine:
    def __init__(self, target_file, start_time=None, end_time=None):
        self.target_file = target_file
        self.start_time = start_time
        self.end_time = end_time

    def _entropy(self, s):
        if len(s) < 15: return 0.0
        p, lns = {}, float(len(s))
        for c in s:
            p[c] = p.get(c, 0) + 1
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

    def _sniper_process(self, row_dict):
        cols_to_check = ["EventData", "Message", "CommandLine", "ScriptBlockText", "Payload", "ContextInfo", "Properties"]
        raw_parts = []
        for col in cols_to_check:
            val = row_dict.get(col)
            if val and str(val).lower() != "null" and str(val).strip():
                raw_parts.append(str(val).strip())
        
        raw_text = " | ".join(raw_parts)
        if len(raw_text) < 10: return None

        intel = {
            "command_line": "", "decoded_cmd": "", "seeds": [], "score": 0, "tags": []
        }

        # STEP 1: CommandLine
        cmd_line = raw_text
        match = RE_COMMAND_LINE.search(raw_text)
        if match:
            extracted = (match.group(1) or match.group(2) or "").strip()
            if extracted: cmd_line = extracted
        
        try: cmd_line = unquote(cmd_line).strip('"\'')
        except: pass
        intel["command_line"] = cmd_line
        full_search_text = cmd_line + " " + raw_text

        # STEP 2: Base64
        b64_match = RE_B64_CMD.search(full_search_text)
        if b64_match:
            try:
                raw_b64 = b64_match.group(1)
                decoded_bytes = base64.b64decode(raw_b64)
                decoded_str = ""
                try: decoded_str = decoded_bytes.decode('utf-16-le')
                except: 
                    try: decoded_str = decoded_bytes.decode('utf-8')
                    except: pass
                
                if decoded_str and len(decoded_str) > 5:
                    intel["decoded_cmd"] = decoded_str
                    intel["score"] += 100
                    intel["tags"].append("DECODED")
                    full_search_text += " " + decoded_str
            except: pass

        # STEP 3: Seeds (Updated Logic)
        found_matches = RE_SEED_PATH.findall(full_search_text)
        candidates = []
        for m in found_matches:
            # m is tuple: ('C:\\path\\file.bat', '') or ('', 'file.bat')
            if m[0]: candidates.append(m[0])
            elif m[1]: candidates.append(m[1])
            
        if candidates:
            clean_seeds = list(set([s.strip("'\"") for s in candidates if len(s) > 4]))
            if clean_seeds:
                intel["seeds"] = clean_seeds
                intel["score"] += 70 # [UPDATE] Score Boost for any script detection
                intel["tags"].append("CONTAINER_SEED")

        # STEP 4: Heuristics
        if self._entropy(cmd_line) > 5.5:
            intel["score"] += 40
            intel["tags"].append("HIGH_ENTROPY")
        
        keywords = ["powershell", "bypass", "-enc", "http", "curl", "wget", "invoke-expression", "iex", "downloadstring"]
        if any(k in full_search_text.lower() for k in keywords):
            intel["score"] += 50
            intel["tags"].append("ATTACK_SIG")

        # [UPDATE] Lower threshold to 40 to catch simple bat files
        if intel["score"] >= 40:
            # [CRITICAL] List -> Semicolon Separated String for CSV safety
            keywords_str = ";".join(intel["seeds"]) if intel["seeds"] else ""
            
            row_dict.update({
                "Sphinx_Score": intel["score"],
                "Original_Snippet": raw_text[:200],
                "Decoded_Hint": (intel["decoded_cmd"] or intel["command_line"]),
                "Sphinx_Tags": " ".join(list(set(intel["tags"]))),
                "Keywords": keywords_str 
            })
            return row_dict
        return None

    def analyze(self):
        print(f"[*] Sphinx is gazing at: {os.path.basename(self.target_file)}")
        try:
            lf = pl.scan_csv(self.target_file, ignore_errors=True, infer_schema_length=0)
            schema = lf.collect_schema().names()
            target_eids = ["4104", "4688", "800", "4103", "1"]
            id_col = next((c for c in ["EventId", "EventID", "Id"] if c in schema), "EventId")
            time_col = next((c for c in ["TimeCreated", "Timestamp_UTC"] if c in schema), "Time")

            lf = lf.filter(pl.col(id_col).cast(pl.Utf8).is_in(target_eids))
            if self.start_time: lf = lf.filter(pl.col(time_col) >= self.start_time)
            if self.end_time:   lf = lf.filter(pl.col(time_col) <= self.end_time)

            df = lf.collect()
            print(f"[*] Events to scan: {len(df)}")
            results = []
            
            def get_context(row):
                return {
                    "TimeCreated": row.get(time_col), "EventId": row.get(id_col),
                    "Provider": row.get("ProviderName") or row.get("Source") or "Unknown",
                    "ProcessId": row.get("ProcessId"), "ThreadId": row.get("ThreadId")
                }

            for row in df.iter_rows(named=True):
                base_ctx = get_context(row)
                base_ctx.update(row)
                analyzed = self._sniper_process(base_ctx)
                if analyzed:
                    results.append({
                        "TimeCreated": analyzed.get("TimeCreated"),
                        "EventId": analyzed.get("EventId"),
                        "Sphinx_Score": analyzed.get("Sphinx_Score"),
                        "Sphinx_Tags": analyzed.get("Sphinx_Tags"),
                        "Keywords": analyzed.get("Keywords"),
                        "Decoded_Hint": analyzed.get("Decoded_Hint"),
                        "Original_Snippet": analyzed.get("Original_Snippet")
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
    parser.add_argument("--start", help="Filter Start Date")
    parser.add_argument("--end", help="Filter End Date")
    args = parser.parse_args(argv)

    engine = SphinxEngine(args.file, args.start, args.end)
    df_result = engine.analyze()

    if df_result is not None and len(df_result) > 0:
        print(f"\n[+] SPHINX SOLVED THE RIDDLE: {len(df_result)} scripts decoded.")
        df_result.write_csv(args.out)
    else:
        print("[-] Sphinx found nothing suspicious.")

if __name__ == "__main__":
    main()
import sqlite3
import polars as pl
from pathlib import Path
import argparse
import sys
import os
import shutil
from datetime import datetime, timedelta

# ============================================================
#  SH_ClioGet v2.2 [Recon Hunter]
#  Mission: Directly extract History from SQLite DBs
#  Update: Feature 2 - Internal Recon Tagging
# ============================================================

def print_logo():
    print(r"""
      _____ _ _      _____      _ 
     / ____| (_)    / ____|    | |
    | |    | |_  __| |  __  ___| |_ 
    | |    | | |/ _` | |  |/ _ \ __|
    | |____| | | (_| | |__|  __/ |_ 
     \_____|_|_|\__,_|\_____\___|\__|  v2.2 (Recon Hunter)
    """)

class ClioGet:
    def __init__(self):
        # [Feature 2] Internal Recon Keywords
        self.RECON_KEYWORDS = [
            "phpmyadmin", "phpinfo", "adminer", "webmin", "kibana", 
            "/admin/", "/dashboard/", "c2", "webshell"
        ]

    def _convert_chrome_time(self, webkit_timestamp):
        """WebKit Timestamp to ISO String"""
        try:
            if not webkit_timestamp: return None
            epoch_start = datetime(1601, 1, 1)
            delta = timedelta(microseconds=int(webkit_timestamp))
            return (epoch_start + delta).strftime("%Y-%m-%d %H:%M:%S")
        except:
            return None

    def _is_sqlite(self, path):
        """Check file header for SQLite signature"""
        try:
            with open(path, 'rb') as f:
                header = f.read(16)
            return header.startswith(b'SQLite format 3')
        except:
            return False

    def _parse_sqlite(self, db_path, csv_path):
        conn = None
        temp_db = None
        try:
            # Copy to temp to avoid lock
            temp_db = db_path.parent / f"tmp_{db_path.name}_{os.getpid()}.db"
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Generic Chrome/Edge History Query
            query = """
            SELECT
                u.url AS URL,
                u.title AS Title,
                v.visit_time AS VisitTime,
                v.visit_duration AS Duration,
                u.visit_count AS VisitCount
            FROM visits v
            LEFT JOIN urls u ON v.url = u.id
            """
            
            rows = []
            for row in cursor.execute(query):
                ts = self._convert_chrome_time(row[2])
                url = str(row[0]) if row[0] else ""
                title = str(row[1]) if row[1] else ""
                
                # [Feature 2] Recon Tagging Logic
                tags = []
                check_str = (url + " " + title).lower()
                for kw in self.RECON_KEYWORDS:
                    if kw in check_str:
                        tags.append("INTERNAL_RECON_WEB")
                        break # One tag is enough for trigger
                
                rows.append({
                    "LastWriteTimestamp": ts,
                    "URL": url,
                    "Title": title,
                    "Duration_Sec": float(row[3])/1000000.0 if row[3] else 0,
                    "VisitCount": row[4],
                    "Tag": ",".join(tags) # New Column
                })

            if rows:
                df = pl.DataFrame(rows)
                df = df.with_columns([
                    pl.col("Title").alias("ValueName"),
                    pl.col("URL").alias("ValueData")
                ])
                df.write_csv(csv_path)
                print(f"  > [OK] Extracted {len(rows)} records from {db_path.name}")
                return True
            else:
                return False

        except sqlite3.DatabaseError:
            return False
        except Exception as e:
            print(f"  > [!] SQLite Parsing Error: {e}")
            return False
        finally:
            if conn: conn.close()
            if temp_db and temp_db.exists():
                try: temp_db.unlink()
                except: pass

    def hunt_and_parse(self, target_dir, output_dir):
        print(f"[*] ClioGet: Hunting for '*History*' artifacts in: {target_dir}")
        candidates = list(Path(target_dir).rglob("*History*"))
        
        if not candidates:
            print("[-] No candidates found.")
            return

        count = 0
        for hist in candidates:
            if not hist.is_file(): continue
            if hist.stat().st_size == 0: continue
            if hist.suffix.lower() in ['.csv', '.txt', '.json', '.html']: continue

            if not self._is_sqlite(hist):
                continue

            # Identify Browser & User from Path
            try:
                path_str = str(hist).lower()
                parts = hist.parts
                
                if "chrome" in path_str: browser = "Chrome"
                elif "edge" in path_str: browser = "Edge"
                elif "brave" in path_str: browser = "Brave"
                elif "opera" in path_str: browser = "Opera"
                elif "firefox" in path_str: browser = "Firefox"
                else: browser = "UnknownBrowser"

                user = "Unknown"
                if "users" in path_str:
                    for i, p in enumerate(parts):
                        if p.lower() == "users" and i+1 < len(parts):
                            user = parts[i+1]
                            break
                
                profile = "Default"
                if "default" in path_str: profile = "Default"
                elif "profile" in path_str: 
                    import re
                    match = re.search(r"(profile\s*\d+)", path_str)
                    if match: profile = match.group(1).replace(" ", "")

                base_name = f"Browser_History_{browser}_{user}_{profile}_{count}"
            except:
                base_name = f"Browser_History_{count}"

            out_csv = Path(output_dir) / f"{base_name}.csv"
            print(f" [+] Targeting: {hist}")

            if self._parse_sqlite(hist, out_csv):
                count += 1

        print(f"[*] ClioGet finished. {count} history files processed.")

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", required=True)
    parser.add_argument("-o", "--out", required=True)
    parser.add_argument("--tools", default="./tools")
    args = parser.parse_args(argv)

    Path(args.out).mkdir(parents=True, exist_ok=True)
    hunter = ClioGet()
    hunter.hunt_and_parse(args.dir, args.out)

if __name__ == "__main__":
    main()
import sqlite3
import polars as pl
from pathlib import Path
import argparse
import sys
import os
import shutil
from datetime import datetime, timedelta

# ============================================================
#  SH_ClioGet v2.0 [Native SQLite Edition]
#  Mission: Directly extract History from SQLite DBs
#  "Tools may fail, but Raw Data never lies."
# ============================================================

def print_logo():
    print(r"""
      _____ _ _      _____      _ 
     / ____| (_)    / ____|    | |
    | |    | |_  __| |  __  ___| |_ 
    | |    | | |/ _` | |  |/ _ \ __|
    | |____| | | (_| | |__|  __/ |_ 
     \_____|_|_|\__,_|\_____\___|\__|  v2.0 (Native)
    """)

class ClioGet:
    def __init__(self):
        pass

    def _convert_chrome_time(self, webkit_timestamp):
        """
        WebKit Timestamp (microseconds since 1601-01-01) to ISO String
        """
        try:
            if not webkit_timestamp: return None
            # 1601-01-01 -> 1970-01-01 is 11,644,473,600 seconds
            epoch_start = datetime(1601, 1, 1)
            delta = timedelta(microseconds=int(webkit_timestamp))
            return (epoch_start + delta).strftime("%Y-%m-%d %H:%M:%S")
        except:
            return None

    def _parse_sqlite(self, db_path, csv_path):
        """
        SQLite3を使ってHistoryファイルを直接パースする
        """
        conn = None
        temp_db = None
        try:
            # 元ファイルがロックされている可能性があるため、一時ファイルにコピーして開く
            temp_db = db_path.parent / f"tmp_{db_path.name}_{os.getpid()}"
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # URLと訪問履歴を結合するクエリ
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
                # row: (url, title, visit_time, duration, visit_count)
                ts = self._convert_chrome_time(row[2])
                rows.append({
                    "LastWriteTimestamp": ts, # KAPE形式に合わせる
                    "URL": row[0],
                    "Title": row[1],
                    "Duration_Sec": float(row[3])/1000000.0 if row[3] else 0,
                    "VisitCount": row[4]
                })

            if rows:
                df = pl.DataFrame(rows)
                # ChaosGraspが読みやすいカラム名に調整
                # ValueName -> Title, ValueData -> URL
                df = df.with_columns([
                    pl.col("Title").alias("ValueName"),
                    pl.col("URL").alias("ValueData")
                ])
                
                # CSV出力
                df.write_csv(csv_path)
                print(f"  > [OK] Extracted {len(rows)} records.")
                return True
            else:
                print(f"  > [!] No records found in DB.")
                return False

        except sqlite3.DatabaseError as e:
            print(f"  > [!] Not a valid SQLite DB or Encrypted: {e}")
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
        print(f"[*] ClioGet: Hunting for 'History' artifacts (Native Mode) in: {target_dir}")
        candidates = list(Path(target_dir).rglob("History"))
        
        if not candidates:
            print("[-] No 'History' files found.")
            return

        count = 0
        for hist in candidates:
            if not hist.is_file(): continue
            # サイズ0のファイルはスキップ
            if hist.stat().st_size == 0: continue
            
            # User Data以外はノイズとして弾く
            if "User Data" not in str(hist): pass 

            # ファイル名生成
            try:
                # パス: .../Users/Bob/AppData/Local/Google/Chrome/User Data/Default/History
                parts = hist.parts
                
                # プロファイル名 (Default or Profile 1)
                profile = hist.parent.name
                
                # ユーザー名 (Usersフォルダの直下を探す)
                if "Users" in parts:
                    user_idx = parts.index("Users") + 1
                    user = parts[user_idx]
                else:
                    user = "Unknown"
                
                # ブラウザ種別判定
                browser = "UnknownBrowser"
                lower_path = str(hist).lower()
                if "chrome" in lower_path: browser = "Chrome"
                elif "edge" in lower_path: browser = "Edge"
                elif "brave" in lower_path: browser = "Brave"
                elif "opera" in lower_path: browser = "Opera"
                
                base_name = f"Browser_History_{browser}_{user}_{profile}"
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
    parser.add_argument("--tools", default="./tools") # 互換性のため残すが使わない
    args = parser.parse_args(argv)

    Path(args.out).mkdir(parents=True, exist_ok=True)
    hunter = ClioGet()
    hunter.hunt_and_parse(args.dir, args.out)

if __name__ == "__main__":
    main()
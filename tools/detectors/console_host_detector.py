import polars as pl
import re
import pathlib
import datetime
from tools.detectors.base_detector import BaseDetector

class ConsoleHostDetector(BaseDetector):
    """
    [Phase 43/42 Refinement] ConsoleHost Detector
    Parses PowerShell ConsoleHost_history.txt directly to prevent semantic loss.
    Detects:
      - Removable Drive Execution (A:\, B:\) -> Critical for Case 10
      - Defense Evasion (Defender exclusions)
      - Masquerading (Fake Updates)
    """
    def __init__(self, config, kape_dir=None):
        super().__init__(config)
        self.kape_dir = kape_dir

    def _expand_aliases(self, line):
        aliases = {
            r"\bac\b": "Add-Content",
            r"\biwr\b": "Invoke-WebRequest",
            r"\biex\b": "Invoke-Expression",
            r"\bsc\b": "Set-Content",
            r"\bgci\b": "Get-ChildItem"
        }
        for alias, full in aliases.items():
            line = re.sub(alias, full, line, flags=re.IGNORECASE)
        return line

    def _ingest_history(self, kape_dir):
        if not kape_dir: return None
        targets = list(pathlib.Path(kape_dir).rglob("ConsoleHost_history.txt"))
        print(f"    [DEBUG] ConsoleHostDetector: Found {len(targets)} history files in {kape_dir}")
        
        rows = []
        for p in targets:
            try:
                parts = p.parts
                user = "Unknown"
                if "Users" in parts:
                    try:
                        idx = parts.index("Users")
                        if idx + 1 < len(parts):
                            user = parts[idx + 1]
                    except: pass

                # ファイル更新日時を取得 (基準時刻)
                try:
                   stats = p.stat()
                   mtime = datetime.datetime.fromtimestamp(stats.st_mtime)
                except:
                   mtime = datetime.datetime(1970, 1, 1)

                with open(p, 'r', errors='ignore') as f:
                    lines = [l.strip() for l in f.readlines() if l.strip()]
                
                # [FIX] enumerateを使ってインデックス(i)を取得
                for i, line in enumerate(lines):
                    # [FIX] 単語数フィルタの緩和: パスが含まれる場合や重要なキーワードがある場合は許可
                    expanded = self._expand_aliases(line)
                    parts = expanded.split()
                    
                    # 1単語でも、パス区切り文字や拡張子が含まれていれば実行の可能性が高いので通す
                    is_path_exec = re.search(r"\\|\/|\.ps1|\.exe|\.bat|\.cmd", line, re.IGNORECASE)
                    
                    if len(parts) <= 1 and not is_path_exec:
                        # 'whoami', 'ls' など単純すぎるものはスキップするが、
                        # 'A:\script.ps1' は is_path_exec で救済される
                        continue

                    ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
                    remote_ip = ips[0] if ips else ""

                    # [FIX] pandas依存を排除し datetime.timedelta を使用
                    event_time = mtime + datetime.timedelta(seconds=i)

                    # [FIX] FileName Unique-ification
                    # Hekateによる「同一ファイル・同一時刻」の重複排除（Aggregation）を回避するため、
                    # ファイル名にコマンドの先頭部分（Stub）を付与してユニーク化する。
                    cmd_stub = parts[0] if parts else "Command"
                    # ファイルパス記号などを除去してきれいにする
                    cmd_stub = re.sub(r'[\\/:*?"<>|]', '_', cmd_stub)
                    
                    unique_filename = f"ConsoleHost_history.txt [{cmd_stub}]"

                    rows.append({
                        "Timestamp_UTC": event_time.strftime('%Y-%m-%d %H:%M:%S'),
                        "User": user,
                        "Action": line,
                        "Value": line,
                        "Summary": f"PS Hist: {line}",
                        "Type": "EXECUTION",
                        "Category": "Execution",
                        "Remote_IP": remote_ip, 
                        "Target_Path": str(p),
                        "FileName": unique_filename,  # ユニーク化されたファイル名
                        "Source": "PowerShell History",
                        "Status": "DELETED_OR_MISSING"
                    })

            except Exception as e:
                print(f"    [!] Error reading history {p}: {e}")
                
        if not rows:
            return None
            
        df_hist = pl.DataFrame(rows)
        return df_hist

    def analyze(self, df, kape_dir=None):
        target_dir = kape_dir if kape_dir else self.kape_dir

        if not target_dir:
            if df is None: return None
        else:
            print(f"    -> [Hercules] Running ConsoleHost Reconstruction (Phase 44) on {target_dir}...")
        
        history_df = None
        if target_dir:
            history_df = self._ingest_history(target_dir)
            
        if history_df is not None:
            # カラムの調整と結合処理 (既存コードと同様)
            cols = ["Threat_Score", "Tag", "Judge_Verdict", "Insight", "EventId"]
            for c in cols:
                if c not in history_df.columns:
                    val = "" if c in ["Tag", "Judge_Verdict", "Insight"] else 0
                    history_df = history_df.with_columns(pl.lit(val).alias(c))
            
            if df is not None:
                # 型合わせ処理
                main_schema = df.schema
                cast_ops = []
                for col_name in history_df.columns:
                    if col_name in main_schema:
                        main_dtype = main_schema[col_name]
                        hist_dtype = history_df.schema.get(col_name)
                        if hist_dtype != main_dtype:
                            try:
                                # [v6.7.1] Datetime変換は明示フォーマット指定で実行
                                if main_dtype == pl.Datetime("us") and hist_dtype == pl.Utf8:
                                    cast_ops.append(
                                        pl.col(col_name)
                                          .str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False, time_unit="us")
                                          .alias(col_name)
                                    )
                                else:
                                    cast_ops.append(pl.col(col_name).cast(main_dtype, strict=False).alias(col_name))
                            except: pass
                if cast_ops:
                    history_df = history_df.with_columns(cast_ops)


                try:
                    df = pl.concat([df, history_df], how="diagonal")
                    print(f"    [+] Successfully merged {history_df.height} history events.")
                except Exception as e:
                    print(f"    [!] Merge Failed: {e}")
            else:
                df = history_df

        if df is None or df.height == 0:
            return df

        # --- Detection Matrix ---
        console_rules = self.config.get("console_history_rules", [])
        
        if "Threat_Score" in df.columns:
             # Ensure Threat_Score is numeric
             df = df.with_columns(pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0))

        for rule in console_rules:
            pattern = rule.get("pattern")
            score = rule.get("score", 0)
            tag = rule.get("tag", "HISTORY_DETECTED")
            
            is_ps_history = pl.col("Source").fill_null("").str.contains("PowerShell")
            
            df = df.with_columns([
                pl.when(is_ps_history & pl.col("Action").fill_null("").str.contains(pattern))
                  .then(pl.col("Threat_Score") + score)
                  .otherwise(pl.col("Threat_Score"))
                  .alias("Threat_Score"),
                  
                pl.when(is_ps_history & pl.col("Action").fill_null("").str.contains(pattern))
                  .then(pl.format("{},{}", pl.col("Tag").fill_null(""), pl.lit(tag)))
                  .otherwise(pl.col("Tag"))
                  .str.replace(r"^,", "")
                  .alias("Tag")
            ])

        # Path Bonus
        drive_pattern = r"(?i)(A|B):\\"
        df = df.with_columns([
            pl.when(pl.col("Action").str.contains(drive_pattern))
              .then(pl.col("Threat_Score") + 500)
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score"),
              
            pl.when(pl.col("Action").str.contains(drive_pattern))
              .then(pl.format("{},REMOVABLE_DRIVE_EXECUTION", pl.col("Tag")))
              .otherwise(pl.col("Tag"))
              .str.replace(r"^,", "")
              .alias("Tag")
        ])
        
        return df
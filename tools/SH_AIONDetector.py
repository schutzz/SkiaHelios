import polars as pl
import argparse
from pathlib import Path
import sys
import io

# ============================================================
#  SH_AIONDetector v10.2 [Column Match]
#  Fix: Aligned MFT correlation keys with Chaos output.
#  "Synchronizing the eyes with the timeline."
# ============================================================

def print_logo():
    print(r"""
        / \
       / _ \     (The Eye of Truth)
      / | | \    "Timestamps are the ultimate evidence."
     /_/   \_\

      [ SH_AIONDetector v10.2 ]
    """)

class AIONEngine:
    def __init__(self, target_dir=None, file_path=None, mft_csv=None):
        self.target_dir = target_dir
        self.file_path = file_path
        self.mft_csv = mft_csv
        
        self.signatures = {
            "High_Risk": {"keywords": ["powershell", "cmd.exe", "wscript", "mshta", "rundll32", "certutil"], "score": 10},
            "User_Persistence": {"keywords": ["hkey_current_user", "hkcu", "software\\microsoft\\windows\\currentversion\\run"], "score": 9},
            "Suspicious_Path": {"keywords": ["temp", "appdata\\local", "users\\public", "perflogs"], "score": 8},
            "WMI_Persistence": {"keywords": ["wmi", "eventfilter", "eventconsumer", "binding"], "score": 12},
            "Atomic_Red_Team": {"keywords": ["atomic", "art-", "redteam", "t10"], "score": 15}
        }

    def load_mft(self):
        if self.mft_csv and Path(self.mft_csv).exists():
            print(f"[*] Loading MFT for correlation: {self.mft_csv}")
            return pl.read_csv(self.mft_csv, ignore_errors=True, infer_schema_length=0)
        return None

    def hunt_persistence(self, mft_df, suspects_list):
        # [Fix] 「時間」を無視した物理検知 (Time-Agnostic Hotspot Analysis)
        # [Re-Tune] パスの曖昧一致 (System32\Tasks, Programs\Startup などを広く拾う)
        PERSISTENCE_HOTSPOTS = [
            r"(?i)Tasks",           # System32\Tasks, Windows\Tasks...
            r"(?i)Startup"          # Programs\Startup, Start Menu\Startup...
        ]
        
        # 時刻に関係なく、このフォルダにある実行可能ファイルは全て疑うっス！
        # 拡張子フィルタ（実行ファイル、スクリプト、XML、DLL）
        RISKY_EXTENSIONS = r"(?i)\.(exe|lnk|bat|ps1|vbs|xml|dll)$"

        # 1. 物理スキャン：永続化フォルダ
        hotspot_filter = pl.col("ParentPath").str.contains("|".join(PERSISTENCE_HOTSPOTS))
        hotspot_files = mft_df.filter(hotspot_filter)

        # 2. 拡張子で絞り込み (Blind Scan)
        suspect_files = hotspot_files.filter(
            pl.col("FileName").str.contains(RISKY_EXTENSIONS)
        )
        
        # [Patch] Infect6: WANTED Files Indictment
        # 永続化に使われたファイル名を直接狙い撃ちっス！
        WANTED_FILES = ["Windows_Security_Audit", "win_optimizer.lnk"]
        
        detected = []

        # 1. 物理スキャン（場所ベース）
        # ... (既存の blind scan logic) ...
        # hotspot_files has already filtered by path
        if not suspect_files.is_empty():
             for row in suspect_files.iter_rows(named=True):
                detected.append({
                    "Last_Executed_Time": row.get("Created0x10"),
                    "AION_Score": 15, 
                    "AION_Tags": "FILE_PERSISTENCE (HOTSPOT)",
                    "Target_FileName": row.get("FileName"),
                    "Entry_Location": row.get("ParentPath"),
                    "Full_Path": f"{row.get('ParentPath')}\\{row.get('FileName')}"
                })

        # 2. 指名手配ファイル検知（場所不問）
        for wanted in WANTED_FILES:
            hits = mft_df.filter(pl.col("FileName").str.contains(f"(?i){wanted}"))
            if not hits.is_empty():
                for row in hits.iter_rows(named=True):
                    detected.append({
                        "Last_Executed_Time": row.get("Created0x10"),
                        "AION_Score": 20, # Ultra High
                        "AION_Tags": "NAMED_PERSISTENCE (WANTED)",
                        "Target_FileName": row.get("FileName"),
                        "Entry_Location": row.get("ParentPath"),
                        "Full_Path": f"{row.get('ParentPath')}\\{row.get('FileName')}"
                    })
        
        if not suspect_files.is_empty():
             for row in suspect_files.iter_rows(named=True):
                detected.append({
                    "Last_Executed_Time": row.get("Created0x10"),
                    "AION_Score": 15, 
                    "AION_Tags": "FILE_PERSISTENCE (HOTSPOT)",
                    "Target_FileName": row.get("FileName"),
                    "Entry_Location": row.get("ParentPath"),
                    "Full_Path": f"{row.get('ParentPath')}\\{row.get('FileName')}"
                })

        # 2. 物理紐付け：新しく実行された怪しいバイナリ名が、ファイル名やパスに含まれていないか？
        for suspect in suspects_list:
            if not suspect or len(suspect) < 4: continue
            
            # [Fix] Case-insensitive search
            persistence_hits = new_persistence_files.filter(
                pl.col("FileName").str.to_lowercase().str.contains(suspect.lower()) | 
                pl.col("ParentPath").str.to_lowercase().str.contains(suspect.lower())
            )
            
            if not persistence_hits.is_empty():
                for row in persistence_hits.iter_rows(named=True):
                     detected.append({
                        "Last_Executed_Time": row.get("Created0x10"),
                        "AION_Score": 15, # High Confidence via Correlation
                        "AION_Tags": "HOTSPOT_PERSISTENCE",
                        "Target_FileName": row.get("FileName"),
                        "Entry_Location": row.get("ParentPath"),
                        "Full_Path": f"{row.get('ParentPath')}\\{row.get('FileName')}"
                    })
        return detected

    def analyze(self):
        targets = self._find_autoruns_csv()
        df_mft = self.load_mft()
        
        final_list = []
        suspects_list = set()

        for t in targets:
            df_auto = self.load_csv_robust(str(t))
            if df_auto is None or df_auto.is_empty(): continue

            df_str = df_auto.select(pl.all().cast(pl.Utf8))
            for row in df_str.iter_rows(named=True):
                row_score = 0
                row_tags = []
                full_text = " ".join([str(v).lower() for v in row.values() if v is not None])
                
                for tag, rule in self.signatures.items():
                    for k in rule['keywords']:
                        if k in full_text:
                            row_score += rule['score']
                            if tag not in row_tags: row_tags.append(tag)
                
                if row_score > 0:
                    img_path = str(row.get('Image Path') or "").strip()
                    fname = str(row.get('Entry') or "").strip()
                    
                    # Add to suspects for secondary hunting
                    if fname: suspects_list.add(fname)
                    
                    mft_time = None
                    if df_mft is not None and img_path:
                        # [FIX] Chaosの出力カラム "Target_Path" を確実に参照するっス！
                        match = df_mft.filter(pl.col("Target_Path").str.to_lowercase().str.contains(img_path.lower(), literal=True))
                        if not match.is_empty():
                            # [FIX] Chaosの標準時刻カラム "Timestamp_UTC" を取得っス！
                            mft_time = match.get_column("Timestamp_UTC")[0]

                    final_list.append({
                        "Last_Executed_Time": mft_time,
                        "AION_Score": row_score,
                        "AION_Tags": ", ".join(row_tags),
                        "Target_FileName": fname or "Unknown",
                        "Entry_Location": str(row.get('Entry Location') or ""),
                        "Full_Path": img_path,
                    })
        
        # [New] Hunt Persistence Hotspots using gathered suspects
        if df_mft is not None and suspects_list:
             hotspot_hits = self.hunt_persistence(df_mft, list(suspects_list))
             if hotspot_hits:
                 print(f"[*] AION Deep Scan: Found {len(hotspot_hits)} correlated persistence artifacts.")
                 final_list.extend(hotspot_hits)

        if not final_list: return None
        return pl.DataFrame(final_list).sort("AION_Score", descending=True).unique(subset=["Full_Path", "AION_Tags"])

    def _find_autoruns_csv(self):
        if self.file_path and Path(self.file_path).exists(): return [Path(self.file_path)]
        if not self.target_dir: return []
        return list(Path(self.target_dir).rglob("*autoruns*.csv"))

    def load_csv_robust(self, path):
        try:
            with open(path, "rb") as f: raw = f.read()
            enc = "utf-16" if raw.startswith(b'\xff\xfe') else "utf-8"
            content = raw.decode(enc, errors="ignore")
            lines = content.splitlines()
            start = next((i for i, l in enumerate(lines[:30]) if "Entry Location" in l or "Image Path" in l), 0)
            return pl.read_csv(io.StringIO("\n".join(lines[start:])), ignore_errors=True)
        except Exception as e:
            print(f" [!] Load failed {path}: {e}")
            return None

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", help="Artifacts Directory (containing autoruns CSVs)")
    parser.add_argument("--mft", help="Master_Timeline.csv (from Chaos/Chronos)")
    parser.add_argument("-o", "--out", default="Persistence_Report.csv")
    args = parser.parse_args(argv)

    if not args.dir:
        print("[!] Error: --dir is required.")
        return

    engine = AIONEngine(target_dir=args.dir, mft_csv=args.mft)
    df = engine.analyze()

    if df is not None:
        print(f"\n[+] PERSISTENCE CORRELATED: {len(df)} entries mapped to MFT timeline.")
        df.write_csv(args.out)
    else:
        print("[-] No persistence identified.")

if __name__ == "__main__":
    main()
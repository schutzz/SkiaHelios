import polars as pl
import argparse
from pathlib import Path
import json
import datetime
import re

# ============================================================
#  SH_Sirenhunt v1.1 [Fix: Argument Error]
#  Mission: Cross-Validate Seeds with Prefetch & Amcache
#  Update: Fixed main() to accept arguments from HeliosConsole
# ============================================================

def print_logo():
    print(r"""
   _____ _                 _                 _   
  / ____(_)               | |               | |  
 | (___  _ _ __ ___ _ __ | |__  _   _ _ __ | |_ 
  \___ \| | '__/ _ \ '_ \| '_ \| | | | '_ \| __|
  ____) | | | |  __/ | | | | | | |_| | | | | |_ 
 |_____/|_|_|  \___|_| |_|_| |_|\__,_|_| |_|\__| v1.1
    """)

class SirenHunter:
    def __init__(self, chronos_csv, pandora_csv, prefetch_csv, amcache_csv):
        self.seeds = {} # {filename_lower: {metadata}}
        self.chronos = self._safe_load(chronos_csv)
        self.pandora = self._safe_load(pandora_csv)
        self.prefetch = self._safe_load(prefetch_csv)
        self.amcache = self._safe_load(amcache_csv)
        
    def _safe_load(self, path):
        if path and Path(path).exists():
            try: return pl.read_csv(path, ignore_errors=True, infer_schema_length=0)
            except: return None
        return None

    def harvest_seeds(self):
        print("[*] Harvesting Seeds from Chronos & Pandora...")
        
        # 1. Chronos (Timestomp & Anomalies)
        if self.chronos is not None:
            # Score 80以上 または TIMESTOMP判定があるものをSeedにする
            try:
                # Chronos_Scoreは文字列で読み込まれている可能性があるためキャスト
                targets = self.chronos.filter(
                    (pl.col("Chronos_Score").cast(pl.Int64, strict=False) >= 80) |
                    (pl.col("Anomaly_Time").str.contains("TIMESTOMP"))
                )
            except:
                # カラムがない場合のフォールバック
                targets = self.chronos.filter(pl.col("FileName").is_not_null()).head(10)

            for row in targets.iter_rows(named=True):
                fname = str(row.get('FileName', '')).lower()
                if len(fname) < 3: continue
                if fname not in self.seeds: self.seeds[fname] = self._init_seed_record(fname)
                
                self.seeds[fname]['Sources'].append('Chronos')
                self.seeds[fname]['Timestomp_Detected'] = True
                self.seeds[fname]['Creation_Time'] = row.get('si_dt') or row.get('fn_dt')
                self.seeds[fname]['Full_Path'] = row.get('ParentPath', '') + "\\" + row.get('FileName', '')

        # 2. Pandora (Deleted / Renamed / Suspicious Path)
        if self.pandora is not None:
            if "Risk_Tag" in self.pandora.columns:
                targets = self.pandora.filter(pl.col("Risk_Tag").is_not_null())
                for row in targets.iter_rows(named=True):
                    fname = str(row.get('Ghost_FileName', '')).lower()
                    if len(fname) < 3: continue
                    if fname not in self.seeds: self.seeds[fname] = self._init_seed_record(fname)
                    
                    self.seeds[fname]['Sources'].append('Pandora')
                    self.seeds[fname]['Is_Deleted'] = True
                    self.seeds[fname]['Original_Path'] = row.get('ParentPath')
                    
                    if "RENAME" in str(row.get('Reason', '')).upper():
                        self.seeds[fname]['Rename_Detected'] = True
                        self.seeds[fname]['Old_Name'] = row.get('OldFileName')

        print(f"[+] Harvested {len(self.seeds)} unique seeds.")

    def _init_seed_record(self, fname):
        return {
            "FileName": fname,
            "Sources": [],
            "Executed": False,
            "Run_Count": 0,
            "Last_Run_Time": None,
            "Signature_Status": "Unknown",
            "Publisher": None,
            "SHA1": None,
            "Timestomp_Detected": False,
            "Is_Deleted": False,
            "Rename_Detected": False,
            "Criticality_Boost": 0,
            "Full_Path": None,
            "Original_Path": None
        }

    def hunt_execution(self):
        if not self.seeds: return
        print("[*] Hunting for Execution Evidence (Prefetch & Amcache)...")
        
        # 1. Prefetch Hunt (Execution Confirmation)
        if self.prefetch is not None:
            name_col = next((c for c in ["ExecutableName", "SourceFilename", "FileName"] if c in self.prefetch.columns), None)
            time_col = next((c for c in ["LastRun", "SourceCreated"] if c in self.prefetch.columns), None)
            
            if name_col:
                for row in self.prefetch.iter_rows(named=True):
                    pf_name = str(row[name_col]).lower()
                    if pf_name in self.seeds:
                        self.seeds[pf_name]['Executed'] = True
                        self.seeds[pf_name]['Run_Count'] = row.get('RunCount', 1)
                        self.seeds[pf_name]['Last_Run_Time'] = row.get(time_col)
                        self.seeds[pf_name]['Criticality_Boost'] += 50 

        # 2. Amcache Hunt (Signature & Identity)
        if self.amcache is not None:
            name_col = next((c for c in ["Name", "FileName"] if c in self.amcache.columns), None)
            if name_col:
                for row in self.amcache.iter_rows(named=True):
                    am_name = str(row[name_col]).lower()
                    if am_name in self.seeds:
                        self.seeds[am_name]['Executed'] = True 
                        pub = str(row.get('Publisher', '')).lower()
                        self.seeds[am_name]['Publisher'] = row.get('Publisher')
                        self.seeds[am_name]['SHA1'] = row.get('SHA1')
                        if "microsoft" in pub or "windows" in pub:
                            self.seeds[am_name]['Signature_Status'] = "Signed (Microsoft)"
                            self.seeds[am_name]['Criticality_Boost'] -= 50
                        elif pub and len(pub) > 1:
                            self.seeds[am_name]['Signature_Status'] = f"Signed ({row.get('Publisher')})"
                        else:
                            self.seeds[am_name]['Signature_Status'] = "Unsigned/Unknown"
                            self.seeds[am_name]['Criticality_Boost'] += 30

    def export_results(self, output_path):
        final_list = []
        for name, data in self.seeds.items():
            score = 0
            if data['Timestomp_Detected']: score += 30
            if data['Is_Deleted']: score += 20
            if data['Rename_Detected']: score += 30
            if data['Executed']: score += 50
            score += data.get('Criticality_Boost', 0)
            
            if self._is_nuclear_noise(name): score = -999

            if score >= 50:
                data['Siren_Score'] = score
                final_list.append(data)
        
        final_list.sort(key=lambda x: x.get('Siren_Score', 0), reverse=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(final_list, f, indent=4, default=str)
        print(f"[+] Sirenhunt Results Exported: {output_path} ({len(final_list)} targets)")

    def _is_nuclear_noise(self, fname):
        if fname.endswith((".tmp", ".xml", ".ini", ".dll", ".mui", ".dat", ".log", ".bin")): return True
        if "svchost" in fname or "edge" in fname or "onedrive" in fname or "teams" in fname: return True
        if "~rf" in fname or ".old" in fname: return True
        return False

# [FIX] HeliosConsoleからの呼び出しに対応
def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("--chronos", help="Chronos Output CSV")
    parser.add_argument("--pandora", help="Pandora Output CSV")
    parser.add_argument("--prefetch", help="PECmd Output CSV")
    parser.add_argument("--amcache", help="AmcacheParser Output CSV")
    parser.add_argument("-o", "--out", default="Sirenhunt_Results.json")
    args = parser.parse_args(argv)

    hunter = SirenHunter(args.chronos, args.pandora, args.prefetch, args.amcache)
    hunter.harvest_seeds()
    hunter.hunt_execution()
    hunter.export_results(args.out)

if __name__ == "__main__":
    # 直接実行された場合は sys.argv[1:] を渡すっス
    import sys
    main(sys.argv[1:])
import argparse
import json
from pathlib import Path
from datetime import datetime
import sys

# ============================================================
#  SH_ChimeraFusion v1.2 [Recursive Weaver]
#  Mission: Merge multiple Grimoire JSONs into one Campaign Report.
#  Fix: Added recursive search (rglob) to find JSONs in subfolders.
# ============================================================

def print_logo():
    print(r"""
      (   )
     (   ) (
      ) _ (   [ CHIMERA FUSION v1.2 ]
       ( \_   "One Beast, Many Heads."
     _(_\ \_
    (____\
    """)

class ChimeraEngine:
    def __init__(self, json_files):
        self.files = json_files
        self.merged_timeline = []
        self.global_iocs = {
            "File": {},
            "Network": set()
        }
        self.host_summaries = {}
        self.lateral_flows = []

    def fuse_grimoires(self):
        print(f"[*] Fusing {len(self.files)} Grimoires (JSON Mode)...")
        
        for j_path in self.files:
            try:
                with open(j_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                meta = data.get("Metadata", {})
                host_name = meta.get("Host", "Unknown")
                print(f"    -> Ingesting Host: {host_name} ({j_path.parent.name})")

                # Verdict
                verdicts = data.get("Verdict", {}).get("Flags", [])
                verdict_str = ", ".join(verdicts) if verdicts else "No Critical Flags"
                self.host_summaries[host_name] = verdict_str

                # Lateral
                lat_sum = data.get("Verdict", {}).get("Lateral_Summary", "")
                if lat_sum and "CONFIRMED" in lat_sum:
                     self.lateral_flows.append(f"{host_name} (Confirmed Lateral Activity)")

                # Timeline
                events = data.get("Timeline", [])
                for ev in events:
                    self.merged_timeline.append({
                        "Time": ev.get("Time"),
                        "Host": host_name,
                        "User": ev.get("User", "-"),
                        "Category": ev.get("Category", "UNK"),
                        "Summary": ev.get("Summary", ""),
                        "Source": ev.get("Source", ""),
                        "Criticality": ev.get("Criticality", 0)
                    })

                # IOCs
                iocs = data.get("IOCs", {})
                for f_ioc in iocs.get("File", []):
                    key = f_ioc.get("SHA256") or f_ioc.get("SHA1") or f_ioc.get("Path")
                    if key:
                        self.global_iocs["File"][key] = f_ioc 

                for n_ioc in iocs.get("Network", []):
                    entry = f"{n_ioc.get('IP')}:{n_ioc.get('Port')} ({n_ioc.get('Process')})"
                    self.global_iocs["Network"].add(entry)

            except Exception as e:
                print(f"    [!] Failed to ingest {j_path}: {e}")

    def generate_campaign_report(self, output_path):
        self.merged_timeline.sort(key=lambda x: x["Time"])

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# 🦁 Operation Chimera: Campaign Investigation Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            f.write(f"**Scope:** {len(self.files)} Hosts Integrated\n\n")

            f.write("## 1. Campaign Executive Summary\n")
            f.write("本レポートは、複数端末にまたがる攻撃活動（Campaign）を統合分析した結果です。\n\n")
            
            f.write("### 🔗 Attack Flow (Lateral Movement)\n")
            if self.lateral_flows:
                for flow in self.lateral_flows:
                    f.write(f"- 🚨 **{flow}**\n")
            else:
                f.write("明確な横展開の連鎖は自動検出されませんでした。\n\n")

            f.write("### 💻 Host Verdicts\n")
            f.write("| Hostname | Verdict Flags |\n|---|---|\n")
            for host, summary in self.host_summaries.items():
                f.write(f"| **{host}** | {summary} |\n")
            
            f.write("\n## 2. Integrated Timeline (All Hosts)\n")
            f.write("| Time (UTC) | Host | User | Category | Event Summary | Source |\n")
            f.write("|---|---|---|---|---|---|\n")
            
            for item in self.merged_timeline:
                t_str = item["Time"].replace("T", " ").split(".")[0]
                f.write(f"| {t_str} | **{item['Host']}** | {item['User']} | {item['Category']} | {item['Summary']} | {item['Source']} |\n")
            
            f.write("\n## 3. Global IOC List (Deduplicated)\n")
            
            if self.global_iocs["File"]:
                f.write("### 📂 Consolidated File IOCs\n")
                f.write("| File Name | SHA1 | SHA256 | Full Path |\n|---|---|---|---|\n")
                for key, val in self.global_iocs["File"].items():
                    f.write(f"| `{val.get('Name','-')}` | `{val.get('SHA1','-')}` | `{val.get('SHA256','-')}` | `{val.get('Path','-')}` |\n")
            
            if self.global_iocs["Network"]:
                f.write("\n### 🌐 Consolidated Network IOCs\n")
                f.write("| Remote Endpoint |\n|---|\n")
                for net in sorted(list(self.global_iocs["Network"])):
                    f.write(f"| `{net}` |\n")

            f.write(f"\n---\n*Fused by SkiaHelios Chimera v1.2*")

        print(f"[+] Campaign Report Generated: {output_path}")

def main():
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", required=True, help="Directory containing Grimoire_*.json files")
    parser.add_argument("-o", "--out", default="Campaign_Report.md")
    args = parser.parse_args()

    # Recursive Search [Fix]
    p = Path(args.dir)
    reports = list(p.rglob("Grimoire_*.json"))
    
    if not reports:
        print("[!] No Grimoire JSONs found. Make sure you ran Lachesis v1.9.1+ first.")
        return

    engine = ChimeraEngine(reports)
    engine.fuse_grimoires()
    engine.generate_campaign_report(args.out)

if __name__ == "__main__":
    main()
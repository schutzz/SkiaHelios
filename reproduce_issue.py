
import polars as pl
import os
import sys

# Mocking LachesisIntel and Analyzer-like behavior
class MockIntel:
    def is_noise(self, fname, path=""): return False
    def is_trusted_system_path(self, path): return False
    def is_dual_use(self, fname): return False
    def search_threat_intel(self, fname): return None

class Analyzer:
    def __init__(self):
        self.intel = MockIntel()
        self.visual_iocs = []

    def _add_unique_visual_ioc(self, ioc_dict):
        self.visual_iocs.append(ioc_dict)

    def _extract_visual_iocs_from_pandora(self, dfs):
        if dfs.get('Pandora') is not None:
            df = dfs['Pandora']
            # Mimic analyzer.py logic
            for row in df.iter_rows(named=True):
                fname = row.get("Ghost_FileName", "")
                path = row.get("ParentPath", "")
                tag = str(row.get("Threat_Tag", "")).upper()
                score = int(float(row.get("Threat_Score", 0)))
                
                bypass_reason = None
                
                if "TIMESTOMP" in tag: bypass_reason = "Timestomp [DROP]"
                
                if bypass_reason: pass
                elif score < 200: continue
                
                if not bypass_reason: bypass_reason = "High Confidence"
                clean_name = os.path.basename(fname.split("] ")[-1])
                
                extra_info = {}
                final_tag = tag

                # [FIX Logic Test]
                if "setmace" in fname.lower() or "setmace" in path.lower():
                    extra_info["Origin_Path"] = f"{path}\\{fname}"
                    clean_name = "SetMACE.exe"
                    final_tag = "CRITICAL_TIMESTOMP"
                    bypass_reason = "Timestomp Tool Detected"
                    print(f"[DEBUG] SetMACE Detected! Name: {clean_name}")

                self._add_unique_visual_ioc({
                    "Type": final_tag, "Value": clean_name, "Path": path, "Score": score
                })

    def _extract_visual_iocs_from_events(self, events):
        for ev in events:
            tag = str(ev.get('Tag', '')).upper()
            summary_lower = str(ev.get('Summary', '')).lower()
            
            is_af = "ANTI_FORENSICS" in tag or "TIMESTOMP" in tag
            is_remote = "REMOTE_ACCESS" in tag or "SSH" in tag or "putty" in summary_lower
            
            try: score = int(ev.get('Criticality') or 0)
            except: score = 0
            allowed_cats = ['EXEC', 'ANTI', 'FILE', 'LATERAL', 'PERSIST']
            
            if (score >= 90 or is_remote) and ((ev.get('Category') in allowed_cats) or ("CRITICAL" in tag)):
                 if is_remote:
                     print(f"[DEBUG] Remote Tool Detected! {ev['Summary']}")
                     self._add_unique_visual_ioc({
                         "Type": "REMOTE_ACCESS", "Value": ev.get("FileName"), "Score": score
                     })


def main():
    print("Loading Data...")
    ghost_csv = r"c:\Users\user\.gemini\antigravity\scratch\SkiaHelios\Helios_Output\case5_improvement_20260112_135845\Ghost_Report.csv"
    herc_csv = r"c:\Users\user\.gemini\antigravity\scratch\SkiaHelios\Helios_Output\case5_improvement_20260112_135845\Hercules_Judged_Timeline.csv"
    
    dfs = {}
    try:
        dfs['Pandora'] = pl.read_csv(ghost_csv)
    except Exception as e:
        print(f"Failed to load Ghost: {e}")

    try:
        df_herc = pl.read_csv(herc_csv)
        # Convert to list of dicts as Hekate does
        events = []
        for row in df_herc.iter_rows(named=True):
            # Clean keys to match Hekate format somewhat (Hekate standardizes keys)
            ev = {
                "Time": row.get("Timestamp"),
                "Summary": row.get("Event_Description"),
                "Tag": row.get("Tag"),
                "Criticality": row.get("Judge_Score"), # Hekate maps Judge_Score to Criticality? No, Hercules has Judge_Score.
                "Category": row.get("Category"),
                "FileName": row.get("FileName_Or_Keyword")
            }
            # Adjust keys for test
            # Hekate logic: 
            # e['Criticality'] = row['Judge_Score']
            # e['Tag'] = row['Tag']
            # e['Category'] = row['Category']
            if ev['Category'] == 'Execution': ev['Category'] = 'EXEC' # Abbreviation mapping might happen
            events.append(ev)
            
    except Exception as e:
        print(f"Failed to load Hercules: {e}")
        events = []

    analyzer = Analyzer()
    print("Running Pandora Extraction...")
    analyzer._extract_visual_iocs_from_pandora(dfs)
    
    print("Running Event Extraction...")
    analyzer._extract_visual_iocs_from_events(events)
    
    print("\nVisual IOCs Found:")
    for ioc in analyzer.visual_iocs:
        if "SetMACE" in ioc["Value"] or "putty" in str(ioc["Value"]).lower():
            print(ioc)

if __name__ == "__main__":
    main()

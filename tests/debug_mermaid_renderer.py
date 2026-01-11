
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.lachesis.renderer import LachesisRenderer

# Mock LachesisRenderer dependencies if needed (e.g., NarrativeGenerator)
# Since we only test _render_attack_chain_mermaid, we might not need full init if we subclass or patch
# But let's try direct instantiation first. Jinja/Narrator might fail if paths are wrong, but we can ignore those errors for this specific method.

class MockRenderer(LachesisRenderer):
    def __init__(self):
        self.lang = "jp"
        # Skip full init to avoid file dependency issues in test environment
        pass

    # Expose the method we want to test
    def render_mermaid(self, visual_iocs):
        return self._render_attack_chain_mermaid(visual_iocs)
    
    # Needs to match the signature in LachesisRenderer if we were calling it from outside, 
    # but since we're calling the internal method directly, we just need the helpers.
    # _render_group_with_date_split is now part of the class.

if __name__ == "__main__":
    renderer = MockRenderer()
    
    # Create mock visual IOCs
    # Scenario: 
    # 1. Download/Prep on Day 1
    # 2. Execution on Day 2 (should ideally be split from Day 1 if grouped in same phase, but here phases differ)
    # 3. Execution on Day 2 AND Day 3 (This is the key test for splitting within a phase)
    
    visual_iocs = [
        # Day 1 - Prep
        {"Tag": "ADMIN_TOOL", "Value": "PsExec.exe", "Time": "2023-01-01T10:00:00", "Note": "UserAssist"},
        
        # Day 2 - Execution (Group 1)
        {"Tag": "EXEC", "Value": "malware.exe", "Time": "2023-01-02T15:30:00", "Note": "Prefetch"},
        {"Tag": "EXEC", "Value": "cmd.exe", "Time": "2023-01-02T15:35:00", "Note": "Prefetch"},
        
        # Day 3 - Execution (Group 2 - Should be split)
        {"Tag": "EXEC", "Value": "powershell.exe", "Time": "2023-01-03T09:00:00", "Note": "Amcache"},
        
        # Day 3 - Persistence (Cleanup/Anti)
        {"Tag": "TIMESTOMP", "Value": "ntuser.dat", "Time": "2023-01-03T09:05:00", "Note": "LogFile"},

        # Day 4 - Auth Failure Test (Gap of 1 day from 03, so no gap note yet)
        {"Tag": "AUTH_FAILURE,BRUTE_FORCE_DETECTED", "Value": "system", "Time": "2023-01-04T12:00:00", "Note": "EventLog", "Score": 300},
        
        # Day 10 - Long Gap Test (6 Days Gap)
        {"Tag": "PERSIST", "Value": "schtasks.exe", "Time": "2023-01-10T08:00:00", "Note": "EventLog", "Score": 100}
    ]
    
    print("Generating Mermaid Diagram...")
    mermaid = renderer.render_mermaid(visual_iocs)
    print("\n--- Mermaid Output (Preview) ---")
    try:
        print(mermaid)
    except UnicodeEncodeError:
        print(mermaid.encode('cp932', 'replace').decode('cp932'))
    print("----------------------")
    
    # Simple verification logic
    if "2023-01-02" in mermaid and "2023-01-03" in mermaid:
        print("\n[SUCCESS] Dates found in output.")
        
        # Check if "Execute" phase has multiple Note blocks or at least multiple date headers in notes
        # We expect _render_group_with_date_split to output multiple "Note right of Execute: ..." lines if distinct dates exist.
        
        # Let's count how many times "Note right of Execute" appears.
        # Logic: 
        # Day 2 Exec -> Note right of Execute
        # Day 3 Exec -> Note right of Execute
        
        exec_notes = mermaid.count("Note right of Execute")
        print(f"Count of 'Note right of Execute': {exec_notes}")
        
        if exec_notes >= 2:
            print("[SUCCESS] Found multiple Note blocks for Execute phase, indicating date split.")
        else:
            print("[FAILURE] Only one Note block for Execute phase. Grouping logic failed.")
    else:
        print("\n[FAILURE] Dates missing from output.")
        
    # Verify AUTH_FAILURE Labeling
    if "AUTH_FAILURE (Brute Force)" in mermaid:
        print("[SUCCESS] Found 'AUTH_FAILURE (Brute Force)' label (Replaced 'system').")
    else:
        print("[FAILURE] 'AUTH_FAILURE (Brute Force)' label NOT found in mermaid output.")
        
    # Verify Gap Note
    if "Days Gap" in mermaid:
        print("[SUCCESS] Found 'Days Gap' note.")
    else:
        print("[FAILURE] 'Days Gap' note missing.")

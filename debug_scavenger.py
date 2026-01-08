
import sys
import traceback
from pathlib import Path

# Add tools to path
sys.path.append(str(Path(".").resolve()))

try:
    from tools.SH_ChainScavenger import ChainScavenger
except ImportError:
    print("[-] ImportError: Could not import ChainScavenger")
    sys.exit(1)

def test_scavenge():
    raw_dir = r"C:\Temp\dfir-case1\kape"
    print(f"[*] Testing ChainScavenger on {raw_dir}")
    
    try:
        scavenger = ChainScavenger(raw_dir)
        is_dirty, reason = scavenger.is_dirty_hive()
        print(f"[*] Dirty? {is_dirty} ({reason})")
        
        results = scavenger.scavenge()
        print(f"[*] Scavenge completed. Found {len(results)} items.")
        for r in results:
            print(f"    - {r['Username']} (Hex: {r.get('Context_Hex', 'N/A')})")
            
    except Exception:
        traceback.print_exc()

if __name__ == "__main__":
    test_scavenge()

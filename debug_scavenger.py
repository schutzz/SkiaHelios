
import polars as pl
from pathlib import Path
from tools.SH_ChainScavenger import ChainScavenger

RAW_DIR = r"C:\Temp\dfir-case1\kape"
SCAVENGER_OUT = "debug_scavenger_rid.csv"

def debug_scavenge():
    if not Path(RAW_DIR).exists():
        print(f"[-] Raw dir not found: {RAW_DIR}")
        return

    print(f"[*] Starting Debug Scavenge on: {RAW_DIR}")
    scavenger = ChainScavenger(RAW_DIR)
    
    # Force run
    results = scavenger.scavenge()
    
    if results:
        print(f"\n[+] Found {len(results)} entries.")
        for r in results:
            print(f"    User: {r['Username']}")
            print(f"    RID: {r.get('RID')} | SID: {r.get('SID')}")
            print(f"    Hash State: {r.get('Hash_State')}")
            print(f"    Context: {r.get('Context_Hex')}")
            print("-" * 40)
            
        df = pl.DataFrame(results)
        df.write_csv(SCAVENGER_OUT)
        print(f"[+] Output saved to {SCAVENGER_OUT}")
    else:
        print("[-] No results found.")

if __name__ == "__main__":
    debug_scavenge()

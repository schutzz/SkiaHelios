
import polars as pl
from pathlib import Path
from tools.SH_ChainScavenger import ChainScavenger

RAW_DIR = r"C:\Temp\dfir-case1\kape"
SCAVENGER_OUT = "debug_scavenger_v2.csv"

def debug_scavenge_v2():
    print(f"[*] Starting Chain Scavenger v2 Debug on: {RAW_DIR}")
    scavenger = ChainScavenger(RAW_DIR)
    
    # Overwrite Context Size locally if needed for speed, but let's test full 32KB
    # scavenger.CONTEXT_SIZE = 32768
    
    results = scavenger.scavenge()
    
    if results:
        print(f"\n[+] Found {len(results)} entries.")
        for r in results:
            if r['Username'] in ["hacker", "user1", "st"]:
                print(f"    User: {r['Username']}")
                print(f"    RID: {r.get('RID')} | SID: {r.get('SID')}")
                print(f"    Hash State: {r.get('Hash_State')}")
                print(f"    Hash Detail: {r.get('Hash_Detail')}")
                print(f"    Tags: {r.get('AION_Tags')}")
                print(f"    Location Note: {r.get('Entry_Location')}")
                print("-" * 40)
            
        df = pl.DataFrame(results)
        df.write_csv(SCAVENGER_OUT)
        print(f"[+] Output saved to {SCAVENGER_OUT}")
    else:
        print("[-] No results found.")

if __name__ == "__main__":
    debug_scavenge_v2()

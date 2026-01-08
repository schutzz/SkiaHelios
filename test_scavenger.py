from tools.SH_ChainScavenger import ChainScavenger
import sys

print("[*] Starting ChainScavenger Test...")
try:
    s = ChainScavenger('C:/Temp/dfir-case1/kape/E/Windows/System32/config')
    dirty, reason = s.is_dirty_hive()
    print(f"[*] Dirty: {dirty} ({reason})")
    
    # Debug: Check file header and simple search
    target_file = s.sam_files[0] if s.sam_files else None
    if target_file:
        print(f"[*] Debugging file: {target_file}")
        with open(target_file, 'rb') as f:
            header = f.read(16)
            print(f"    Header: {header}")
            f.seek(0)
            data = f.read()
            # Try to find "Names" in ASCII and simple Unicode
            ascii_find = data.find(b'Names')
            unicode_find = data.find(b'N\x00a\x00m\x00e\x00s\x00')
            print(f"    ASCII 'Names' offset: {ascii_find}")
            print(f"    Unicode 'Names' offset: {unicode_find}")

    results = s.scavenge()
    print(f"[*] Results count: {len(results)}")
    
    for r in results[:10]:
        print(f"    Detected: {r['Username']} (Score: {r['AION_Score']})")
        
except Exception as e:
    print(f"[!] Error: {e}")
    import traceback
    traceback.print_exc()

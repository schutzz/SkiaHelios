import polars as pl
from pathlib import Path
import sys
import os

# Mock the Lachesis class partially
class MockLachesis:
    def _infer_source_roots(self, dfs):
        roots = set()
        try:
            if dfs and dfs.get('Timeline') is not None:
                df = dfs['Timeline']
                cols = df.columns
                target_col = "Source" if "Source" in cols else ("Source_File" if "Source_File" in cols else None)
                if target_col:
                    sample = df.head(20)
                    for row in sample.iter_rows(named=True):
                        val = str(row.get(target_col, ""))
                        # Improved Heuristic logic (simulated from current code)
                        # Current Code:
                        # if ":" in val and ("\\" in val or "/" in val):
                        #     path = Path(val)
                        #     try:
                        #         if path.is_file(): path = path.parent
                        #         roots.add(path)
                        #         roots.add(path.parent)
                        #     except: pass
                        
                        # We will copy the Exact Logic from v4.43 to see it fail
                        if ":" in val and ("\\" in val or "/" in val):
                            path = Path(val)
                            try:
                                # [v4.44] Smart Deep Walk
                                # Walk up until we find "filesystem" or "out" or just grab upper levels
                                parts = path.parts
                                # Look for "filesystem" index
                                fs_idx = -1
                                for i, p in enumerate(parts):
                                    if p.lower() in ["filesystem", "kape", "triage", "artifacts", "c"]: fs_idx = i
                                
                                if fs_idx > 0:
                                    # If ".../out/filesystem/...", we want ".../out"
                                    # fs_idx points to "filesystem". So path is parts[:fs_idx]
                                    root_path = Path(*parts[:fs_idx])
                                    roots.add(root_path)
                                    roots.add(root_path.parent)
                                else:
                                    # Fallback: Just add parents up to 5 levels
                                    curr = path
                                    if curr.is_file(): curr = curr.parent
                                    for _ in range(5):
                                        roots.add(curr)
                                        curr = curr.parent
                                        if len(curr.parts) <= 1: break
                            except: pass
        except Exception as e: print(e)
        return list(roots)

def test_inference():
    # Simulate a path that is deep
    # Goal: Find "C:\Temp\dfir-case2\out"
    # Source: "C:\Temp\dfir-case2\out\filesystem\C\Windows\System32\cmd.exe"
    
    mock_path = r"C:\Temp\dfir-case2\out\filesystem\C\Windows\System32\cmd.exe"
    df = pl.DataFrame({"Source": [mock_path]})
    
    lachesis = MockLachesis()
    roots = lachesis._infer_source_roots({"Timeline": df})
    
    print(f"Input: {mock_path}")
    print("Inferred Roots:")
    found = False
    target_root = r"C:\Temp\dfir-case2\out"
    
    for r in roots:
        print(f" - {r}")
        if str(r).startswith(target_root) and len(str(r)) <= len(target_root) + 5: # Close enough
             found = True
             
    if found: print("\n[PASS] Root found (or close enough)!")
    else: print("\n[FAIL] Target root not found. Logic is too shallow.")

if __name__ == "__main__":
    test_inference()

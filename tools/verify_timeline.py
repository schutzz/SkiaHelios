import polars as pl
import sys

csv_path = r"C:\Users\user\.gemini\antigravity\scratch\SkiaHelios\Helios_Output\case6_20260115_143658\Master_Timeline_Fixed.csv"

try:
    df = pl.read_csv(csv_path, ignore_errors=True)
    print(f"Total Rows: {len(df)}")
    if "Artifact_Type" in df.columns:
        vc = df["Artifact_Type"].value_counts()
        print("Artifact_Type Counts:")
        for row in vc.iter_rows():
            print(f"{row[0]}: {row[1]}")
    
    # Check for keywords
    keywords = ["7za", "choco", "AppsAndFeatures", "LeCmd", "PeCmd"]
    for kw in keywords:
        # Search in all string columns
        mask = pl.lit(False)
        for col in df.select(pl.col(pl.Utf8)).columns:
            mask = mask | df[col].str.contains(kw, literal=True)
        
        count = df.filter(mask).height
        print(f"Keyword '{kw}': {count} matches")

    # Specific check for Prefetch/LNK presence
    if "Artifact_Type" in df.columns:
        pf_count = df.filter(pl.col("Artifact_Type") == "Prefetch").height
        lnk_count = df.filter(pl.col("Artifact_Type") == "LNK").height
        print(f"Explicit Prefetch Count: {pf_count}")
        print(f"Explicit LNK Count: {lnk_count}")

except Exception as e:
    print(f"Error: {e}")

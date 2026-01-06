
import polars as pl
from pathlib import Path

# Find the file
base_dir = Path("Helios_Output")
dname = sorted(list(base_dir.glob("Case2_Verdict_Triage_*")))[-1].name
csv_path = base_dir / dname / "Hercules_Judged_Timeline.csv"

print(f"Analyzing: {csv_path}")

try:
    df = pl.read_csv(csv_path, ignore_errors=True)
    with open("verdict_analysis.txt", "w", encoding="utf-8") as f:
        f.write(f"Total Rows: {df.height}\n")
        f.write("\n--- Breakdown by Verdict ---\n")
        f.write(str(df.group_by("Judge_Verdict").count().sort("count", descending=True)) + "\n")

        f.write("\n--- Breakdown by Artifact_Type ---\n")
        f.write(str(df.group_by("Artifact_Type").count().sort("count", descending=True)) + "\n")
        
        f.write("\n--- Breakdown by Tag ---\n")
        f.write(str(df.group_by("Tag").count().sort("count", descending=True).head(20)) + "\n")
        
    print("Analysis saved to verdict_analysis.txt")

except Exception as e:
    print(f"Error: {e}")

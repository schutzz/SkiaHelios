
import polars as pl
import sys

try:
    df = pl.read_csv("Helios_Output/case7_FinalVerify/Hercules_Judged_Timeline.csv", ignore_errors=True, infer_schema_length=0)
    target = df.filter(pl.col("Timestamp_UTC").str.contains("2018-09-15 09:16:24"))
    
    if target.height > 0:
        print(f"Found {target.height} rows.")
        for row in target.filter(pl.col("Category") != "FILE").iter_rows(named=True):
            print(f"Source: {row.get('Source')}")
            print(f"Summary: {row.get('Summary')}")
            print(f"FileName: {row.get('FileName')}")
            print(f"Category: {row.get('Category')}")
            print(f"Message: {row.get('Message')}")
            print(f"Action: {row.get('Action')}")
            print(f"Description: {row.get('Description')}")
            print("-" * 20)
    else:
        print("No row found.")

except Exception as e:
    print(f"Error: {e}")

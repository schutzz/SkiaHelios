import polars as pl
try:
    df = pl.read_csv(r"Helios_Output\case7_FinalVerify\MFT_Clean.csv", ignore_errors=True, infer_schema_length=0)
    time_cols = [c for c in df.columns if "time" in c.lower() or "created" in c.lower()]
    print(time_cols)
except Exception as e:
    print(e)

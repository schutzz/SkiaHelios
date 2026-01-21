import os
import json
import polars as pl
from tools.detectors.console_host_detector import ConsoleHostDetector

def run_test():
    # Mock config
    config = {
        "console_history_rules": [
            {"pattern": "Add-MpPreference", "score": 500, "tag": "DEFENDER_DISABLE_ATTEMPT"},
            {"pattern": "Set-MpPreference", "score": 500, "tag": "DEFENDER_DISABLE_ATTEMPT"},
            {"pattern": "Add-Content.*etc\\\\hosts", "score": 400, "tag": "HOSTS_FILE_MODIFICATION"}
        ]
    }
    
    # Target directory (parent of kape\D\...)
    kape_dir = r"C:\Temp\dfir-case10\kape"
    
    detector = ConsoleHostDetector(config, kape_dir=kape_dir)
    
    # Run analysis (with empty initial df)
    # The detector will ingest the history files and then apply rules.
    df = detector.analyze(None)
    
    if df is not None:
        # Convert polars DataFrame to JSON records
        result = df.to_dicts()
        output_file = "console_host_test_result.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"Test Successful. Results written to {output_file}")
    else:
        print("Test Failed: No data returned from detector.")

if __name__ == "__main__":
    run_test()

import csv
import sys
import json

csv.field_size_limit(2147483647)

file_path = r"C:\Users\user\.gemini\antigravity\scratch\SkiaHelios\Helios_Output\case5_sigma_phase2_final_v5_20260112_144448\Hercules_Judged_Timeline.csv"
output_path = r"C:\Users\user\.gemini\antigravity\scratch\SkiaHelios\found_hercules.txt"

try:
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        found_rows = []
        for row in reader:
            found = False
            for k, v in row.items():
                if v and ("SetMACE" in str(v)):
                    found = True
                    # row['Description'] = row.get('Description', '')[:100] # truncate for readability
                    break
            
            if found:
                found_rows.append(row)
                if len(found_rows) > 5:
                    break
        
    with open(output_path, 'w', encoding='utf-8') as f:
        for row in found_rows:
            f.write(json.dumps(row, indent=2) + "\n")
            
    print("Done")

except Exception as e:
    print(f"Error: {e}")

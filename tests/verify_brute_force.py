
import polars as pl
from datetime import datetime, timedelta

def verify_brute_force():
    print("[*] Verifying Brute Force Detection Logic")

    # Base time
    base_time = datetime(2025, 1, 1, 12, 0, 0)

    # Scenario 1: Sparse failures (safe)
    # 3 failures in 5 minutes
    safe_events = []
    for i in range(3):
        safe_events.append({
            "Timestamp_UTC": base_time + timedelta(minutes=i*2),
            "FileName": "AUTH_FAILURE (EID:4625)",
            "Tag": "",
            "Threat_Score": 0
        })

    # Scenario 2: Brute Force Attack
    # 15 failures in 30 seconds starting at 12:30:00
    bf_start = base_time + timedelta(minutes=30)
    bf_events = []
    for i in range(15):
        bf_events.append({
            "Timestamp_UTC": bf_start + timedelta(seconds=i*2),
            "FileName": "AUTH_FAILURE (EID:4625)",
            "Tag": "",
            "Threat_Score": 0
        })

    # Scenario 3: Other events (Noise)
    noise_events = [{
        "Timestamp_UTC": base_time + timedelta(minutes=15),
        "FileName": "explorer.exe",
        "Tag": "",
        "Threat_Score": 0
    }]

    # Combine
    all_data = safe_events + bf_events + noise_events
    df = pl.DataFrame(all_data)
    
    # Ensure Timestamp is handled as datetime (Simulating behavior inside Referee if it casts)
    # The Referee usually expects strings in CSV but casts them. Here we provide datetime objects directly to start, but let's emulate string input if needed? 
    # Let's keep it clean and use datetime objects as Polars handles them well.
    
    print(f"Total Events: {df.height}")

    # --- LOGIC TO BE IMPLEMENTED IN REF ----
    # 1. Filter for AUTH_FAILURE
    # 2. Sort
    # 3. Rolling count
    
    # Needs to apply to the WHOLE dataframe eventually
    
    # Mocking the implementation logic here for verification design
    
    def detect_brute_force_mock(df_in):
        # working on a copy or modifying? Polars is immutable mostly unless re-assigned
        df_sorted = df_in.sort("Timestamp_UTC")
        
        # Identify AUTH_FAILURE rows
        # We need an index to map back or we can join back.
        # Let's add an index column for tracking
        # df_sorted = df_sorted.with_row_index("orig_idx") # Removed as it is passed in
        
        auth_failures = df_sorted.filter(pl.col("FileName").str.contains("AUTH_FAILURE"))
        
        if auth_failures.height > 0:
            # Rolling count: "1m" window, looking at past? or centered? usually 'closed="left"' or similar
            # We want: for each row, count how many occurrences in the [t - 1m, t] or similar.
            # Actually user said: "1 minute > 10 times".
            # rolling_count is easy with 'by' temporal
            
            # We use rolling on the filtered auth_failures
            counts = auth_failures.rolling(
                index_column="Timestamp_UTC",
                period="1m",
                closed="both" # include boundaries?
            ).agg(
                pl.len().alias("count_1m")
            )
            
            # Now we have counts for each auth failure event.
            # If count > 10, that event is part of a cluster? 
            # Or should we mark ALL events that contributed? 
            # Simplest: If at the moment of this event, we saw >10 in the last minute, it is part of a BF.
            # This marks the 'tail' of the burst primarily, but if the burst is sustained, most get marked.
            # To mark the *start* of the burst as well, we might need a forward looking window too, or just accept that the first few might be 'scouts' before the specific threshold is hit.
            # Let's stick to "if this event is part of a dense cluster".
            # Actually, rolling can be centered, but real-time detection is usually backward looking. 
            # Forensic analysis has future knowledge.
            # Let's use `group_by_dynamic` or just rolling with center=True?
            # Rolling with `center=True` would mark the whole cluster.
            
            # Let's use backward looking for now as it's standard "detection" logic (alert when threshold crossed).
            # But the user said "mark that chunk".
            # Let's verify what rolling logic does best.
            
            # Joining counts back
            # `counts` should have same length and order as `auth_failures` if we didn't group? 
            # rolling() context returns a context, agg returns DF.
            
            # Polars rolling:
            # df.rolling(index_column="ts", period="1m").agg(pl.len())
            
            # Let's use simple logic: backward 1m > 10.
            
            # Correct Rolling Logic using DataFrame context
            # We want to count occurrences in the last 1 minute relative to "Timestamp_UTC"
            # Since 'auth_failures' is already sorted by Timestamp_UTC, we can use rolling() on the DataFrame
            
            counts = auth_failures.rolling(
                index_column="Timestamp_UTC",
                period="1m",
                closed="right"
            ).agg(
                pl.len().alias("rolling_count")
            )
            
            # The counts DataFrame aligns with auth_failures
            df_counts = auth_failures.with_columns(counts["rolling_count"])
            
            # Filter IDs that have count > 10
            bf_indices = df_counts.filter(pl.col("rolling_count") > 10).select("orig_idx")
            
            # Flatten to list
            bf_idx_list = bf_indices["orig_idx"].to_list()
            
            # Apply tag
            return df_in.with_columns(
                pl.when(pl.col("orig_idx").is_in(bf_idx_list))
                .then(
                    pl.when(pl.col("Tag") == "").then(pl.lit("BRUTE_FORCE_DETECTED"))
                    .otherwise(pl.col("Tag") + ",BRUTE_FORCE_DETECTED")
                )
                .otherwise(pl.col("Tag"))
                .alias("Tag")
            ).drop("orig_idx")

        return df_in

    # Run Mock Logic
    # We need to inject 'orig_idx' support or handle it inside
    df_result = detect_brute_force_mock(df.with_row_index("orig_idx"))
    
    # Verify
    print("\nResult Analysis:")
    
    # 1. Safe events should NOT have tag
    safe_tags = df_result.filter(pl.col("Timestamp_UTC") < base_time + timedelta(minutes=10))["Tag"].unique().to_list()
    print(f"Safe Tags: {safe_tags}")
    if any("BRUTE_FORCE" in t for t in safe_tags if t):
         print("[FAILED] Safe events marked as Brute Force")
    else:
         print("[PASS] Safe events clean")

    # 2. BF events should have tag (at least the ones after the 10th one)
    # With backward 1m window:
    # Event 0: count 1
    # ...
    # Event 10: count 11 -> Tagged
    bf_chunk = df_result.filter(pl.col("Timestamp_UTC") >= bf_start)
    tagged_count = bf_chunk.filter(pl.col("Tag").str.contains("BRUTE_FORCE_DETECTED")).height
    print(f"BF Events Tagged: {tagged_count}/{bf_chunk.height}")
    
    if tagged_count >= 5: # We expect at least the tail 5 to be tagged (15 total, threshold 10)
        print("[PASS] Brute force detected")
    else:
        print("[FAILED] Not enough events tagged")
        print(bf_chunk.select(["Timestamp_UTC", "Tag"]))

if __name__ == "__main__":
    verify_brute_force()

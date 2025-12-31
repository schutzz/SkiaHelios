import sys
import os
import argparse
import ctypes
from ctypes import wintypes
import datetime
import time

# Define Windows API structs and functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

FILE_WRITE_ATTRIBUTES = 0x0100
OPEN_EXISTING = 3

class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD),
                ("dwHighDateTime", wintypes.DWORD)]

def create_filetime(timestamp_str):
    # Parse sting to unix timestamp
    dt = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    # Windows FILETIME starts from Jan 1, 1601.
    # Unix timestamp is seconds since Jan 1, 1970.
    # Difference in seconds is 11644473600.
    # FILETIME is in 100-nanosecond intervals (1e-7 seconds).
    
    epoch_diff = 11644473600
    timestamp = dt.timestamp()
    
    # Check if timestamp is negative (before 1970) - not strictly needed for this tool but good practice
    # Windows FILETIME is unsigned 64-bit usually, but represented here as high/low.
    
    filetime_val = int((timestamp + epoch_diff) * 10000000)
    
    ft = FILETIME()
    ft.dwLowDateTime = filetime_val & 0xFFFFFFFF
    ft.dwHighDateTime = filetime_val >> 32
    return ft

def timestomp(filepath, timestamp_str):
    print(f"[*] target: {filepath}")
    print(f"[*] time:   {timestamp_str}")
    
    if not os.path.exists(filepath):
        print("[!] Error: File not found.")
        sys.exit(1)

    try:
        ft = create_filetime(timestamp_str)
    except ValueError:
        print("[!] Error: Invalid timestamp format (YYYY-MM-DD HH:MM:SS needed).")
        sys.exit(1)

    handle = kernel32.CreateFileW(
        filepath,
        FILE_WRITE_ATTRIBUTES,
        0,
        None,
        OPEN_EXISTING,
        0,
        None
    )

    if handle == -1: # INVALID_HANDLE_VALUE
        print(f"[!] Error: Could not open file (Error Code: {ctypes.get_last_error()})")
        sys.exit(1)

    success = kernel32.SetFileTime(handle, ctypes.byref(ft), ctypes.byref(ft), ctypes.byref(ft))
    kernel32.CloseHandle(handle)

    if not success:
        print(f"[!] Error: SetFileTime failed (Error Code: {ctypes.get_last_error()})")
        sys.exit(1)
    
    print("[+] Success: Timestamps updated.")

def main():
    parser = argparse.ArgumentParser(description="Simple Timestomp Tool (MACE Setter)")
    parser.add_argument("file", help="Target file path")
    parser.add_argument("time", help="Timestamp (YYYY-MM-DD HH:MM:SS)")
    
    if len(sys.argv) < 3:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    timestomp(args.file, args.time)

if __name__ == "__main__":
    main()

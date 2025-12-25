import os
import winreg
import subprocess
import base64
import time

# ============================================================
#  SkiaHelios_Trigger v1.0 [Unit Test Artifact Generator]
#  Mission: Generate a single "CRITICAL" alert for each module.
#  "Creating the perfect crime for the perfect tool."
# ============================================================

def trigger_aion():
    print("[*] Triggering AION: Writing HKCU Run Key...")
    # HKCUのRunキーに、不審なパス（Public）の偽装バイナリを登録するっス
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            # AION v10.1 の User_Persistence と Suspicious_Path を両方踏ませるっス！
            winreg.SetValueEx(key, "SkiaHelios_Test", 0, winreg.REG_SZ, r"C:\Users\Public\Verification_Binary.exe")
        print("  [+] Success: AION trigger set.")
    except Exception as e: print(f"  [!] Failed: {e}")

def trigger_sphinx():
    print("[*] Triggering Sphinx: Writing Obfuscated Event Log...")
    # ID 4104 (ScriptBlock) に難読化された PowerShell コードを刻むっス
    # 内容: Write-Host 'SkiaHelios Sphinx Test'
    payload = "VwByAGkAdABlAC0ASABvAHMAdAAgACcAUwBrAGkAYQBIAGUAbABpAG8AcwAgAFMAcABoAGkAbgB4ACAAVABlAHMAdAAnAA=="
    cmd = f"powershell -Command \"Write-EventLog -LogName 'Windows PowerShell' -Source 'PowerShell' -EventID 4104 -Message 'powershell -enc {payload}'\""
    try:
        subprocess.run(cmd, shell=True, check=True)
        print("  [+] Success: Sphinx trigger logged.")
    except Exception as e: print(f"  [!] Failed: {e}")

def trigger_chronos():
    print("[*] Triggering Chronos: Creating a Timestomped File...")
    # ファイルを作成し、作成日時だけを未来に飛ばして $SI と $FN の矛盾を作るっス
    file_path = "C:\\Temp\\Chronos_Test.txt"
    os.makedirs("C:\\Temp", exist_ok=True)
    with open(file_path, "w") as f: f.write("Chronos Verification File")
    
    # PowerShellを使って $SI の作成日時だけを 2030年に設定するっス
    stomp_cmd = f"powershell -Command \"(Get-Item '{file_path}').CreationTime = '2030/12/24 21:00:00'\""
    try:
        subprocess.run(stomp_cmd, shell=True, check=True)
        print(f"  [+] Success: Chronos trigger file created at {file_path}")
    except Exception as e: print(f"  [!] Failed: {e}")

import argparse

def cleanup():
    print("[*] Cleaning up artifacts...")
    # 1. Registry
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, "SkiaHelios_Test")
        print("  [+] Registry key deleted.")
    except FileNotFoundError: print("  [-] Registry key not found.")
    except Exception as e: print(f"  [!] Registry cleanup failed: {e}")

    # 2. File
    try:
        if os.path.exists("C:\\Temp\\Chronos_Test.txt"):
            os.remove("C:\\Temp\\Chronos_Test.txt")
            print("  [+] Test file deleted.")
    except Exception as e: print(f"  [!] File cleanup failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SkiaHelios Artifact Trigger")
    parser.add_argument("--clean", action="store_true", help="Remove artifacts")
    args = parser.parse_args()

    if args.clean:
        cleanup()
    else:
        print("--- SkiaHelios Artifact Trigger Tool ---")
        trigger_aion()
        trigger_sphinx()
        trigger_chronos()
        print("--- Complete. Run SkiaHelios detection. Use --clean to remove artifacts. ---")
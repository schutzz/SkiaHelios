# ============================================================
#  SkiaHelios_Causality_FullStamper.ps1 (v1.4 Ultimate Edition)
#  Mission: Physically stamp evidence of Web -> Drop -> Exec
#  Fix: Use DPS (Diagnostic Policy Service) for guaranteed SRUM flush
# ============================================================

$ErrorActionPreference = "Stop"

# --- 0. Configuration: Correlation Keys ---
$targetFileName = "sh_malicious_payload.ps1"
$targetDir = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\INetCache\Content.Outlook\HELIOS_RC1"
$payloadPath = Join-Path $targetDir $targetFileName
$dummyUrl = "https://example.com/downloads/invoice_secure_check.zip"

Write-Host "[*] SkiaHelios v1.8: Starting Physical Evidence Stamping..." -ForegroundColor Cyan

# --- 1. Clio (WebHistory) Trace Generation ---
Write-Host "[1/5] Stamping Browser History (Clio)..." -ForegroundColor Yellow
# Ensure Edge OOBE is finished before running this to capture history!
Start-Process "msedge.exe" -ArgumentList $dummyUrl
Start-Sleep -Seconds 5
Stop-Process -Name "msedge" -ErrorAction SilentlyContinue

# --- 2. Plutos (SRUM) Network Burst Generation ---
Write-Host "[2/5] Generating Network Burst (Plutos)..." -ForegroundColor Yellow
Invoke-WebRequest -Uri "https://www.google.com" -OutFile (Join-Path $env:TEMP "srum_trigger.tmp")
Start-Sleep -Seconds 3

# --- 3. Pandora (MFT) Physical Artifact Creation ---
Write-Host "[3/5] Dropping Payload into Outlook Cache (Pandora)..." -ForegroundColor Yellow
if (!(Test-Path $targetDir)) { 
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null 
}

$payloadContent = "Write-Host '--- SkiaHelios Causality Analysis Point ---'`nWrite-Host 'Physical Evidence: Verified.'"
Set-Content -Path $payloadPath -Value $payloadContent

# Create Zone.Identifier (ADS) to mark it as an external download
$adsPath = $payloadPath + ":Zone.Identifier"
Set-Content -Path $adsPath -Value "[ZoneTransfer]`nZoneId=3"

# --- 4. Sphinx (EventLog) Execution Log Generation ---
Write-Host "[4/5] Stamping Execution Command Line (Sphinx)..." -ForegroundColor Yellow
$execArgs = "-ExecutionPolicy Bypass -File `"$payloadPath`""
Start-Process powershell.exe -ArgumentList $execArgs
Start-Sleep -Seconds 5

# --- 5. Physical Flush: Force SRUM Purge via DPS ---
Write-Host "[5/5] Forcing SRUM flush via DPS (Diagnostic Policy Service)..." -ForegroundColor Yellow

# Target DPS (Diagnostic Policy Service) as the primary flush trigger
$dps = Get-Service -Name "dps" -ErrorAction SilentlyContinue

if ($null -ne $dps) {
    Write-Host "[*] Service 'dps' found. Restarting to commit SRUDB.dat..." -ForegroundColor Cyan
    # -Force is required as other diagnostic services depend on it
    Stop-Service -Name "dps" -Force
    Start-Sleep -Seconds 5
    Start-Service -Name "dps"
    Write-Host "[+] SRUM commit triggered successfully." -ForegroundColor Green
} else {
    Write-Host "[!] DPS not found. Attempting srumsvc fallback..." -ForegroundColor Red
    $srum = Get-Service | Where-Object { $_.DisplayName -like "*System Resource Usage*" -or $_.Name -eq "srumsvc" }
    if ($null -ne $srum) {
        Stop-Service -Name $srum.Name -Force
        Start-Sleep -Seconds 5
        Start-Service -Name $srum.Name
        Write-Host "[+] SRUM commit triggered via srumsvc." -ForegroundColor Green
    } else {
        Write-Host "[!] No SRUM-related service found. Disk flush might be delayed." -ForegroundColor White
    }
}

Write-Host "`n[+] SUCCESS: Causality Chain Physically Stamped." -ForegroundColor Green
Write-Host "[!] Final Step: Take a snapshot and run KAPE!" -ForegroundColor Cyan
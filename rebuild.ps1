# rebuild.ps1
# Run this instead of manually killing the exe + running pyinstaller by hand.
# Usage:  .\rebuild.ps1

Write-Host "Killing any running processes that could lock build files..." -ForegroundColor Yellow
taskkill /F /IM desktop_app.exe /T 2>$null
taskkill /F /IM tshark.exe /T 2>$null
taskkill /F /IM dumpcap.exe /T 2>$null
taskkill /F /IM nmap.exe /T 2>$null
Start-Sleep -Seconds 2

Write-Host "Cleaning old build artifacts..." -ForegroundColor Yellow
$maxRetries = 5
for ($i = 1; $i -le $maxRetries; $i++) {
    Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue
    if (-not (Test-Path dist) -and -not (Test-Path build)) {
        break
    }
    Write-Host "  Files still locked, retrying ($i/$maxRetries)..." -ForegroundColor DarkYellow
    Start-Sleep -Seconds 2
}

if ((Test-Path dist) -or (Test-Path build)) {
    Write-Host "Could not fully clean build/dist folders - a process is still holding a file open." -ForegroundColor Red
    Write-Host "Open Task Manager and check for desktop_app.exe, tshark.exe, dumpcap.exe, or nmap.exe manually." -ForegroundColor Red
    exit 1
}

Write-Host "Rebuilding with Admin Manifest..." -ForegroundColor Yellow
pyinstaller --onedir --noconsole --noconfirm --manifest manifest.xml desktop_app.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build succeeded. Launching..." -ForegroundColor Green
    Start-Process ".\dist\desktop_app\desktop_app.exe"
} else {
    Write-Host "Build failed - check the output above." -ForegroundColor Red
}
#! Just to Push For Git
<#
Launches the platform (a single Flask process — no separate frontend/DB
services needed):

    .\scripts\start-windows.ps1

Run .\scripts\setup-windows.ps1 first if you haven't already.
Close the window (or Ctrl+C inside it) to stop.
#>

$root = Split-Path -Parent $PSScriptRoot

Write-Host "Starting the platform on http://localhost:5000/ ..." -ForegroundColor Cyan
Push-Location "$root"
& ".\venv\Scripts\python.exe" app.py
Pop-Location

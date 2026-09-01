<#
Optional: launches the intentionally vulnerable demo_app practice target on
its own, separate from the main platform. Only useful if you want a safe
sandbox to try the platform against before pointing it at your own real
application.

    .\scripts\start-demo-app.ps1
#>

$root = Split-Path -Parent $PSScriptRoot

Write-Host "Starting demo_app on http://localhost:8081 ..." -ForegroundColor Cyan
Push-Location "$root\demo_app"
& ".\venv\Scripts\python.exe" app.py
Pop-Location

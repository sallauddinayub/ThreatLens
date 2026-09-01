<#
One-time setup for Windows. Run this once from the project root:

    .\scripts\setup-windows.ps1

Creates a single virtual environment, installs the lightweight requirements
(no torch/chromadb), and configures .env. Since this is a plain Flask +
SQLite app, there's no separate frontend/database service to set up.
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "==> Setting up the platform (Flask + SQLite)" -ForegroundColor Cyan
Push-Location "$root"
if (-not (Test-Path "venv")) {
    python -m venv venv
}
& ".\venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\venv\Scripts\python.exe" -m pip install -r requirements.txt

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env (SQLite database, mock LLM provider by default)." -ForegroundColor Green
}
Pop-Location

Write-Host "==> Setting up the demo app (optional practice target)" -ForegroundColor Cyan
Push-Location "$root\demo_app"
if (-not (Test-Path "venv")) {
    python -m venv venv
}
& ".\venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\venv\Scripts\python.exe" -m pip install -r requirements.txt
Pop-Location

Write-Host ""
Write-Host "Setup complete. Run .\scripts\start-windows.ps1 to launch the platform." -ForegroundColor Green

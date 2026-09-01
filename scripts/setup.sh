#!/usr/bin/env bash
# One-time setup for macOS/Linux. Run once from the project root:
#   bash scripts/setup.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Setting up the platform (Flask + SQLite)"
cd "$ROOT"
[ -d venv ] || python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env (SQLite database, mock LLM provider by default)."
fi

echo "==> Setting up the demo app (optional practice target)"
cd "$ROOT/demo_app"
[ -d venv ] || python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

echo ""
echo "Setup complete. Run: bash scripts/start.sh"

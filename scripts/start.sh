#!/usr/bin/env bash
# Launches the platform (a single Flask process).
#   bash scripts/start.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Starting the platform on http://localhost:5000/ ..."
cd "$ROOT"
exec ./venv/bin/python app.py

#!/usr/bin/env bash
# Optional: launches the intentionally vulnerable demo_app practice target.
#   bash scripts/start-demo-app.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Starting demo_app on http://localhost:8081 ..."
cd "$ROOT/demo_app"
exec ./venv/bin/python app.py

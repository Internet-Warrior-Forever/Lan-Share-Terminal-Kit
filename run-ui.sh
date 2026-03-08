#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="python3"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY="python"
fi
exec "$PY" "$DIR/ui.py"

#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

# Make the Terminal window large enough for the full menu/status area.
if command -v osascript >/dev/null 2>&1; then
  /usr/bin/osascript >/dev/null 2>&1 <<'APPLESCRIPT' || true
tell application "Terminal"
  activate
  delay 0.1
  try
    set bounds of front window to {80, 60, 1520, 920}
  end try
  try
    set number of columns of front window to 128
  end try
  try
    set number of rows of front window to 38
  end try
end tell
APPLESCRIPT
fi

# ANSI resize fallback for terminals that support xterm-compatible sequences.
printf '\033[8;38;128t' || true

/bin/bash "$DIR/run-ui.sh"

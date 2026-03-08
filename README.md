# Portable LAN Share Kit

Cross-platform terminal UI to share your current system route/VPN over LAN using Xray.

## Features
- Works on `macOS`, `Linux`, and `Windows`
- Terminal UI with `start/stop/restart/status/test/log`
- Auto-downloads official Xray on first run
- Dual listener ports for compatibility:
  - SOCKS5: `20911` + `20811`
  - HTTP: `20912` + `20812`
  - DNS relay: `2053`

## Requirements
- Python `3.8+`
- Internet access (first run, for Xray download)
- `curl` (optional, used by built-in test actions)

## Quick Start
### macOS / Linux
```bash
./run-ui.sh
```

### Windows
- Double-click `run-ui.bat`
- Or run:
```bat
py -3 ui.py
```

## Client Setup
Use only one mode per device.

### HTTP proxy
- Host: your machine LAN IP (example: `192.168.1.100`)
- Port: `20912` (fallback `20812`)

### SOCKS5 proxy
- Host: your machine LAN IP
- Port: `20911` (fallback `20811`)
- If supported by the client app, enable remote DNS / `socks5h`

## Troubleshooting
- `context deadline exceeded` on client:
  - Verify the client can reach your machine LAN IP
  - Try fallback ports (`20811` / `20812`)
  - Ensure phone and host are on the same SSID/subnet
  - Disable AP/Client isolation on router
- View runtime logs:
  - `runtime/xray.log`

## Repository Layout
- `ui.py` main cross-platform app
- `run-ui.sh` launcher for macOS/Linux
- `run-ui.bat` launcher for Windows
- `run-ui.command` macOS double-click launcher
- `runtime/` generated state/config/log
- `bin/` downloaded Xray binary

## License
MIT (see `LICENSE`)

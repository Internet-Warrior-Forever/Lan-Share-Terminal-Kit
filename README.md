# Portable LAN Share Kit

Cross-platform terminal UI for LAN proxy sharing with two local engines (no Docker required):

- `xray`: share your current system route/VPN over LAN
- `wireproxy`: run an independent WireGuard tunnel and expose SOCKS/HTTP to LAN

## Features
- Works on `macOS`, `Linux`, and `Windows` (wireproxy auto-download in this kit is for macOS/Linux)
- Terminal UI with `start/stop/restart/status/test/log`
- Engine switch at runtime: `xray` <-> `wireproxy`
- Auto-downloads required binaries to local `bin/`
- Optional SOCKS/HTTP username+password auth for `wireproxy`
- No Docker dependency

## Requirements
- Python `3.8+`
- Internet access for first binary download
- `curl` (optional, used by built-in test)

## Quick Start
### macOS / Linux
```bash
./run-ui.sh
```

### Windows
- Run one-time preflight:
```bat
setup-windows.bat
```
- Start UI:
```bat
run-ui.bat
```
- Or run directly:
```bat
py -3 ui.py
```

### Windows Notes
- `xray` mode works out of the box (binary auto-download supported).
- For `wireproxy` mode on Windows, put `wireproxy.exe` in `bin\wireproxy.exe` (auto-download in this kit is macOS/Linux only).
- Put your `.conf` profiles in `profiles\` (or set another path from the UI).

## How To Use
1. Open UI (`./run-ui.sh`)
2. Select engine:
   - `xray` for sharing your current system tunnel
   - `wireproxy` for independent WireGuard connection
3. Set `LAN IP`, `listen host` (usually `0.0.0.0`), and ports
4. For `wireproxy`, set WireGuard config directory and active `.conf`
5. Start service and connect clients via your LAN IP + selected proxy ports

## Wireproxy Auth (LAN users)
From menu option `Proxy auth user/pass (wireproxy)`:
- Set username/password to enable auth
- Leave username empty to disable auth
- Restart service after changes

## Default Ports
- Primary SOCKS: `20911`
- Primary HTTP: `20912`
- Xray fallback SOCKS: `20811`
- Xray fallback HTTP: `20812`
- Xray DNS relay: `2053`

## Runtime Files
- State: `runtime/state.json`
- Xray config: `runtime/config.json`
- Xray log: `runtime/xray.log`
- Wireproxy config: `runtime/wireproxy.conf`
- Wireproxy log: `runtime/wireproxy.log`
- Binaries: `bin/`

## Notes
- In `xray` mode, traffic follows your host's current route/VPN.
- In `wireproxy` mode, traffic is independent from host VPN state.
- Keep your WireGuard `.conf` files in your selected config directory (default tries sibling `../profiles`).

## License
MIT (see `LICENSE`)

## Legal Notice
- Copyright: 2026 contributors
- This project code is MIT licensed.
- Xray-core and wireproxy are third-party software with their own upstream licenses.
- See `NOTICE` for concise attribution notes.

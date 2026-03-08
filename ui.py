#!/usr/bin/env python3
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / "runtime"
STATE_FILE = RUNTIME / "state.json"
CONFIG_FILE = RUNTIME / "config.json"
LOG_FILE = RUNTIME / "xray.log"
XRAY_DIR = ROOT / "bin"
LICENSE_FILE = ROOT / "LICENSE"
NOTICE_FILE = ROOT / "NOTICE"

DEFAULTS = {
    "lan_ip": "",
    "listen_host": "0.0.0.0",
    "socks_port": 20911,
    "http_port": 20912,
    "socks_alt_port": 20811,
    "http_alt_port": 20812,
    "dns_port": 2053,
    "vless_port": 44900,
}


def is_windows() -> bool:
    return os.name == "nt"


def clear_screen() -> None:
    os.system("cls" if is_windows() else "clear")


def detect_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return "127.0.0.1"


def random_uuid() -> str:
    import uuid

    return str(uuid.uuid4())


def arch_tag() -> tuple[str, str]:
    sysname = platform.system().lower()
    machine = platform.machine().lower()
    if sysname.startswith("darwin"):
        os_tag = "macos"
    elif sysname.startswith("linux"):
        os_tag = "linux"
    elif sysname.startswith("windows"):
        os_tag = "windows"
    else:
        raise RuntimeError(f"Unsupported OS: {platform.system()}")

    if machine in {"x86_64", "amd64"}:
        arch = "64"
    elif machine in {"arm64", "aarch64"}:
        arch = "arm64-v8a"
    else:
        raise RuntimeError(f"Unsupported architecture: {platform.machine()}")

    return os_tag, arch


def xray_asset_name() -> str:
    os_tag, arch = arch_tag()
    return f"Xray-{os_tag}-{arch}.zip"


def xray_binary_path() -> Path:
    return XRAY_DIR / ("xray.exe" if is_windows() else "xray")


def ensure_runtime() -> None:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    XRAY_DIR.mkdir(parents=True, exist_ok=True)


def fetch_latest_xray_binary() -> Path:
    ensure_runtime()
    asset = xray_asset_name()
    url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{asset}"
    zip_path = RUNTIME / asset

    print(f"Downloading {asset} ...")
    urllib.request.urlretrieve(url, zip_path)

    extract_dir = RUNTIME / "xray_extract"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_dir)

    if is_windows():
        candidates = list(extract_dir.rglob("xray.exe"))
    else:
        candidates = list(extract_dir.rglob("xray"))
    if not candidates:
        raise RuntimeError("xray binary not found in downloaded archive")

    src = candidates[0]
    dst = xray_binary_path()
    shutil.copy2(src, dst)
    if not is_windows():
        dst.chmod(0o755)
    return dst


def ensure_xray_binary() -> Path:
    p = xray_binary_path()
    if p.exists():
        return p
    return fetch_latest_xray_binary()


def state_default() -> dict:
    s = dict(DEFAULTS)
    s["lan_ip"] = detect_lan_ip()
    s["uuid"] = random_uuid()
    s["pid"] = None
    return s


def load_state() -> dict:
    ensure_runtime()
    if not STATE_FILE.exists():
        s = state_default()
        save_state(s)
        return s
    try:
        with STATE_FILE.open("r", encoding="utf-8") as f:
            s = json.load(f)
    except Exception:
        s = state_default()
    for k, v in DEFAULTS.items():
        s.setdefault(k, v)
    s.setdefault("lan_ip", detect_lan_ip())
    s.setdefault("uuid", random_uuid())
    s.setdefault("pid", None)
    return s


def save_state(s: dict) -> None:
    ensure_runtime()
    with STATE_FILE.open("w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=True, indent=2)


def build_config(s: dict) -> dict:
    listen_host = s["listen_host"]
    socks_port = int(s["socks_port"])
    http_port = int(s["http_port"])
    socks_alt = int(s["socks_alt_port"])
    http_alt = int(s["http_alt_port"])
    dns_port = int(s["dns_port"])
    vless_port = int(s["vless_port"])
    uuid = s["uuid"]

    inbounds = [
        {
            "tag": "in-socks",
            "listen": listen_host,
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        },
        {
            "tag": "in-http",
            "listen": listen_host,
            "port": http_port,
            "protocol": "http",
            "settings": {},
        },
        {
            "tag": "in-socks-alt",
            "listen": listen_host,
            "port": socks_alt,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        },
        {
            "tag": "in-http-alt",
            "listen": listen_host,
            "port": http_alt,
            "protocol": "http",
            "settings": {},
        },
        {
            "tag": "in-dns",
            "listen": listen_host,
            "port": dns_port,
            "protocol": "dokodemo-door",
            "settings": {"address": "8.8.8.8", "port": 53, "network": "tcp,udp"},
        },
        {
            "tag": "in-vless",
            "listen": listen_host,
            "port": vless_port,
            "protocol": "vless",
            "settings": {"decryption": "none", "clients": [{"id": uuid}]},
            "streamSettings": {"network": "tcp", "security": "none"},
        },
    ]

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "dns-out", "protocol": "dns", "settings": {}},
            {"tag": "direct", "protocol": "freedom", "settings": {}},
        ],
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": [
                "https://1.1.1.1/dns-query",
                "https://dns.google/dns-query",
                "1.1.1.1",
                "8.8.8.8",
                "localhost",
            ],
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["in-dns"], "outboundTag": "dns-out"},
                {
                    "type": "field",
                    "inboundTag": [
                        "in-socks",
                        "in-http",
                        "in-socks-alt",
                        "in-http-alt",
                        "in-vless",
                    ],
                    "outboundTag": "direct",
                },
            ],
        },
    }


def write_config(s: dict) -> None:
    cfg = build_config(s)
    with CONFIG_FILE.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=True, indent=2)


def pid_alive(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        if is_windows():
            out = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}"], stderr=subprocess.DEVNULL, text=True
            )
            return str(pid) in out
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def stop_service(s: dict) -> None:
    pid = s.get("pid")
    if pid_alive(pid):
        try:
            if is_windows():
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=False)
            else:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.7)
                if pid_alive(pid):
                    os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
    s["pid"] = None
    save_state(s)


def start_service(s: dict) -> None:
    ensure_runtime()
    xray = ensure_xray_binary()
    stop_service(s)
    write_config(s)

    log_f = LOG_FILE.open("a", encoding="utf-8")
    cmd = [str(xray), "run", "-c", str(CONFIG_FILE)]
    creationflags = 0
    if is_windows():
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    p = subprocess.Popen(
        cmd,
        stdout=log_f,
        stderr=subprocess.STDOUT,
        cwd=str(ROOT),
        creationflags=creationflags,
    )
    s["pid"] = int(p.pid)
    save_state(s)
    time.sleep(1.0)


def restart_service(s: dict) -> None:
    stop_service(s)
    start_service(s)


def quick_http_test(s: dict, use_alt: bool = False) -> str:
    port = int(s["http_alt_port"] if use_alt else s["http_port"])
    proxy = f"http://{s['lan_ip']}:{port}"
    try:
        cmd = ["curl", "--max-time", "10", "-x", proxy, "https://api.ipify.org"]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out.strip()
    except Exception as e:
        return f"HTTP test failed on {proxy}: {e}"


def tail_log(lines: int = 80) -> str:
    if not LOG_FILE.exists():
        return "No log yet."
    try:
        data = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(data[-lines:])
    except Exception as e:
        return f"Failed to read log: {e}"


def show_status(s: dict) -> None:
    alive = pid_alive(s.get("pid"))
    print(f"xray binary: {xray_binary_path()}")
    print(f"running    : {alive} (pid={s.get('pid')})")
    print(f"LAN IP     : {s['lan_ip']}")
    print(f"listen host: {s['listen_host']}")
    print(f"SOCKS      : {s['lan_ip']}:{s['socks_port']}")
    print(f"HTTP       : {s['lan_ip']}:{s['http_port']}")
    print(f"SOCKS ALT  : {s['lan_ip']}:{s['socks_alt_port']}")
    print(f"HTTP ALT   : {s['lan_ip']}:{s['http_alt_port']}")
    print(f"DNS        : {s['lan_ip']}:{s['dns_port']}")


def show_legal_notice() -> None:
    print("License: MIT")
    print("Copyright (c) 2026 contributors")
    print("Third-party: Xray-core is downloaded from upstream and uses its own license.")
    print()
    if NOTICE_FILE.exists():
        print("--- NOTICE ---")
        print(NOTICE_FILE.read_text(encoding="utf-8", errors="replace").strip())
        print()
    if LICENSE_FILE.exists():
        print("--- LICENSE (summary) ---")
        lines = LICENSE_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[:18]:
            print(line)
        if len(lines) > 18:
            print("...")


def menu() -> None:
    s = load_state()
    while True:
        clear_screen()
        print("LAN Share Manager (Cross-Platform)")
        print("----------------------------------")
        show_status(s)
        print()
        print("License: MIT | Copyright (c) 2026 contributors")
        print("Xray-core is third-party software and follows its upstream license.")
        print()
        print("1) Restart share")
        print("2) Start share")
        print("3) Stop share")
        print("4) Status")
        print("5) Test HTTP (20912)")
        print("6) Test HTTP ALT (20812)")
        print("7) Show log tail")
        print("8) Change LAN IP")
        print("9) Download/Update Xray")
        print("10) About / License")
        print("0) Exit")
        choice = input("Select [0-10]: ").strip()

        if choice == "1":
            restart_service(s)
            print("Restarted.")
        elif choice == "2":
            start_service(s)
            print("Started.")
        elif choice == "3":
            stop_service(s)
            print("Stopped.")
        elif choice == "4":
            show_status(s)
        elif choice == "5":
            print(quick_http_test(s, use_alt=False))
        elif choice == "6":
            print(quick_http_test(s, use_alt=True))
        elif choice == "7":
            print(tail_log())
        elif choice == "8":
            new_ip = input("Enter LAN IP: ").strip()
            if new_ip:
                s["lan_ip"] = new_ip
                save_state(s)
                print(f"LAN IP updated: {new_ip}")
        elif choice == "9":
            p = fetch_latest_xray_binary()
            print(f"Xray ready at: {p}")
        elif choice == "10":
            show_legal_notice()
        elif choice == "0":
            return
        else:
            print("Invalid option")
        input("\nPress Enter to continue...")


def main() -> None:
    ensure_runtime()
    if len(sys.argv) > 1 and sys.argv[1] == "--non-interactive-status":
        s = load_state()
        show_status(s)
        return
    menu()


if __name__ == "__main__":
    main()

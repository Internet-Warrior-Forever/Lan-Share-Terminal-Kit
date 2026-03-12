#!/usr/bin/env python3
import getpass
import ipaddress
import json
import os
import platform
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional
import uuid as uuidlib

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / "runtime"
XRAY_DIR = ROOT / "bin"
LICENSE_FILE = ROOT / "LICENSE"
NOTICE_FILE = ROOT / "NOTICE"

STATE_FILE = RUNTIME / "state.json"
XRAY_CONFIG_FILE = RUNTIME / "config.json"
XRAY_LOG_FILE = RUNTIME / "xray.log"
WIREPROXY_CONF_FILE = RUNTIME / "wireproxy.conf"
WIREPROXY_LOG_FILE = RUNTIME / "wireproxy.log"
WIREPROXY_WG_ACTIVE_FILE = RUNTIME / "wireproxy-wg-active.conf"
_RESIZE_TRIED = False


def default_wg_config_dir() -> Path:
    sibling = ROOT.parent / "profiles"
    if sibling.exists():
        return sibling
    return ROOT / "profiles"


DEFAULTS = {
    "engine": "xray",
    "lan_ip": "",
    "lan_iface": "",
    "listen_host": "0.0.0.0",
    "pid": None,
    "uuid": "",
    "socks_port": 20911,
    "http_port": 20912,
    "socks_alt_port": 20811,
    "http_alt_port": 20812,
    "dns_port": 2053,
    "vless_port": 44900,
    "wireproxy_version": "v1.1.2",
    "wireproxy_dns": "",
    "wireproxy_mtu": 1280,
    "wireproxy_resolve_strategy": "ipv4",
    "wireproxy_uplink_iface": "auto",
    "wireproxy_route_mode": "auto",
    "wireproxy_route_active_endpoint_ip": "",
    "wireproxy_route_active_gateway": "",
    "wireproxy_block_start": False,
    "wireproxy_allow_nested_vpn": False,
    "ui_mode": "simple",
    "wg_config_dir": str(default_wg_config_dir()),
    "wg_active_config": "",
    "proxy_username": "",
    "proxy_password": "",
}

FALLBACK_DNS_IPS = [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "178.22.122.100",
    "185.51.200.2",
]

XRAY_DOH_BOOTSTRAP_HOSTS: dict[str, object] = {
    "cloudflare-dns.com": ["1.1.1.1", "1.0.0.1"],
    "dns.google": ["8.8.8.8", "8.8.4.4"],
    "dns.quad9.net": ["9.9.9.9", "149.112.112.112"],
}

XRAY_DOH_DNS_SERVERS: list[object] = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
]

XRAY_FALLBACK_DNS_SERVERS: list[object] = [
    *XRAY_DOH_DNS_SERVERS,
    "tcp://1.1.1.1",
    "tcp://1.0.0.1",
    "tcp://8.8.8.8",
    "tcp://8.8.4.4",
    "tcp://9.9.9.9",
    "tcp://149.112.112.112",
    *FALLBACK_DNS_IPS,
]


def is_windows() -> bool:
    return os.name == "nt"


def clear_screen() -> None:
    os.system("cls" if is_windows() else "clear")


def ensure_terminal_layout() -> None:
    global _RESIZE_TRIED
    if _RESIZE_TRIED or is_windows():
        return
    _RESIZE_TRIED = True

    try:
        size = shutil.get_terminal_size((120, 30))
        min_cols = int(os.environ.get("LAN_UI_MIN_COLS", "120"))
        min_rows = int(os.environ.get("LAN_UI_MIN_ROWS", "36"))
        if size.columns < min_cols or size.lines < min_rows:
            sys.stdout.write(f"\033[8;{min_rows};{min_cols}t")
            sys.stdout.flush()
    except Exception:
        pass


def compact_view_enabled() -> bool:
    try:
        size = shutil.get_terminal_size((120, 30))
        return size.lines < 32 or size.columns < 104
    except Exception:
        return False


def _sort_ipv4_candidates(candidates: list[tuple[str, str]]) -> list[tuple[str, str]]:
    def key(item: tuple[str, str]) -> tuple[int, str, str]:
        iface, ip = item
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            rank = 2
        elif addr.is_private:
            rank = 0
        else:
            rank = 1
        return (rank, iface, ip)

    return sorted(candidates, key=key)


def list_interface_ipv4s() -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    candidates: list[tuple[str, str]] = []

    # Preferred path on Unix-like systems.
    if not is_windows():
        try:
            out = subprocess.check_output(
                ["ip", "-o", "-4", "addr", "show", "up"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in out.splitlines():
                parts = line.split()
                # Example: "2: en0    inet 192.168.1.2/24 ..."
                if len(parts) >= 4 and parts[2] == "inet":
                    iface = parts[1]
                    ip = parts[3].split("/")[0]
                    pair = (iface, ip)
                    if pair not in seen:
                        seen.add(pair)
                        candidates.append(pair)
        except Exception:
            pass

        # macOS fallback (and generic fallback) via ifconfig.
        if not candidates:
            try:
                out = subprocess.check_output(
                    ["ifconfig"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                current_iface = ""
                for raw in out.splitlines():
                    line = raw.rstrip()
                    if not line.startswith("\t") and ":" in line:
                        maybe_iface = line.split(":", 1)[0].strip()
                        # Example: "en0: flags=8863<...>"
                        if maybe_iface and " " not in maybe_iface:
                            current_iface = maybe_iface
                            continue
                    if not current_iface:
                        continue
                    stripped = line.strip()
                    if not stripped.startswith("inet "):
                        continue
                    parts = stripped.split()
                    if len(parts) < 2:
                        continue
                    ip = parts[1]
                    pair = (current_iface, ip)
                    if pair not in seen:
                        seen.add(pair)
                        candidates.append(pair)
            except Exception:
                pass
    else:
        # Windows fallback via ipconfig parsing.
        try:
            out = subprocess.check_output(
                ["ipconfig"],
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            current_iface = ""
            for raw in out.splitlines():
                line = raw.rstrip()
                if line.endswith(":") and ("adapter " in line.lower() or "آداپتور" in line):
                    current_iface = line.strip(" :")
                    continue
                if "IPv4" not in line:
                    continue
                if ":" not in line:
                    continue
                ip = line.split(":", 1)[1].strip()
                if not ip:
                    continue
                pair = (current_iface or "unknown", ip)
                if pair not in seen:
                    seen.add(pair)
                    candidates.append(pair)
        except Exception:
            pass

    # Keep only valid IPv4 values.
    filtered: list[tuple[str, str]] = []
    for iface, ip in candidates:
        try:
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv4Address):
                filtered.append((iface, ip))
        except Exception:
            continue

    return _sort_ipv4_candidates(filtered)


def detect_lan_candidate() -> tuple[str, str]:
    for iface, ip in list_interface_ipv4s():
        if not ip.startswith("127."):
            return ip, iface

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and not ip.startswith("127."):
            return ip, "auto"
    except Exception:
        pass
    return "127.0.0.1", "loopback"


def detect_lan_ip() -> str:
    ip, _iface = detect_lan_candidate()
    return ip


def random_uuid() -> str:
    return str(uuidlib.uuid4())


def parse_key_value_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if key:
                values[key] = val
    except Exception:
        return {}
    return values


def is_valid_uuid(raw: str) -> bool:
    try:
        uuidlib.UUID(raw)
        return True
    except Exception:
        return False


def parse_int_port(raw: str) -> int:
    try:
        value = int(str(raw).strip())
    except Exception:
        return 0
    if 1 <= value <= 65535:
        return value
    return 0


def collect_vless_clients(state: dict) -> list[dict]:
    ids: list[str] = []
    current = str(state.get("uuid") or "").strip()
    if is_valid_uuid(current):
        ids.append(current)

    extra = str(state.get("legacy_uuid") or "").strip()
    if is_valid_uuid(extra):
        ids.append(extra)

    sibling_env = parse_key_value_file(ROOT.parent / "runtime" / "state.env")
    old_uuid = str(sibling_env.get("UUID") or "").strip()
    if is_valid_uuid(old_uuid):
        ids.append(old_uuid)

    unique_ids: list[str] = []
    seen: set[str] = set()
    for item in ids:
        if item in seen:
            continue
        seen.add(item)
        unique_ids.append(item)

    return [{"id": item} for item in unique_ids]


def collect_vless_ports(state: dict) -> list[int]:
    ports: list[int] = []
    current = parse_int_port(state.get("vless_port"))
    if current:
        ports.append(current)

    legacy = parse_int_port(state.get("legacy_vless_port"))
    if legacy:
        ports.append(legacy)

    sibling_env = parse_key_value_file(ROOT.parent / "runtime" / "state.env")
    old_port = parse_int_port(sibling_env.get("VLESS_PORT", ""))
    if old_port:
        ports.append(old_port)

    # Keep backward compatibility with older mobile configs.
    ports.append(44300)

    unique_ports: list[int] = []
    seen: set[int] = set()
    for port in ports:
        if port in seen:
            continue
        seen.add(port)
        unique_ports.append(port)
    return unique_ports


def xray_arch_tag() -> tuple[str, str]:
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


def wireproxy_arch_tag() -> tuple[str, str]:
    sysname = platform.system().lower()
    machine = platform.machine().lower()

    if sysname.startswith("darwin"):
        os_tag = "darwin"
    elif sysname.startswith("linux"):
        os_tag = "linux"
    else:
        raise RuntimeError(
            "Auto download for wireproxy is supported on macOS/Linux in this kit."
        )

    if machine in {"x86_64", "amd64"}:
        arch = "amd64"
    elif machine in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        raise RuntimeError(f"Unsupported architecture: {platform.machine()}")

    return os_tag, arch


def xray_asset_name() -> str:
    os_tag, arch = xray_arch_tag()
    return f"Xray-{os_tag}-{arch}.zip"


def wireproxy_asset_name(version: str) -> tuple[str, str]:
    os_tag, arch = wireproxy_arch_tag()
    asset = f"wireproxy_{os_tag}_{arch}.tar.gz"
    url = f"https://github.com/windtf/wireproxy/releases/download/{version}/{asset}"
    return asset, url


def xray_binary_path() -> Path:
    return XRAY_DIR / ("xray.exe" if is_windows() else "xray")


def wireproxy_binary_path() -> Path:
    return XRAY_DIR / ("wireproxy.exe" if is_windows() else "wireproxy")


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

    candidates = list(extract_dir.rglob("xray.exe" if is_windows() else "xray"))
    if not candidates:
        raise RuntimeError("xray binary not found in downloaded archive")

    src = candidates[0]
    dst = xray_binary_path()
    shutil.copy2(src, dst)
    if not is_windows():
        dst.chmod(0o755)
    return dst


def fetch_wireproxy_binary(version: str) -> Path:
    ensure_runtime()
    asset, url = wireproxy_asset_name(version)
    archive_path = RUNTIME / asset

    print(f"Downloading {asset} ...")
    urllib.request.urlretrieve(url, archive_path)

    extract_dir = RUNTIME / "wireproxy_extract"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive_path, "r:gz") as tf:
        tf.extractall(extract_dir)

    target_name = "wireproxy.exe" if is_windows() else "wireproxy"
    candidates = list(extract_dir.rglob(target_name))
    if not candidates and target_name.endswith(".exe"):
        candidates = list(extract_dir.rglob("wireproxy"))
    if not candidates:
        raise RuntimeError("wireproxy binary not found in downloaded archive")

    src = candidates[0]
    dst = wireproxy_binary_path()
    shutil.copy2(src, dst)
    if not is_windows():
        dst.chmod(0o755)
    return dst


def ensure_xray_binary() -> Path:
    path = xray_binary_path()
    if path.exists():
        return path
    return fetch_latest_xray_binary()


def ensure_wireproxy_binary(s: dict) -> Path:
    path = wireproxy_binary_path()
    if path.exists():
        return path
    return fetch_wireproxy_binary(str(s.get("wireproxy_version") or "v1.1.2"))


def list_wg_configs(s: dict) -> list[str]:
    cfg_dir = Path(str(s.get("wg_config_dir") or default_wg_config_dir()))
    if not cfg_dir.exists() or not cfg_dir.is_dir():
        return []
    return sorted(p.name for p in cfg_dir.glob("*.conf") if p.is_file())


def resolve_wg_config_path(s: dict) -> Optional[Path]:
    cfg_dir = Path(str(s.get("wg_config_dir") or default_wg_config_dir()))
    name = str(s.get("wg_active_config") or "").strip()

    if name:
        primary = cfg_dir / name
        if primary.exists() and primary.is_file():
            return primary
        as_path = Path(name)
        if as_path.exists() and as_path.is_file():
            return as_path

    candidates = list_wg_configs(s)
    if candidates:
        s["wg_active_config"] = candidates[0]
        save_state(s)
        return cfg_dir / candidates[0]
    return None


def state_default() -> dict:
    state = dict(DEFAULTS)
    ip, iface = detect_lan_candidate()
    state["lan_ip"] = ip
    state["lan_iface"] = iface
    state["uuid"] = random_uuid()
    state["pid"] = None
    return state


def load_state() -> dict:
    ensure_runtime()
    if not STATE_FILE.exists():
        state = state_default()
        save_state(state)
        return state

    try:
        with STATE_FILE.open("r", encoding="utf-8") as f:
            state = json.load(f)
    except Exception:
        state = state_default()

    for key, value in DEFAULTS.items():
        state.setdefault(key, value)

    if not state.get("lan_ip"):
        ip, iface = detect_lan_candidate()
        state["lan_ip"] = ip
        state["lan_iface"] = iface
    elif not state.get("lan_iface"):
        matched_iface = ""
        for iface, ip in list_interface_ipv4s():
            if ip == state["lan_ip"]:
                matched_iface = iface
                break
        state["lan_iface"] = matched_iface or "manual"
    if not state.get("uuid"):
        state["uuid"] = random_uuid()
    if state.get("engine") not in {"xray", "wireproxy"}:
        state["engine"] = "xray"
    try:
        state["wireproxy_mtu"] = int(state.get("wireproxy_mtu") or 1280)
    except Exception:
        state["wireproxy_mtu"] = 1280
    if state["wireproxy_mtu"] < 576:
        state["wireproxy_mtu"] = 576
    strategy = str(state.get("wireproxy_resolve_strategy") or "ipv4").strip().lower()
    if strategy not in {"auto", "ipv4", "ipv6"}:
        strategy = "ipv4"
    state["wireproxy_resolve_strategy"] = strategy
    uplink_iface = str(state.get("wireproxy_uplink_iface") or "auto").strip()
    state["wireproxy_uplink_iface"] = uplink_iface or "auto"
    route_mode = str(state.get("wireproxy_route_mode") or "auto").strip().lower()
    if route_mode not in {"auto", "off"}:
        route_mode = "auto"
    state["wireproxy_route_mode"] = route_mode
    state["wireproxy_route_active_endpoint_ip"] = str(
        state.get("wireproxy_route_active_endpoint_ip") or ""
    ).strip()
    state["wireproxy_route_active_gateway"] = str(
        state.get("wireproxy_route_active_gateway") or ""
    ).strip()
    state["wireproxy_block_start"] = bool(state.get("wireproxy_block_start", False))
    state["wireproxy_allow_nested_vpn"] = bool(
        state.get("wireproxy_allow_nested_vpn", False)
    )
    ui_mode = str(state.get("ui_mode") or "simple").strip().lower()
    if ui_mode not in {"simple", "full"}:
        ui_mode = "simple"
    state["ui_mode"] = ui_mode

    return state


def save_state(state: dict) -> None:
    ensure_runtime()
    with STATE_FILE.open("w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=True, indent=2)


def build_xray_config(state: dict) -> dict:
    listen_host = state["listen_host"]
    socks_port = int(state["socks_port"])
    http_port = int(state["http_port"])
    socks_alt = int(state["socks_alt_port"])
    http_alt = int(state["http_alt_port"])
    dns_port = int(state["dns_port"])
    vless_port = int(state["vless_port"])
    clients = collect_vless_clients(state)
    if not clients:
        clients = [{"id": random_uuid()}]
    vless_ports = collect_vless_ports(state)
    if not vless_ports:
        vless_ports = [vless_port]

    # Ordered fallback DNS pool (primary -> secondary ...).
    dns_servers = XRAY_FALLBACK_DNS_SERVERS
    dns_forward_target = "1.1.1.1"

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
            "settings": {
                "address": dns_forward_target,
                "port": 53,
                "network": "tcp,udp",
            },
        },
        {
            "tag": "in-vless",
            "listen": listen_host,
            "port": vless_ports[0],
            "protocol": "vless",
            "settings": {"decryption": "none", "clients": clients},
            "streamSettings": {"network": "tcp", "security": "none"},
        }
    ]

    for extra_port in vless_ports[1:]:
        inbounds.append(
            {
                "tag": f"in-vless-{extra_port}",
                "listen": listen_host,
                "port": extra_port,
                "protocol": "vless",
                "settings": {"decryption": "none", "clients": clients},
                "streamSettings": {"network": "tcp", "security": "none"},
            }
        )

    vless_tags = [item["tag"] for item in inbounds if item["tag"].startswith("in-vless")]

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "dns-out", "protocol": "dns", "settings": {}},
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {"domainStrategy": "UseIPv4"},
            },
        ],
        "dns": {
            "queryStrategy": "UseIPv4",
            "hosts": XRAY_DOH_BOOTSTRAP_HOSTS,
            "servers": dns_servers,
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "inboundTag": ["in-dns"], "outboundTag": "direct"},
                {
                    "type": "field",
                    "inboundTag": [
                        "in-socks",
                        "in-http",
                        "in-socks-alt",
                        "in-http-alt",
                        *vless_tags,
                    ],
                    "outboundTag": "direct",
                },
            ],
        },
    }


def write_xray_config(state: dict) -> None:
    with XRAY_CONFIG_FILE.open("w", encoding="utf-8") as f:
        json.dump(build_xray_config(state), f, ensure_ascii=True, indent=2)


def wireproxy_section_auth_lines(state: dict) -> list[str]:
    user = str(state.get("proxy_username") or "").strip()
    password = str(state.get("proxy_password") or "").strip()
    if not user or not password:
        return []
    return [f"Username = {user}", f"Password = {password}"]


def normalize_dns_csv(raw: str) -> str:
    items: list[str] = []
    for part in raw.split(","):
        val = part.strip()
        if not val:
            continue
        items.append(val)
    return ",".join(items)


def normalize_resolve_strategy(raw: str) -> str:
    value = raw.strip().lower()
    if value in {"auto", "ipv4", "ipv6"}:
        return value
    return ""


def build_wireproxy_wg_config(state: dict, wg_conf_path: Path) -> Path:
    try:
        mtu_value = int(state.get("wireproxy_mtu") or 1280)
    except Exception:
        mtu_value = 1280
    if mtu_value < 576:
        mtu_value = 576
    lines = wg_conf_path.read_text(encoding="utf-8", errors="replace").splitlines()

    profile_dns_items: list[str] = []
    out: list[str] = []
    in_interface = False
    dns_written = False
    mtu_written = False

    for line in lines:
        stripped = line.strip()
        is_section = stripped.startswith("[") and stripped.endswith("]")
        if is_section:
            in_interface = stripped.lower() == "[interface]"
            continue
        if in_interface and stripped.lower().startswith("dns"):
            _k, _eq, rest = line.partition("=")
            value = rest.strip()
            if value:
                for part in value.split(","):
                    item = part.strip()
                    if item and item not in profile_dns_items:
                        profile_dns_items.append(item)

    requested_dns = normalize_dns_csv(str(state.get("wireproxy_dns") or ""))
    merged_dns: list[str] = []
    if requested_dns:
        for part in requested_dns.split(","):
            item = part.strip()
            if item and item not in merged_dns:
                merged_dns.append(item)
    else:
        # Tunnel-first behavior: keep WG profile DNS first, then chain fallbacks.
        for item in profile_dns_items:
            if item and item not in merged_dns:
                merged_dns.append(item)
        for item in FALLBACK_DNS_IPS:
            if item and item not in merged_dns:
                merged_dns.append(item)
    dns_csv = ",".join(merged_dns)
    in_interface = False

    for line in lines:
        stripped = line.strip()
        is_section = stripped.startswith("[") and stripped.endswith("]")

        if is_section:
            if in_interface and not dns_written and dns_csv:
                out.append(f"DNS = {dns_csv}")
                dns_written = True
            if in_interface and not mtu_written:
                out.append(f"MTU = {mtu_value}")
                mtu_written = True
            in_interface = stripped.lower() == "[interface]"
            out.append(line)
            continue

        if in_interface and stripped.lower().startswith("dns"):
            if not dns_written and dns_csv:
                out.append(f"DNS = {dns_csv}")
                dns_written = True
            continue

        if in_interface and stripped.lower().startswith("mtu"):
            if not mtu_written:
                out.append(f"MTU = {mtu_value}")
                mtu_written = True
            continue

        out.append(line)

    if in_interface and not dns_written and dns_csv:
        out.append(f"DNS = {dns_csv}")
    if in_interface and not mtu_written:
        out.append(f"MTU = {mtu_value}")

    WIREPROXY_WG_ACTIVE_FILE.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
    return WIREPROXY_WG_ACTIVE_FILE


def write_wireproxy_config(state: dict, wg_conf_path: Path) -> None:
    auth = wireproxy_section_auth_lines(state)
    runtime_wg_conf = build_wireproxy_wg_config(state, wg_conf_path)
    lines = [
        f"WGConfig = {runtime_wg_conf}",
        "",
        "[Socks5]",
        f"BindAddress = {state['listen_host']}:{int(state['socks_port'])}",
    ]
    lines.extend(auth)
    lines.extend(
        [
            "",
            "[http]",
            f"BindAddress = {state['listen_host']}:{int(state['http_port'])}",
        ]
    )
    lines.extend(auth)
    resolve_strategy = normalize_resolve_strategy(
        str(state.get("wireproxy_resolve_strategy") or "ipv4")
    )
    lines.extend(
        [
            "",
            "[Resolve]",
            f"ResolveStrategy = {resolve_strategy or 'ipv4'}",
            "",
        ]
    )
    WIREPROXY_CONF_FILE.write_text("\n".join(lines), encoding="utf-8")


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


def find_pids_by_pattern(pattern: str) -> list[int]:
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", pattern],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except Exception:
        return []

    pids: list[int] = []
    for raw in out.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            pids.append(int(raw))
        except ValueError:
            continue
    return pids


def probe_listen_port(port: int) -> bool:
    if port <= 0:
        return False
    try:
        out = subprocess.check_output(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return bool(out.strip())
    except Exception:
        return False


def expected_process_pattern(state: dict) -> str:
    if state["engine"] == "wireproxy":
        return f"{wireproxy_binary_path()} -c {WIREPROXY_CONF_FILE}"
    return f"{xray_binary_path()} run -c {XRAY_CONFIG_FILE}"


def is_service_running(state: dict) -> bool:
    pid = state.get("pid")
    if pid_alive(pid):
        return True

    pattern = expected_process_pattern(state)
    matched = [p for p in find_pids_by_pattern(pattern) if p != os.getpid()]
    if matched:
        state["pid"] = matched[0]
        save_state(state)
        return True

    # For wireproxy, use listener probe as additional runtime signal.
    if state["engine"] == "wireproxy":
        socks_on = probe_listen_port(int(state.get("socks_port") or 0))
        http_on = probe_listen_port(int(state.get("http_port") or 0))
        return socks_on and http_on

    return False


def stop_service(state: dict) -> None:
    pid = state.get("pid")
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

    pattern = expected_process_pattern(state)
    for extra_pid in find_pids_by_pattern(pattern):
        if extra_pid == os.getpid():
            continue
        try:
            if is_windows():
                subprocess.run(["taskkill", "/PID", str(extra_pid), "/F"], check=False)
            else:
                os.kill(extra_pid, signal.SIGTERM)
        except Exception:
            pass
    clear_wireproxy_endpoint_route(state)
    state["pid"] = None
    save_state(state)


def start_xray_service(state: dict) -> None:
    ensure_runtime()
    xray = ensure_xray_binary()
    stop_service(state)
    write_xray_config(state)

    log_file = XRAY_LOG_FILE.open("a", encoding="utf-8")
    cmd = [str(xray), "run", "-c", str(XRAY_CONFIG_FILE)]
    creationflags = 0
    if is_windows():
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS

    proc = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        cwd=str(ROOT),
        creationflags=creationflags,
        start_new_session=(not is_windows()),
    )
    state["pid"] = int(proc.pid)
    save_state(state)
    time.sleep(1.0)


def start_wireproxy_service(state: dict) -> None:
    ensure_runtime()
    wireproxy = ensure_wireproxy_binary(state)
    wg_conf = resolve_wg_config_path(state)
    if wg_conf is None:
        raise RuntimeError(
            "No WireGuard .conf found. Set WG config dir and add at least one .conf file."
        )
    stop_service(state)
    write_wireproxy_config(state, wg_conf)
    ensure_wireproxy_endpoint_route(state, wg_conf)

    log_file = WIREPROXY_LOG_FILE.open("a", encoding="utf-8")
    cmd = [str(wireproxy), "-c", str(WIREPROXY_CONF_FILE)]
    creationflags = 0
    if is_windows():
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS

    proc = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        cwd=str(ROOT),
        creationflags=creationflags,
        start_new_session=(not is_windows()),
    )
    pattern = expected_process_pattern(state)
    matched = [p for p in find_pids_by_pattern(pattern) if p != os.getpid()]
    state["pid"] = int(matched[0]) if matched else int(proc.pid)
    save_state(state)
    time.sleep(1.0)


def start_service(state: dict) -> None:
    if state["engine"] == "xray":
        start_xray_service(state)
    elif state["engine"] == "wireproxy":
        start_wireproxy_service(state)
    else:
        raise RuntimeError(f"Unsupported engine: {state['engine']}")


def restart_service(state: dict) -> None:
    stop_service(state)
    start_service(state)


def quick_http_test(state: dict, use_alt: bool = False) -> str:
    if state["engine"] == "wireproxy":
        port = int(state["http_port"])
        label = "wireproxy"
    else:
        port = int(state["http_alt_port"] if use_alt else state["http_port"])
        label = "xray-alt" if use_alt else "xray"

    proxy = f"http://{state['lan_ip']}:{port}"
    try:
        cmd = ["curl", "--max-time", "10", "-x", proxy, "https://api.ipify.org"]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return f"{label}: {out.strip()}"
    except Exception as exc:
        return f"HTTP test failed on {proxy}: {exc}"


def active_log_path(state: dict) -> Path:
    return WIREPROXY_LOG_FILE if state["engine"] == "wireproxy" else XRAY_LOG_FILE


def tail_log(state: dict, lines: int = 80) -> str:
    path = active_log_path(state)
    if not path.exists():
        return f"No log yet ({path.name})."
    try:
        data = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(data[-lines:])
    except Exception as exc:
        return f"Failed to read log: {exc}"


def connected_system_vpn_name() -> str:
    if is_windows():
        return ""
    try:
        out = subprocess.check_output(
            ["scutil", "--nc", "list"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in out.splitlines():
            if "(Connected)" not in line:
                continue
            if '"' not in line:
                continue
            return line.split('"')[1].strip()
    except Exception:
        return ""
    return ""


def parse_wg_endpoint(wg_conf_path: Path) -> Optional[tuple[str, int]]:
    in_peer = False
    try:
        for raw in wg_conf_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                in_peer = line.lower() == "[peer]"
                continue
            if not in_peer:
                continue
            key, sep, value = line.partition("=")
            if not sep:
                continue
            if key.strip().lower() != "endpoint":
                continue
            endpoint = value.strip()
            host, port = endpoint.rsplit(":", 1)
            return host.strip(), int(port.strip())
    except Exception:
        return None
    return None


def resolve_endpoint_ip(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except Exception:
        pass

    timeout_before = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(1.5)
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
        for item in infos:
            ip = item[4][0]
            if ip:
                return ip
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(timeout_before)
    return ""


def route_interface_for_destination(ip: str) -> str:
    if not ip or is_windows():
        return ""
    try:
        if platform.system().lower().startswith("darwin"):
            out = subprocess.check_output(
                ["route", "-n", "get", ip],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in out.splitlines():
                stripped = line.strip()
                if stripped.lower().startswith("interface:"):
                    return stripped.split(":", 1)[1].strip()
            return ""

        out = subprocess.check_output(
            ["ip", "route", "get", ip],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        parts = out.split()
        for i, tok in enumerate(parts):
            if tok == "dev" and i + 1 < len(parts):
                return parts[i + 1].strip()
    except Exception:
        return ""
    return ""


def choose_wireproxy_uplink_iface(state: dict) -> str:
    selected = str(state.get("wireproxy_uplink_iface") or "auto").strip()
    if selected and selected != "auto":
        return selected
    iface = str(state.get("lan_iface") or "").strip()
    if not iface or iface.startswith("utun"):
        return "en0"
    return iface


def run_macos_route_cmd(route_args: list[str], allow_prompt: bool = True) -> bool:
    base = ["route", "-n"] + route_args

    # Try non-interactive sudo first.
    rc = subprocess.run(["sudo", "-n"] + base, check=False).returncode
    if rc == 0:
        return True

    if not allow_prompt:
        return False

    # Try interactive terminal sudo.
    rc = subprocess.run(["sudo"] + base, check=False).returncode
    if rc == 0:
        return True

    # Fallback for GUI launches (macOS password prompt).
    cmd_str = " ".join(shlex.quote(part) for part in base)
    apple = f"do shell script {json.dumps(cmd_str)} with administrator privileges"
    rc = subprocess.run(["osascript", "-e", apple], check=False).returncode
    return rc == 0


def ensure_wireproxy_endpoint_route(state: dict, wg_conf_path: Path) -> None:
    if platform.system().lower() != "darwin":
        return
    if str(state.get("wireproxy_route_mode") or "auto") == "off":
        return

    endpoint = parse_wg_endpoint(wg_conf_path)
    if endpoint is None:
        return
    host, _port = endpoint
    endpoint_ip = resolve_endpoint_ip(host)
    if not endpoint_ip:
        return

    iface = choose_wireproxy_uplink_iface(state)
    gateway = gateway_for_iface_macos(iface)
    if not gateway:
        return

    current_iface = route_interface_for_destination(endpoint_ip)
    if current_iface == iface:
        state["wireproxy_route_active_endpoint_ip"] = endpoint_ip
        state["wireproxy_route_active_gateway"] = gateway
        save_state(state)
        return

    ok = run_macos_route_cmd(["add", "-host", endpoint_ip, gateway], allow_prompt=True)
    if not ok:
        ok = run_macos_route_cmd(["change", "-host", endpoint_ip, gateway], allow_prompt=True)
    if not ok:
        print(
            "Warning    : failed to pin endpoint route to selected interface."
            f" endpoint={endpoint_ip} iface={iface} gateway={gateway}"
        )
        return

    state["wireproxy_route_active_endpoint_ip"] = endpoint_ip
    state["wireproxy_route_active_gateway"] = gateway
    save_state(state)
    print(f"Route pin   : endpoint {endpoint_ip} -> {iface} via {gateway}")


def clear_wireproxy_endpoint_route(state: dict) -> None:
    endpoint_ip = str(state.get("wireproxy_route_active_endpoint_ip") or "").strip()
    state["wireproxy_route_active_endpoint_ip"] = ""
    state["wireproxy_route_active_gateway"] = ""
    if not endpoint_ip:
        return
    if platform.system().lower() != "darwin":
        return
    run_macos_route_cmd(["delete", "-host", endpoint_ip], allow_prompt=False)


def wireproxy_endpoint_diag(state: dict) -> dict:
    if state.get("engine") != "wireproxy":
        return {}
    wg_conf = resolve_wg_config_path(state)
    if wg_conf is None:
        return {}
    endpoint = parse_wg_endpoint(wg_conf)
    if endpoint is None:
        return {}
    host, port = endpoint
    ip = resolve_endpoint_ip(host)
    return {
        "endpoint_host": host,
        "endpoint_port": port,
        "endpoint_ip": ip,
        "route_iface": route_interface_for_destination(ip) if ip else "",
    }


def wireproxy_preflight_issues(state: dict, wg_conf_path: Path) -> list[str]:
    issues: list[str] = []
    endpoint = parse_wg_endpoint(wg_conf_path)
    endpoint_ip = ""
    route_iface = ""
    if endpoint is not None:
        endpoint_ip = resolve_endpoint_ip(endpoint[0])
        if endpoint_ip:
            route_iface = route_interface_for_destination(endpoint_ip)

    sys_vpn = connected_system_vpn_name()
    if sys_vpn and wg_conf_path.stem == sys_vpn:
        issues.append("same profile name is active on system VPN and wireproxy")

    if route_iface.startswith("utun"):
        issues.append(f"wireproxy endpoint route is inside VPN interface ({route_iface})")
    return issues


def gateway_for_iface_macos(iface: str) -> str:
    try:
        out = subprocess.check_output(
            ["route", "-n", "get", "default", "-ifscope", iface],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("gateway:"):
                return stripped.split(":", 1)[1].strip()
    except Exception:
        return ""
    return ""


def run_wireproxy_direct_path_test(state: dict) -> None:
    if state.get("engine") != "wireproxy":
        print("This test is only for wireproxy mode.")
        return
    if platform.system().lower() != "darwin":
        print("This temporary direct-path test is currently implemented for macOS.")
        return

    diag = wireproxy_endpoint_diag(state)
    if not diag:
        print("Could not read active WireGuard endpoint.")
        return
    endpoint_ip = str(diag.get("endpoint_ip") or "").strip()
    if not endpoint_ip:
        print("Could not resolve endpoint IP. Try again when DNS is up.")
        return

    iface = choose_wireproxy_uplink_iface(state)

    gateway = gateway_for_iface_macos(iface)
    if not gateway:
        print(f"Could not find gateway for interface {iface}.")
        print("Set another uplink interface or use auto.")
        return

    current_route = str(diag.get("route_iface") or "-")
    print(f"Endpoint IP: {endpoint_ip}")
    print(f"Current route iface: {current_route}")
    print(f"Temporary target iface: {iface} (gateway {gateway})")
    confirm = input("Run one-shot direct test now? [y/N]: ").strip().lower()
    if confirm not in {"y", "yes"}:
        print("Canceled.")
        return

    print("Before temp route:")
    print(quick_http_test(state))

    route_set = False
    try:
        add_cmd = ["sudo", "route", "-n", "add", "-host", endpoint_ip, gateway]
        change_cmd = ["sudo", "route", "-n", "change", "-host", endpoint_ip, gateway]
        rc = subprocess.run(add_cmd, check=False).returncode
        if rc != 0:
            rc = subprocess.run(change_cmd, check=False).returncode
        if rc != 0:
            print("Failed to set temporary route.")
            print("Try manually:")
            print(f"sudo route -n add -host {endpoint_ip} {gateway}")
            return
        route_set = True

        restart_service(state)
        print("After temp route:")
        print(quick_http_test(state))
        print(quick_http_test(state))
    finally:
        if route_set:
            subprocess.run(
                ["sudo", "route", "-n", "delete", "-host", endpoint_ip],
                check=False,
            )
            try:
                restart_service(state)
            except Exception as exc:
                print(f"Restart after cleanup failed: {exc}")


def show_status(state: dict, compact: bool = False) -> None:
    alive = is_service_running(state)
    if compact:
        print(
            f"engine:{state['engine']} status:{'ON' if alive else 'OFF'} "
            f"pid:{state.get('pid') or '-'}"
        )
        print(
            f"LAN:{state['lan_ip']} ({state.get('lan_iface') or '-'}) "
            f"listen:{state['listen_host']}"
        )
        print(f"SOCKS:{state['lan_ip']}:{state['socks_port']}")
        print(f"HTTP :{state['lan_ip']}:{state['http_port']}")
        if state["engine"] == "xray":
            print(f"ALT  :{state['lan_ip']}:{state['http_alt_port']} (HTTP ALT)")
        else:
            auth_on = bool(
                str(state.get("proxy_username") or "").strip()
                and str(state.get("proxy_password") or "").strip()
            )
            wg_conf = resolve_wg_config_path(state)
            wg_label = wg_conf.name if wg_conf else "not selected"
            print(f"WG   :{wg_label} | Auth:{'on' if auth_on else 'off'}")
            sys_vpn = connected_system_vpn_name()
            if sys_vpn:
                print(f"VPN  :system connected -> {sys_vpn}")
            diag = wireproxy_endpoint_diag(state)
            if diag and diag.get("route_iface"):
                print(f"EP   :{diag['endpoint_ip']} via {diag['route_iface']}")
        return

    print(f"engine     : {state['engine']}")
    print(f"status     : {'ON' if alive else 'OFF'}")
    print(f"running    : {alive} (pid={state.get('pid')})")
    print(f"LAN IP     : {state['lan_ip']}")
    print(f"LAN iface  : {state.get('lan_iface') or '-'}")
    print(f"listen host: {state['listen_host']}")

    if state["engine"] == "xray":
        print(f"xray bin   : {xray_binary_path()}")
        print(f"SOCKS      : {state['lan_ip']}:{state['socks_port']}")
        print(f"HTTP       : {state['lan_ip']}:{state['http_port']}")
        print(f"SOCKS ALT  : {state['lan_ip']}:{state['socks_alt_port']}")
        print(f"HTTP ALT   : {state['lan_ip']}:{state['http_alt_port']}")
        print(f"DNS        : {state['lan_ip']}:{state['dns_port']}")
        print("Mode       : shares current system route/VPN")
    else:
        auth_on = bool(
            str(state.get("proxy_username") or "").strip()
            and str(state.get("proxy_password") or "").strip()
        )
        wg_conf = resolve_wg_config_path(state)
        print(f"wireproxy  : {wireproxy_binary_path()}")
        print(f"WG dir     : {state['wg_config_dir']}")
        print(f"WG active  : {wg_conf if wg_conf else 'not selected'}")
        wg_dns_label = str(state.get("wireproxy_dns") or "").strip()
        if not wg_dns_label:
            wg_dns_label = "profile-first + fallback chain"
        print(f"WG DNS     : {wg_dns_label}")
        print(f"WG MTU     : {state.get('wireproxy_mtu')}")
        print(f"Resolve    : {state.get('wireproxy_resolve_strategy')}")
        print(f"Uplink IF  : {state.get('wireproxy_uplink_iface')}")
        print(f"Route mode : {state.get('wireproxy_route_mode')}")
        print(f"Start lock : {'ON' if state.get('wireproxy_block_start') else 'OFF'}")
        print(
            "Nested ok  : "
            + ("ON" if state.get("wireproxy_allow_nested_vpn") else "OFF")
        )
        pinned_ip = str(state.get("wireproxy_route_active_endpoint_ip") or "").strip()
        if pinned_ip:
            print(f"Route pin  : {pinned_ip} via {state.get('wireproxy_route_active_gateway')}")
        print(f"SOCKS      : {state['lan_ip']}:{state['socks_port']}")
        print(f"HTTP       : {state['lan_ip']}:{state['http_port']}")
        print(f"Auth       : {'enabled' if auth_on else 'disabled'}")
        diag = wireproxy_endpoint_diag(state)
        if diag:
            ep_host = str(diag.get("endpoint_host") or "-")
            ep_port = str(diag.get("endpoint_port") or "-")
            ep_ip = str(diag.get("endpoint_ip") or "-")
            route_iface = str(diag.get("route_iface") or "-")
            print(f"Endpoint   : {ep_host}:{ep_port} -> {ep_ip}")
            print(f"EP route   : {route_iface}")
        sys_vpn = connected_system_vpn_name()
        if sys_vpn:
            print(f"System VPN : connected ({sys_vpn})")
            if wg_conf and wg_conf.stem == sys_vpn:
                print("Warning    : same profile is connected on system; wireproxy may conflict.")
            if diag and str(diag.get("route_iface") or "").startswith("utun"):
                print("Warning    : WG endpoint route is inside system VPN (utun).")
                print("             Use one-shot direct path test to verify en0 path.")
        print("Mode       : independent WireGuard client via wireproxy")


def show_legal_notice() -> None:
    print("License: MIT")
    print("Copyright (c) 2026 contributors")
    print("Third-party: Xray-core and wireproxy use their own upstream licenses.")
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


def configure_engine(state: dict) -> None:
    current = state["engine"]
    print(f"Current engine: {current}")
    print("1) xray (share current system route/VPN)")
    print("2) wireproxy (independent WireGuard tunnel)")
    choice = input("Select engine [1-2]: ").strip()

    target = current
    if choice == "1":
        target = "xray"
    elif choice == "2":
        target = "wireproxy"

    if target != current:
        stop_service(state)
        state["engine"] = target
        save_state(state)
        print(f"Engine switched to: {target}")
    else:
        print("No change.")


def configure_lan_ip(state: dict) -> None:
    print(f"Current LAN IP: {state['lan_ip']}")
    print(f"Current iface : {state.get('lan_iface') or '-'}")

    candidates = list_interface_ipv4s()
    if candidates:
        print("Detected interface IPv4 addresses:")
        for idx, (iface, ip) in enumerate(candidates, start=1):
            print(f"{idx}) {iface} -> {ip}")
        print("a) Auto-detect best")
        print("m) Manual entry")
        print("x) Cancel")
        choice = input("Select interface/IP [1-n|a|m|x]: ").strip().lower()

        if choice in {"", "a"}:
            ip, iface = detect_lan_candidate()
            state["lan_ip"] = ip
            state["lan_iface"] = iface
            save_state(state)
            print(f"LAN IP set to: {ip} ({iface})")
            return

        if choice == "x":
            print("No change.")
            return

        if choice == "m":
            manual = input("Enter LAN IP: ").strip()
            if not manual:
                print("No change.")
                return
            try:
                ipaddress.ip_address(manual)
            except Exception:
                print("Invalid IP address.")
                return
            state["lan_ip"] = manual
            state["lan_iface"] = "manual"
            save_state(state)
            print(f"LAN IP set to: {manual} (manual)")
            return

        if choice.isdigit():
            i = int(choice)
            if 1 <= i <= len(candidates):
                iface, ip = candidates[i - 1]
                state["lan_ip"] = ip
                state["lan_iface"] = iface
                save_state(state)
                print(f"LAN IP set to: {ip} ({iface})")
                return

        print("Invalid choice.")
        return

    print("No interface IP detected. Falling back to manual/auto.")
    new_ip = input("Enter LAN IP (empty to auto-detect): ").strip()
    if new_ip:
        try:
            ipaddress.ip_address(new_ip)
        except Exception:
            print("Invalid IP address.")
            return
        state["lan_ip"] = new_ip
        state["lan_iface"] = "manual"
    else:
        ip, iface = detect_lan_candidate()
        state["lan_ip"] = ip
        state["lan_iface"] = iface
    save_state(state)
    print(f"LAN IP set to: {state['lan_ip']} ({state.get('lan_iface')})")


def configure_listen_host(state: dict) -> None:
    print(f"Current listen host: {state['listen_host']}")
    print("Tip: use 0.0.0.0 for LAN-wide access")
    new_host = input("Enter listen host: ").strip()
    if not new_host:
        print("No change.")
        return
    state["listen_host"] = new_host
    save_state(state)
    print(f"Listen host set to: {new_host}")


def read_int(prompt: str, current: int) -> int:
    raw = input(f"{prompt} [{current}]: ").strip()
    if not raw:
        return current
    value = int(raw)
    if value <= 0 or value > 65535:
        raise ValueError("Port must be in range 1..65535")
    return value


def configure_ports(state: dict) -> None:
    print("Set ports (press Enter to keep current value)")
    state["socks_port"] = read_int("SOCKS port", int(state["socks_port"]))
    state["http_port"] = read_int("HTTP port", int(state["http_port"]))
    if state["engine"] == "xray":
        state["socks_alt_port"] = read_int("SOCKS alt port", int(state["socks_alt_port"]))
        state["http_alt_port"] = read_int("HTTP alt port", int(state["http_alt_port"]))
    save_state(state)
    print("Ports updated.")


def configure_wireguard_profile(state: dict) -> None:
    print(f"Current WG config dir: {state['wg_config_dir']}")
    print(f"Current active config: {state.get('wg_active_config') or '-'}")
    print("1) Select from current dir")
    print("2) Change WG config dir")
    choice = input("Select [1-2]: ").strip()

    if choice == "2":
        new_dir = input("Enter WG config directory path: ").strip()
        if not new_dir:
            print("No change.")
            return
        path = Path(new_dir).expanduser().resolve()
        if not path.exists() or not path.is_dir():
            print("Directory not found.")
            return
        state["wg_config_dir"] = str(path)
        save_state(state)

    configs = list_wg_configs(state)
    if not configs:
        print("No .conf files found in WG config dir.")
        return

    print("Available .conf files:")
    for idx, name in enumerate(configs, start=1):
        print(f"{idx}) {name}")

    selected = input(f"Select config [1-{len(configs)}]: ").strip()
    if not selected.isdigit():
        print("No change.")
        return

    i = int(selected)
    if i < 1 or i > len(configs):
        print("Invalid index.")
        return

    state["wg_active_config"] = configs[i - 1]
    save_state(state)
    print(f"Active WG config set: {state['wg_active_config']}")


def configure_proxy_auth(state: dict) -> None:
    print("wireproxy SOCKS/HTTP auth")
    print("Leave username empty to disable auth.")
    current_user = str(state.get("proxy_username") or "")
    user = input(f"Username [{current_user or '-'}]: ").strip()
    if not user:
        state["proxy_username"] = ""
        state["proxy_password"] = ""
        save_state(state)
        print("Auth disabled.")
        return

    password = getpass.getpass("Password: ").strip()
    if not password:
        print("Password empty, auth not changed.")
        return

    state["proxy_username"] = user
    state["proxy_password"] = password
    save_state(state)
    print("Auth enabled. Restart service to apply.")


def configure_wireproxy_dns(state: dict) -> None:
    print("Wireproxy DNS servers (comma-separated)")
    print("Example: 178.22.122.100,185.51.200.2")
    print("Type 'default' to use profile DNS first + fallback chain.")
    current = str(state.get("wireproxy_dns") or "")
    shown = current or "default: profile-first + fallback chain"
    new_value = input(f"DNS servers [{shown}]: ").strip()
    if not new_value:
        print("No change.")
        return
    if new_value.lower() in {"default", "chain", "auto", "reset", "inherit", "profile", "wg"}:
        state["wireproxy_dns"] = ""
        save_state(state)
        print("Wireproxy DNS set to: profile-first + fallback chain")
        print("Restart service to apply.")
        return
    normalized = normalize_dns_csv(new_value)
    if not normalized:
        print("Invalid DNS list.")
        return
    state["wireproxy_dns"] = normalized
    save_state(state)
    print(f"Wireproxy DNS set to: {normalized}")
    print("Restart service to apply.")


def configure_wireproxy_mtu(state: dict) -> None:
    current = int(state.get("wireproxy_mtu") or 1280)
    print("Wireproxy MTU")
    print("Tip: for nested tunnels, 1200-1280 is often more stable.")
    raw = input(f"MTU [{current}]: ").strip()
    if not raw:
        print("No change.")
        return
    value = int(raw)
    if value < 576 or value > 1500:
        print("Invalid MTU. Use 576..1500")
        return
    state["wireproxy_mtu"] = value
    save_state(state)
    print(f"Wireproxy MTU set to: {value}")
    print("Restart service to apply.")


def configure_wireproxy_resolve_strategy(state: dict) -> None:
    current = str(state.get("wireproxy_resolve_strategy") or "ipv4")
    print("Wireproxy resolve strategy")
    print("1) auto")
    print("2) ipv4")
    print("3) ipv6")
    choice = input(f"Select [1-3] (current={current}): ").strip()
    mapping = {"1": "auto", "2": "ipv4", "3": "ipv6"}
    target = mapping.get(choice)
    if not target:
        print("No change.")
        return
    state["wireproxy_resolve_strategy"] = target
    save_state(state)
    print(f"Resolve strategy set to: {target}")
    print("Restart service to apply.")


def configure_wireproxy_uplink_iface(state: dict) -> None:
    current = str(state.get("wireproxy_uplink_iface") or "auto").strip() or "auto"
    iface_order: list[str] = []
    seen: set[str] = set()
    for iface, _ip in list_interface_ipv4s():
        if iface in seen:
            continue
        seen.add(iface)
        iface_order.append(iface)

    print("Wireproxy uplink interface (for direct-path test)")
    print(f"Current: {current}")
    print("a) auto")
    for idx, iface in enumerate(iface_order, start=1):
        print(f"{idx}) {iface}")
    print("x) cancel")
    choice = input("Select [a|1-n|x]: ").strip().lower()
    if choice in {"", "x"}:
        print("No change.")
        return
    if choice == "a":
        state["wireproxy_uplink_iface"] = "auto"
        save_state(state)
        print("Uplink interface set to: auto")
        return
    if not choice.isdigit():
        print("Invalid choice.")
        return
    i = int(choice)
    if i < 1 or i > len(iface_order):
        print("Invalid index.")
        return
    state["wireproxy_uplink_iface"] = iface_order[i - 1]
    save_state(state)
    print(f"Uplink interface set to: {state['wireproxy_uplink_iface']}")


def configure_wireproxy_route_mode(state: dict) -> None:
    current = str(state.get("wireproxy_route_mode") or "auto")
    print("Wireproxy endpoint route pinning")
    print("1) auto (pin endpoint route to uplink interface)")
    print("2) off  (do not modify route table)")
    choice = input(f"Select [1-2] (current={current}): ").strip()
    if choice == "1":
        state["wireproxy_route_mode"] = "auto"
    elif choice == "2":
        state["wireproxy_route_mode"] = "off"
    else:
        print("No change.")
        return
    save_state(state)
    print(f"Route mode set to: {state['wireproxy_route_mode']}")
    print("Restart service to apply.")


def menu() -> None:
    state = load_state()

    def start_or_restart() -> None:
        if is_service_running(state):
            restart_service(state)
            print("Restarted.")
        else:
            start_service(state)
            print("Started.")

    while True:
        ensure_terminal_layout()
        clear_screen()
        term_compact = compact_view_enabled()
        simple_mode = str(state.get("ui_mode") or "simple") == "simple"
        engine = str(state.get("engine") or "xray")
        print("LAN Share Manager (Hybrid: Xray + Wireproxy)")
        print("--------------------------------------------")
        show_status(state, compact=(term_compact or simple_mode))
        if term_compact and not simple_mode:
            print("view       : compact (terminal is small)")
        print()

        if simple_mode and engine == "xray":
            print("Xray Menu (Simple)")
            print("1) Start/Restart service")
            print("2) Stop service")
            print("3) Test HTTP")
            print("4) Test HTTP ALT")
            print("5) Change LAN IP")
            print("6) Change listen host")
            print("7) Change ports")
            print("8) Select engine")
            print("9) Status (full)")
            print("l) Show active log tail")
            print("a) Advanced menu")
            print("0) Exit")
            choice = input("Select [0-9|l|a]: ").strip().lower()
        elif simple_mode and engine == "wireproxy":
            print("Wireproxy Menu (Simple)")
            print("1) Start/Restart service")
            print("2) Stop service")
            print("3) Test HTTP")
            print("4) WireGuard config")
            print("5) Wireproxy DNS servers")
            print("6) Change LAN IP")
            print("7) Change listen host")
            print("8) Change ports")
            print("9) Select engine")
            print("s) Status (full)")
            print("l) Show active log tail")
            print("a) Advanced menu")
            print("0) Exit")
            choice = input("Select [0-9|s|l|a]: ").strip().lower()
        elif (not simple_mode) and engine == "xray":
            print("Xray Menu (Advanced)")
            print("1) Select engine")
            print("2) Restart service")
            print("3) Start service")
            print("4) Stop service")
            print("5) Status")
            print("6) Test HTTP")
            print("7) Test HTTP ALT")
            print("8) Show active log tail")
            print("9) Change LAN IP")
            print("10) Change listen host")
            print("11) Change ports")
            print("12) Download/Update Xray")
            print("13) About / License")
            print("m) Simple menu")
            print("0) Exit")
            choice = input("Select [0-13|m]: ").strip().lower()
        else:
            print("Wireproxy Menu (Advanced)")
            print("1) Select engine")
            print("2) Restart service")
            print("3) Start service")
            print("4) Stop service")
            print("5) Status")
            print("6) Test HTTP")
            print("7) Show active log tail")
            print("8) Change LAN IP")
            print("9) Change listen host")
            print("10) Change ports")
            print("11) WireGuard config")
            print("12) Proxy auth user/pass")
            print("13) Download/Update Wireproxy")
            print("14) Wireproxy DNS servers")
            print("15) Wireproxy MTU")
            print("16) Wireproxy resolve strategy")
            print("17) Wireproxy uplink iface")
            print("18) Wireproxy route pinning")
            print("19) One-shot direct path test (macOS)")
            print("20) About / License")
            print("m) Simple menu")
            print("0) Exit")
            choice = input("Select [0-20|m]: ").strip().lower()

        try:
            if simple_mode and engine == "xray":
                if choice == "1":
                    start_or_restart()
                elif choice == "2":
                    stop_service(state)
                    print("Stopped.")
                elif choice == "3":
                    print(quick_http_test(state, use_alt=False))
                elif choice == "4":
                    print(quick_http_test(state, use_alt=True))
                elif choice == "5":
                    configure_lan_ip(state)
                elif choice == "6":
                    configure_listen_host(state)
                elif choice == "7":
                    configure_ports(state)
                elif choice == "8":
                    configure_engine(state)
                elif choice == "9":
                    show_status(state)
                elif choice == "l":
                    print(tail_log(state))
                elif choice == "a":
                    state["ui_mode"] = "full"
                    save_state(state)
                    print("Advanced menu enabled.")
                elif choice == "0":
                    return
                else:
                    print("Invalid option")
            elif simple_mode and engine == "wireproxy":
                if choice == "1":
                    start_or_restart()
                elif choice == "2":
                    stop_service(state)
                    print("Stopped.")
                elif choice == "3":
                    print(quick_http_test(state, use_alt=False))
                elif choice == "4":
                    configure_wireguard_profile(state)
                elif choice == "5":
                    configure_wireproxy_dns(state)
                elif choice == "6":
                    configure_lan_ip(state)
                elif choice == "7":
                    configure_listen_host(state)
                elif choice == "8":
                    configure_ports(state)
                elif choice == "9":
                    configure_engine(state)
                elif choice == "s":
                    show_status(state)
                elif choice == "l":
                    print(tail_log(state))
                elif choice == "a":
                    state["ui_mode"] = "full"
                    save_state(state)
                    print("Advanced menu enabled.")
                elif choice == "0":
                    return
                else:
                    print("Invalid option")
            elif (not simple_mode) and engine == "xray":
                if choice == "1":
                    configure_engine(state)
                elif choice == "2":
                    restart_service(state)
                    print("Restarted.")
                elif choice == "3":
                    start_service(state)
                    print("Started.")
                elif choice == "4":
                    stop_service(state)
                    print("Stopped.")
                elif choice == "5":
                    show_status(state)
                elif choice == "6":
                    print(quick_http_test(state, use_alt=False))
                elif choice == "7":
                    print(quick_http_test(state, use_alt=True))
                elif choice == "8":
                    print(tail_log(state))
                elif choice == "9":
                    configure_lan_ip(state)
                elif choice == "10":
                    configure_listen_host(state)
                elif choice == "11":
                    configure_ports(state)
                elif choice == "12":
                    path = fetch_latest_xray_binary()
                    print(f"Xray ready at: {path}")
                elif choice == "13":
                    show_legal_notice()
                elif choice == "m":
                    state["ui_mode"] = "simple"
                    save_state(state)
                    print("Simple menu enabled.")
                elif choice == "0":
                    return
                else:
                    print("Invalid option")
            else:
                if choice == "1":
                    configure_engine(state)
                elif choice == "2":
                    restart_service(state)
                    print("Restarted.")
                elif choice == "3":
                    start_service(state)
                    print("Started.")
                elif choice == "4":
                    stop_service(state)
                    print("Stopped.")
                elif choice == "5":
                    show_status(state)
                elif choice == "6":
                    print(quick_http_test(state, use_alt=False))
                elif choice == "7":
                    print(tail_log(state))
                elif choice == "8":
                    configure_lan_ip(state)
                elif choice == "9":
                    configure_listen_host(state)
                elif choice == "10":
                    configure_ports(state)
                elif choice == "11":
                    configure_wireguard_profile(state)
                elif choice == "12":
                    configure_proxy_auth(state)
                elif choice == "13":
                    version = input(
                        f"Wireproxy version [{state.get('wireproxy_version', 'v1.1.2')}]: "
                    ).strip()
                    if version:
                        state["wireproxy_version"] = version
                        save_state(state)
                    path = fetch_wireproxy_binary(
                        str(state.get("wireproxy_version") or "v1.1.2")
                    )
                    print(f"Wireproxy ready at: {path}")
                elif choice == "14":
                    configure_wireproxy_dns(state)
                elif choice == "15":
                    configure_wireproxy_mtu(state)
                elif choice == "16":
                    configure_wireproxy_resolve_strategy(state)
                elif choice == "17":
                    configure_wireproxy_uplink_iface(state)
                elif choice == "18":
                    configure_wireproxy_route_mode(state)
                elif choice == "19":
                    run_wireproxy_direct_path_test(state)
                elif choice == "20":
                    show_legal_notice()
                elif choice == "m":
                    state["ui_mode"] = "simple"
                    save_state(state)
                    print("Simple menu enabled.")
                elif choice == "0":
                    return
                else:
                    print("Invalid option")
        except Exception as exc:
            print(f"Error: {exc}")

        input("\nPress Enter to continue...")


def main() -> None:
    ensure_runtime()
    if len(sys.argv) > 1 and sys.argv[1] == "--non-interactive-status":
        state = load_state()
        show_status(state)
        return
    menu()


if __name__ == "__main__":
    main()

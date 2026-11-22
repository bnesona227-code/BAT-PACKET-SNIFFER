#!/usr/bin/env python3
"""
BAT-PACKET-SNIFFER v1.3 // Zero-Dependency Live Connection & Process Traffic Inspector
- 100% Python 3 Standard Library (no pip, no psutil, no scapy required)
- Auto-free port selection (finds free port automatically if 8080 is busy)
- Automatic browser launch only AFTER the HTTP server is actively listening
- Safe HTTP/1.0 response framing with Connection: close (prevents Safari hang)
- Live cross-platform socket/process auditor (lsof/netstat + reverse DNS + risk scoring)
"""

from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import platform
import socket
import subprocess
import threading
import time
from urllib.parse import urlparse
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Tuple

state_lock = threading.Lock()
dns_cache: Dict[str, str] = {}

STATE: Dict[str, Any] = {
    "scanning": False,
    "os_name": platform.system(),
    "last_update": "—",
    "connections": [],
    "process_summary": [],
    "alerts": [],
    "logs": [],
}

SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 1337, 31337, 8443, 9001, 9050, 1080, 3389, 23, 21}

ORG_HINTS = [
    ("telegram", "Telegram Messenger"),
    ("t.me", "Telegram Messenger"),
    ("149.154.", "Telegram DC"),
    ("91.108.", "Telegram DC"),
    ("valve", "Valve / Steam"),
    ("steam", "Valve / Steam"),
    ("akamai", "Akamai CDN"),
    ("cloudflare", "Cloudflare"),
    ("104.16.", "Cloudflare"),
    ("104.17.", "Cloudflare"),
    ("104.18.", "Cloudflare"),
    ("172.67.", "Cloudflare"),
    ("1.1.1.", "Cloudflare DNS"),
    ("1e100.net", "Google / YouTube"),
    ("google", "Google"),
    ("8.8.8.", "Google DNS"),
    ("amazonaws", "Amazon AWS"),
    ("apple", "Apple / iCloud"),
    ("17.", "Apple Network"),
    ("github", "GitHub"),
    ("140.82.", "GitHub"),
    ("microsoft", "Microsoft"),
    ("azure", "Microsoft Azure"),
    ("yandex", "Yandex"),
    ("vk.com", "VK / Mail.ru"),
    ("discord", "Discord"),
]


def add_log(msg: str, level: str = "INFO") -> None:
    ts = time.strftime("%H:%M:%S")
    entry = f"[{ts}] [{level}] {msg}"
    print(entry, flush=True)
    STATE["logs"].insert(0, entry)
    STATE["logs"] = STATE["logs"][:60]


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
    except Exception:
        return True


def classify_org(ip: str, hostname: str) -> str:
    if is_private_ip(ip):
        return "Local / LAN"
    hay = f"{ip} {hostname}".lower()
    for needle, label in ORG_HINTS:
        if needle in hay:
            return label
    if hostname:
        parts = hostname.rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
    return "External Host"


def resolve_ip(ip: str) -> str:
    if is_private_ip(ip):
        return "localhost" if ip.startswith("127.") else "lan-device"
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        socket.setdefaulttimeout(0.35)
        host, _, _ = socket.gethostbyaddr(ip)
        dns_cache[ip] = host
        return host
    except Exception:
        dns_cache[ip] = ""
        return ""


def get_windows_pid_map() -> Dict[str, str]:
    pid_map: Dict[str, str] = {}
    try:
        out = subprocess.check_output(["tasklist", "/FO", "CSV", "/NH"], text=True, errors="ignore", timeout=4)
        for line in out.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                pid_map[parts[1]] = parts[0]
    except Exception:
        pass
    return pid_map


def parse_connections_macos_linux() -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    try:
        out = subprocess.check_output(["lsof", "-i", "-n", "-P"], text=True, errors="ignore", timeout=5)
        for line in out.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 9:
                continue
            proc = cols[0].replace("\\x20", " ")
            pid = cols[1]
            proto = cols[7] if cols[7] in ("TCP", "UDP") else "TCP"
            name_field = cols[8]
            state = cols[9].strip("()") if len(cols) > 9 else ("LISTEN" if proto == "UDP" else "ACTIVE")

            if "->" in name_field:
                local_part, remote_part = name_field.split("->", 1)
                if ":" not in local_part or ":" not in remote_part:
                    continue
                l_ip, l_port = local_part.rsplit(":", 1)
                r_ip, r_port = remote_part.rsplit(":", 1)
                l_ip = l_ip.strip("[]")
                r_ip = r_ip.strip("[]")
                results.append({
                    "process": proc,
                    "pid": pid,
                    "proto": proto,
                    "local_ip": l_ip,
                    "local_port": l_port,
                    "remote_ip": r_ip,
                    "remote_port": r_port,
                    "state": state,
                })
    except Exception as e:
        add_log(f"Ошибка чтения lsof: {e}", "ERR")
    return results


def parse_connections_windows() -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    pid_map = get_windows_pid_map()
    try:
        out = subprocess.check_output(["netstat", "-ano"], text=True, errors="ignore", timeout=5)
        for line in out.splitlines():
            cols = line.split()
            if len(cols) < 4:
                continue
            proto = cols[0].upper()
            if proto not in ("TCP", "UDP"):
                continue
            local_addr = cols[1]
            remote_addr = cols[2]
            if proto == "TCP" and len(cols) >= 5:
                state = cols[3]
                pid = cols[4]
            else:
                state = "ACTIVE"
                pid = cols[3]

            if ":" not in remote_addr or remote_addr.startswith("0.0.0.0") or remote_addr.startswith("[::]") or remote_addr == "*:*":
                continue
            l_ip, l_port = local_addr.rsplit(":", 1)
            r_ip, r_port = remote_addr.rsplit(":", 1)
            l_ip = l_ip.strip("[]")
            r_ip = r_ip.strip("[]")
            results.append({
                "process": pid_map.get(pid, f"PID-{pid}"),
                "pid": pid,
                "proto": proto,
                "local_ip": l_ip,
                "local_port": l_port,
                "remote_ip": r_ip,
                "remote_port": r_port,
                "state": state,
            })
    except Exception as e:
        add_log(f"Ошибка чтения netstat: {e}", "ERR")
    return results


def build_block_cmd(ip: str) -> str:
    sys_name = platform.system()
    if sys_name == "Darwin":
        return f"echo 'block drop quick from any to {ip}' | sudo pfctl -ef -"
    elif sys_name == "Windows":
        return f'netsh advfirewall firewall add rule name="BAT_BLOCK_{ip}" dir=out action=block remoteip={ip}'
    return f"sudo iptables -A OUTPUT -d {ip} -j DROP"


def evaluate_risk(conn: Dict[str, Any], hostname: str, org: str) -> Tuple[str, str]:
    r_ip = conn["remote_ip"]
    try:
        r_port = int(conn["remote_port"])
    except Exception:
        r_port = 0

    if is_private_ip(r_ip):
        return ("safe", "Локальная сеть")
    if r_port in SUSPICIOUS_PORTS:
        return ("high", f"Нестандартный/чувствительный порт :{r_port}")
    if not hostname and org == "External Host" and r_port not in (80, 443):
        return ("warn", f"Прямой коннект по голому IP без PTR-записи (:{r_port})")
    if r_port not in (80, 443, 53, 5222, 5223, 5228, 3478, 27015):
        return ("warn", f"Нетипичный внешний порт :{r_port}")
    return ("safe", "Стандартный TLS/Web трафик")


def collect_snapshot() -> None:
    with state_lock:
        if STATE["scanning"]:
            return
        STATE["scanning"] = True

    try:
        sys_name = platform.system()
        raw_conns = parse_connections_windows() if sys_name == "Windows" else parse_connections_macos_linux()

        unique_ips = list({c["remote_ip"] for c in raw_conns if not is_private_ip(c["remote_ip"])})[:60]
        with ThreadPoolExecutor(max_workers=24) as pool:
            pool.map(resolve_ip, unique_ips)

        enriched: List[Dict[str, Any]] = []
        alerts: List[Dict[str, Any]] = []
        proc_counts: Dict[str, Dict[str, Any]] = {}

        for c in raw_conns:
            r_ip = c["remote_ip"]
            host = resolve_ip(r_ip)
            org = classify_org(r_ip, host)
            risk, reason = evaluate_risk(c, host, org)
            item = {
                **c,
                "hostname": host or "—",
                "org": org,
                "risk": risk,
                "reason": reason,
                "is_private": is_private_ip(r_ip),
                "block_cmd": build_block_cmd(r_ip),
            }
            enriched.append(item)

            p_name = c["process"]
            if p_name not in proc_counts:
                proc_counts[p_name] = {"process": p_name, "pid": c["pid"], "total": 0, "external": 0, "high_risk": 0}
            proc_counts[p_name]["total"] += 1
            if not item["is_private"]:
                proc_counts[p_name]["external"] += 1
            if risk in ("high", "warn"):
                proc_counts[p_name]["high_risk"] += 1

            if risk == "high":
                alerts.append(item)

        enriched.sort(key=lambda x: (0 if x["risk"] == "high" else (1 if x["risk"] == "warn" else 2), x["process"].lower()))
        proc_list = sorted(proc_counts.values(), key=lambda x: (x["high_risk"], x["external"], x["total"]), reverse=True)

        with state_lock:
            STATE["connections"] = enriched
            STATE["process_summary"] = proc_list
            STATE["alerts"] = alerts
            STATE["last_update"] = time.strftime("%H:%M:%S")
    finally:
        with state_lock:
            STATE["scanning"] = False


def background_loop() -> None:
    while True:
        collect_snapshot()
        time.sleep(3)


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class SnifferHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _send_bytes(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send_bytes(body, "application/json; charset=utf-8", status=status)

    def _read_json(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            html_path = Path(__file__).resolve().parent / "index.html"
            if not html_path.exists():
                self._send_bytes(b"<h1>index.html not found</h1>", "text/html; charset=utf-8", status=500)
                return
            self._send_bytes(html_path.read_bytes(), "text/html; charset=utf-8")
        elif parsed.path == "/api/state":
            with state_lock:
                payload = dict(STATE)
            self._send_json(payload)
        else:
            self._send_json({"detail": "Not Found"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        data = self._read_json()

        if parsed.path == "/api/refresh":
            threading.Thread(target=collect_snapshot, daemon=True).start()
            self._send_json({"status": "ok"})

        elif parsed.path == "/api/kill-pid":
            pid = str(data.get("pid") or "").strip()
            if not pid.isdigit():
                self._send_json({"detail": "Некорректный PID"}, status=400)
                return
            try:
                if platform.system() == "Windows":
                    subprocess.run(["taskkill", "/PID", pid, "/F"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    os.kill(int(pid), 9)
                with state_lock:
                    add_log(f"Процесс PID {pid} принудительно завершён пользователем.", "ALERT")
                threading.Thread(target=collect_snapshot, daemon=True).start()
                self._send_json({"status": "ok"})
            except Exception as e:
                self._send_json({"detail": f"Не удалось завершить PID {pid}: {e}"}, status=400)

        else:
            self._send_json({"detail": "Not Found"}, status=404)


def bind_server() -> Tuple[ReusableThreadingHTTPServer, int]:
    for port in (8080, 8081, 8082, 8088, 8888, 9090):
        try:
            srv = ReusableThreadingHTTPServer(("127.0.0.1", port), SnifferHandler)
            return srv, port
        except OSError:
            continue
    srv = ReusableThreadingHTTPServer(("127.0.0.1", 0), SnifferHandler)
    return srv, srv.server_address[1]


if __name__ == "__main__":
    add_log(f"BAT-PACKET-SNIFFER v1.3 запущен ({platform.system()}).", "INFO")
    server, active_port = bind_server()
    url = f"http://127.0.0.1:{active_port}"

    threading.Thread(target=background_loop, daemon=True).start()

    print("=" * 64, flush=True)
    print(" BAT-PACKET-SNIFFER v1.3 // LIVE CONNECTION & PROCESS INSPECTOR", flush=True)
    print("=" * 64, flush=True)
    print(f"[INFO] Platform : {platform.system()}", flush=True)
    print(f"[INFO] Web UI   : {url}", flush=True)
    print("[INFO] Press Ctrl+C to stop.\n", flush=True)

    threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...", flush=True)
        server.server_close()

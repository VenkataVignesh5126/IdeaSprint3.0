#!/usr/bin/env python3
"""
🚀 PRO PORT SCANNER - Web Edition
Ultra-fast threaded port scanner with beautiful Flask frontend
"""

import socket
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Tuple, Optional, Dict

from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.secret_key = "portscan-pro-v2.5-super-secret-key-2026"  # Change in production!

# ====================== CORE SCANNER FUNCTIONS ======================

def get_service_name(port: int) -> str:
    """Get human-readable service name for a port."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_single_port(
    target: str,
    port: int,
    timeout: float = 1.2,
    grab_banner: bool = True,
) -> Tuple[int, bool, Optional[str]]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))

            if result != 0:
                return port, False, None

            banner = None
            if grab_banner:
                try:
                    if port in (80, 8080, 8000, 443):
                        s.sendall(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                    elif port == 21:
                        s.sendall(b"HELP\r\n")
                    elif port == 22:
                        s.sendall(b"SSH-2.0-Probe\r\n")
                    elif port in (25, 110, 143, 587):
                        s.sendall(b"NOOP\r\n")
                    else:
                        s.sendall(b"\r\n")

                    time.sleep(0.3)
                    banner_data = s.recv(2048)
                    banner = banner_data.decode("utf-8", errors="ignore").strip()[:200]
                except:
                    banner = "Banner grab failed / Timeout"

            return port, True, banner or "No banner received"

    except Exception:
        return port, False, None


def parse_ports(port_spec: str) -> List[int]:
    """Parse port specification like '80,443,1-1000'"""
    ports: List[int] = []
    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                start = max(1, start)
                end = min(65535, end)
                if start <= end:
                    ports.extend(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.append(p)
            except ValueError:
                continue
    return sorted(set(ports))


def risk_level(port: int, service: str, banner: str) -> str:
    """Intelligent risk scoring"""
    high_risk_ports = {22, 23, 445, 3389, 5900, 5985}
    critical_ports = {21, 25, 110, 143, 3306, 5432, 6379}

    if port in critical_ports:
        return "Critical"
    if port in high_risk_ports or "root" in banner.lower() or "admin" in banner.lower():
        return "High"
    if port in (80, 443, 8080):
        return "Medium"
    return "Low"


# ====================== FLASK ROUTES ======================

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        
        if not target:
            return render_template("index.html", error="Target is required!")

        # Resolve hostname/IP
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return render_template("index.html", error=f"Cannot resolve hostname '{target}'")

        # Default ports (you can make this configurable later)
        port_spec = request.form.get("ports", "21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,5900,6379,8080")
        ports = parse_ports(port_spec)

        if not ports:
            return render_template("index.html", error="No valid ports provided.")

        timeout = float(request.form.get("timeout", 1.2))
        threads = int(request.form.get("threads", 300))
        grab_banner = request.form.get("banner", "on") == "on"

        print(f"[{datetime.now()}] Scanning {target} ({target_ip}) | Ports: {len(ports)} | Threads: {threads}")

        start_time = time.time()
        open_ports: List[Dict] = []
        completed = 0

        try:
            with ThreadPoolExecutor(max_workers=min(threads, 500)) as executor:
                future_to_port = {
                    executor.submit(scan_single_port, target_ip, port, timeout, grab_banner): port
                    for port in ports
                }

                for future in as_completed(future_to_port):
                    port, is_open, banner = future.result()
                    completed += 1

                    if is_open:
                        service = get_service_name(port)
                        risk = risk_level(port, service, banner or "")

                        open_ports.append({
                            "port": port,
                            "service": service,
                            "banner": banner or "No banner",
                            "risk": risk
                        })

        except Exception as e:
            print(f"Scan error: {e}")

        duration = time.time() - start_time

        # Sort results
        open_ports.sort(key=lambda x: x["port"])

        return render_template(
            "index.html",
            result=open_ports,
            target=target,
            target_ip=target_ip,
            duration=round(duration, 2),
            total_scanned=len(ports),
            open_count=len(open_ports)
        )

    # GET request - show empty form
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """JSON API endpoint (bonus for future frontend improvements)"""
    data = request.get_json()
    # ... similar logic as above, return JSON
    return jsonify({"status": "not_implemented_yet"})


if __name__ == "__main__":
    print("🚀 PRO PORT SCANNER Web Edition v2.5 starting...")
    print("   → Open http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)   # Set debug=True only in development
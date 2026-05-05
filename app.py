import socket
import time
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request
from attack_simulator import simulate_attack
from risk_analyzer import analyze_risk
import ipaddress
app = Flask(__name__)

# ================= FUNCTIONS =================

def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except:
        return "unknown"


def grab_banner(target, port):
    """Improved banner grabbing with proper HTTP request"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect((target, port))

            # For HTTP/HTTPS ports, send a proper request
            if port in [80, 443]:
                http_request = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: PortScan-Pro\r\nConnection: close\r\n\r\n"
                s.sendall(http_request.encode())
            else:
                # For other services, send simple newline
                s.sendall(b"\r\n")

            # Receive banner
            banner = s.recv(4096).decode(errors="ignore").strip()
            return banner if banner else "No banner received"

    except Exception:
        return "No banner received"


def scan_single_port(target, port, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))

            if result == 0:
                banner = grab_banner(target, port)
                if banner and len(banner) > 300:
                    banner = banner[:300] + "..."
                return port, "OPEN", banner
    except Exception:
        return port, "FILTERED", None


def parse_ports(port_spec):
    ports = []
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                ports.extend(range(start, end + 1))
            except:
                continue
        else:
            try:
                ports.append(int(part))
            except:
                continue
    return sorted(list(set(ports)))


def risk_level(port):
    if port in [21, 25, 110, 143, 3306]:
        return "Critical"
    elif port in [22, 23, 445, 3389]:
        return "High"
    elif port in [80, 443, 8080]:
        return "Medium"
    else:
        return "Low"


def get_cve_info(port):
    cve_map = {
        21: "FTP vulnerability",
        22: "SSH enumeration",
        23: "Telnet insecure",
        80: "Web exploit possible",
        445: "EternalBlue",
        3389: "BlueKeep"
    }
    return cve_map.get(port, "-")

def is_safe_target(host):
    try:
        ip = ipaddress.ip_address(host)
        return not ip.is_private
    except ValueError:
        return True  # it's a domain name, allow it
# ================= ROUTE =================

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target:
            return render_template("index.html", error="Please enter a valid target")

        try:
            target_ip = socket.gethostbyname(target)
        except Exception:
            return render_template("index.html", error="Invalid target or could not resolve hostname")
        if not is_safe_target(target_ip):
            return render_template("index.html", error="Scanning private/internal IPs is not allowed.")
        port_input = request.form.get("ports", "21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080")
        ports = parse_ports(port_input)

        start = time.time()
        results = []

        with ThreadPoolExecutor(max_workers=200) as executor:
            futures = [executor.submit(scan_single_port, target_ip, p) for p in ports]

            for future in as_completed(futures):
                port, status, banner = future.result()
                service = get_service_name(port)

                if status == "OPEN":
                    risk = risk_level(port)
                    cve = get_cve_info(port)
                    attack_info = simulate_attack(port)
                    risk_detail, _ = analyze_risk(port)
                else:
                    risk = "-"
                    cve = "-"
                    attack_info = "-"
                    risk_detail = "-"

                results.append({
                    "port": port,
                    "service": service,
                    "status": status,
                    "banner": banner,
                    "risk": risk,
                    "cve": cve,
                    "attack": attack_info,
                    "risk_detail": risk_detail
            })

        duration = round(time.time() - start, 2)
        open_count = sum(1 for r in results if r["status"] == "OPEN")

        # Sort: Open first, then by risk
        risk_priority = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "-": 4}
        results.sort(key=lambda x: (
            0 if x["status"] == "OPEN" else 1,
            risk_priority.get(x["risk"], 4)
        ))

        return render_template("index.html",
                               result=results,
                               target=target,
                               ip=target_ip,
                               duration=duration,
                               open_count=open_count)

    return render_template("index.html", result=[], open_count=0)


if __name__ == "__main__":
    app.run(debug=True)
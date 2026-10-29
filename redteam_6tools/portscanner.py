#!/usr/bin/env python3
"""Tool 1/6 - TCP connect port scanner with optional banner grabbing.

CLI:
    python portscanner.py example.com -p 80,443,8080-8090 --grab -T 400

Programmatic:
    import portscanner
    result = portscanner.run("127.0.0.1", ports_spec="1-100")
"""
import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from common import banner, eprint, parse_ports


def scan_port(host, port, timeout, grab):
    """Return (port, is_open, banner). Best-effort; never raises."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        if s.connect_ex((host, port)) != 0:
            return port, False, ""
        info = ""
        if grab:
            try:
                s.settimeout(1.5)
                data = s.recv(256)
                if data:
                    lines = data.decode("utf-8", errors="replace").splitlines()
                    info = lines[0].strip() if lines else ""
            except OSError:
                info = ""
        return port, True, info
    except OSError:
        return port, False, ""
    finally:
        try:
            s.close()
        except OSError:
            pass


def run(host, ports_spec="1-1024,3389,8080,8443", timeout=2.0, threads=300,
        grab=False):
    """Scan a host and return a JSON-serializable result dict.

    Raises ValueError on a bad port spec and socket.gaierror on a host that
    cannot be resolved.
    """
    ports = parse_ports(ports_spec)
    ip = socket.gethostbyname(host)

    open_ports = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout, grab): p for p in ports}
        for fut in as_completed(futures):
            port, is_open, info = fut.result()
            if not is_open:
                continue
            svc = ""
            try:
                svc = socket.getservbyport(port, "tcp")
            except OSError:
                svc = ""
            open_ports.append({"port": port, "service": svc, "banner": info})

    open_ports.sort(key=lambda x: x["port"])
    return {
        "tool": "portscanner",
        "target": host,
        "resolved_ip": ip,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
    }


def main():
    banner("PortScanner")
    ap = argparse.ArgumentParser(description="TCP connect port scanner")
    ap.add_argument("host", help="target hostname or IP address")
    ap.add_argument("-p", "--ports", default="1-1024,3389,8080,8443",
                    help="ports to scan, e.g. 80,443,8000-9000 "
                         "(default: 1-1024,3389,8080,8443)")
    ap.add_argument("-t", "--timeout", type=float, default=2.0,
                    help="per-port connect timeout in seconds (default: 2)")
    ap.add_argument("-T", "--threads", type=int, default=300,
                    help="worker threads (default: 300)")
    ap.add_argument("--grab", action="store_true",
                    help="attempt to grab a service banner")
    args = ap.parse_args()

    try:
        result = run(args.host, args.ports, args.timeout, args.threads, args.grab)
    except ValueError as exc:
        eprint(f"[!] {exc}")
        return 1
    except socket.gaierror:
        eprint(f"[!] cannot resolve host: {args.host}")
        return 1

    print(f"[*] target : {args.host} ({result['resolved_ip']})")
    print(f"[*] ports  : {result['ports_scanned']} scanned, {args.threads} threads, "
          f"timeout {args.timeout}s")

    for o in result["open_ports"]:
        line = f"  [OPEN] {o['port']}/tcp"
        if o["service"]:
            line += f" ({o['service']})"
        if o["banner"]:
            line += f"  |  {o['banner']}"
        print(line)

    print(f"\n[*] done: {len(result['open_ports'])} open port(s) out of "
          f"{result['ports_scanned']} scanned")
    return 0


if __name__ == "__main__":
    sys.exit(main())

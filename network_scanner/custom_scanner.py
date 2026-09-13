"""
network_scanner/custom_scanner.py

A pure-Python TCP connect-scan port scanner -- replaces nmap entirely.
Zero external dependencies, zero third-party licensing concerns: this is
just Python's built-in `socket` module doing what a "TCP connect scan"
always does -- attempting a real handshake and seeing if it succeeds.

Drop-in compatible: scan_network() returns the exact same data shape as
the old nmap-based version, so compare_to_baseline() and everything else
downstream needs no changes at all.
"""

import socket
import concurrent.futures

# A curated list standing in for nmap's "top ports" list -- the most
# commonly used ports, so a scan stays fast without checking all 65535.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 179, 389,
    443, 445, 465, 514, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 2049,
    2082, 2083, 2181, 27017, 3000, 3128, 3306, 3389, 3690, 5000, 5432,
    5601, 5900, 5985, 6379, 6443, 7001, 7070, 8000, 8008, 8080, 8081,
    8443, 8888, 9000, 9090, 9200, 9300, 11211, 27015, 50000,
]

# Minimal service-name lookup, standing in for nmap's much larger database.
SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 179: "bgp", 389: "ldap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 514: "syslog",
    587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "ms-sql-s", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 3000: "dev-http", 3128: "squid-proxy", 3306: "mysql",
    3389: "ms-wbt-server", 5000: "upnp", 5432: "postgresql", 5900: "vnc",
    5985: "wsman", 6379: "redis", 6443: "kubernetes-api", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}


def _grab_banner(sock):
    """Best-effort attempt to read a service banner for extra detail."""
    try:
        sock.settimeout(0.5)
        data = sock.recv(64)
        return data.decode(errors="ignore").strip().split("\n")[0][:60]
    except Exception:
        return None


def _check_port(target, port, timeout=0.4):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            banner = _grab_banner(sock)
            service = SERVICE_NAMES.get(port, "unknown")
            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": banner if banner else service,
            }
    except Exception:
        pass
    finally:
        sock.close()
    return None


def scan_network(target="127.0.0.1", ports=None, max_workers=50):
    """
    Same interface and return shape as the old nmap-based scan_network():
        { "127.0.0.1": [ {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}, ... ] }
    """
    if ports is None:
        ports = COMMON_PORTS

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_check_port, target, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    return {target: sorted(open_ports, key=lambda p: p["port"])}


if __name__ == "__main__":
    import json
    print(json.dumps(scan_network("127.0.0.1"), indent=2))
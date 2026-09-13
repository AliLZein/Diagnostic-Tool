"""
network_scanner/lan_scanner.py

Discovers every live device on YOUR OWN local network subnet (e.g. all of
192.168.1.1 - 192.168.1.254) and port-scans each one using the existing
custom TCP-connect scanner. This is standard home-network administration --
the same category of thing your router's own admin page or any home
network monitor does. It is deliberately scoped to your own local subnet,
derived from your own machine's IP -- it has no way to target arbitrary
internet hosts you don't control.
"""

import subprocess
import concurrent.futures
from network_scanner.custom_scanner import scan_network


def get_subnet_prefix(local_ip):
    """e.g. '192.168.1.100' -> '192.168.1'"""
    parts = local_ip.split(".")
    return ".".join(parts[:3])


def _is_host_alive(ip, timeout_ms=300):
    """Uses a normal ping (ICMP) to check if a device on your subnet is online."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True, text=True, timeout=(timeout_ms / 1000) + 1,
        )
        return "ttl=" in result.stdout.lower()
    except Exception:
        return False


def discover_lan_hosts(subnet_prefix, max_workers=50):
    """Pings every address in the subnet (.1 to .254) in parallel and returns the live ones."""
    alive_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_is_host_alive, f"{subnet_prefix}.{i}"): i for i in range(1, 255)}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                alive_hosts.append(f"{subnet_prefix}.{futures[future]}")
    return sorted(alive_hosts, key=lambda ip: int(ip.split(".")[-1]))


def scan_lan(local_ip, ports=None):
    """
    Discovers live devices on the local subnet, then port-scans each one.
    Returns the same multi-host shape scan_network() already produces for
    a single host, just with one entry per discovered device:
        { "192.168.1.1": [...], "192.168.1.23": [...], ... }
    """
    prefix = get_subnet_prefix(local_ip)
    hosts = discover_lan_hosts(prefix)

    combined_results = {}
    for host in hosts:
        host_result = scan_network(host, ports=ports)
        combined_results.update(host_result)

    return combined_results
import subprocess
import re
from network_scanner.custom_scanner import scan_network

def get_active_arp_hosts(local_ip):
    """Parses the local system ARP table to find devices already communicating on the subnet."""
    active_hosts = set()
    try:
        output = subprocess.check_output("arp -a", shell=True, text=True)
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        
        subnet_prefix = ".".join(local_ip.split(".")[:3])
        
        for line in output.split("\n"):
            if "dynamic" in line.lower() or "static" in line.lower():
                match = ip_pattern.search(line)
                if match:
                    found_ip = match.group(1)
                    if found_ip.startswith(subnet_prefix) and found_ip != local_ip and not found_ip.endswith(".255"):
                        active_hosts.add(found_ip)
    except Exception:
        pass
        
    return list(active_hosts)

def scan_lan(local_ip, ports=None):
    hosts = get_active_arp_hosts(local_ip)

    combined_results = {}
    for host in hosts:
        host_result = scan_network(host, ports=ports)
        combined_results.update(host_result)

    return combined_results
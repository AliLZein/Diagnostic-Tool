import nmap
import json
import os
import sys
import time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from storage.db import log_finding

BASELINE_FILE = "data/baseline.json"

def scan_network(target="127.0.0.1"):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sV")

    results = {}
    for host in nm.all_hosts():
        results[host] = []
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]
                results[host].append({
                    "port": port,
                    "protocol": proto,
                    "state": service["state"],
                    "service": service.get("name", "unknown")
                })
    return results

def save_baseline(results):
    os.makedirs("data", exist_ok=True)
    with open(BASELINE_FILE, "w") as f:
        json.dump(results, f, indent=2)
    log_finding("network", "info", "nmap-scan", f"Baseline saved with {len(results)} host(s)")

def compare_to_baseline(current_results):
    if not os.path.exists(BASELINE_FILE):
        print("No baseline found — saving current scan as baseline.")
        save_baseline(current_results)
        return

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    for host, ports in current_results.items():
        baseline_ports = baseline.get(host, [])
        baseline_port_numbers = {p["port"] for p in baseline_ports}
        current_port_numbers = {p["port"] for p in ports}

        new_ports = current_port_numbers - baseline_port_numbers
        closed_ports = baseline_port_numbers - current_port_numbers

        for port in new_ports:
            log_finding("security", "warning", host, f"New open port detected: {port}")
        for port in closed_ports:
            log_finding("network", "info", host, f"Previously open port now closed: {port}")

    if not any([new_ports, closed_ports] for host in current_results):
        log_finding("network", "info", "nmap-scan", "No changes from baseline")

if __name__ == "__main__":
    target = "127.0.0.1"
    print(f"Starting continuous network scan loop for {target}...")
    
    while True:
        try:
            print(f"\n[INFO] Running scan cycle...")
            results = scan_network(target)
            compare_to_baseline(results)
            print("[INFO] Scan complete. Check data/findings.db for logged results.")
            
            time.sleep(5)
            
        except KeyboardInterrupt:
            print("\n[INFO] Stopping network scanner gracefully.")
            break
        except Exception as e:
            print(f"[ERROR] An error occurred during scan: {e}")
            time.sleep(10)
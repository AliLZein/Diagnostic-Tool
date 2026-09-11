import pyshark
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from storage.db import log_finding

def analyze_capture(filepath):
    print(f"Analyzing {filepath}...")
    cap = pyshark.FileCapture(filepath)

    retransmission_count = 0
    failed_handshake_count = 0
    unusual_ports = set()

    common_ports = {80, 443, 53, 22, 21, 25, 3389}

    for packet in cap:
        try:
            if "TCP" in packet:
                tcp_layer = packet.tcp

                if hasattr(tcp_layer, "analysis_retransmission"):
                    retransmission_count += 1
                    src = packet.ip.src if "IP" in packet else "unknown"
                    log_finding("network", "warning", src, "TCP retransmission detected")

                if tcp_layer.flags_syn == "1" and tcp_layer.flags_ack == "0":
                    failed_handshake_count += 1

                # Flag traffic on uncommon ports
                dport = int(tcp_layer.dstport)
                if dport not in common_ports and dport > 1024:
                    unusual_ports.add(dport)

        except AttributeError:
            continue

    cap.close()

    log_finding("network", "info", filepath, f"Total retransmissions: {retransmission_count}")
    log_finding("network", "info", filepath, f"SYN packets without immediate ACK: {failed_handshake_count}")

    if unusual_ports:
        log_finding("security", "warning", filepath, f"Unusual ports seen: {sorted(unusual_ports)}")

    print("Analysis complete.")
    print(f"  Retransmissions: {retransmission_count}")
    print(f"  Possible failed handshakes: {failed_handshake_count}")
    print(f"  Unusual ports: {sorted(unusual_ports) if unusual_ports else 'none'}")

if __name__ == "__main__":
    analyze_capture("data/sample_capture.pcapng")
"""
capture.py

Shared packet-capture loop used by every TrafficSource backend once
traffic is actually arriving on the interface (whether that traffic
got there via ARP spoofing + forwarding, or via a switch SPAN/mirror
port). Keeping this logic in one place means the rest of the app
(packet_analyzer, analysis, storage, etc.) never needs to know which
backend produced the packets it receives.
"""

import logging
from typing import Callable, Optional

from scapy.all import sniff
from scapy.packet import Packet

logger = logging.getLogger(__name__)


def start_capture(
    iface: str,
    on_packet: Callable[[Packet], None],
    bpf_filter: Optional[str] = None,
    packet_count: int = 0,
) -> None:
    """
    Start a blocking sniff loop on the given interface.

    Args:
        iface: Network interface to capture on (e.g. "eth0").
        on_packet: Callback invoked with each captured scapy Packet.
            Should be the same ingestion function your existing
            packet_analyzer / analysis modules already use.
        bpf_filter: Optional BPF filter string (e.g. "tcp port 80")
            to reduce noise instead of capturing everything.
        packet_count: Number of packets to capture before stopping.
            0 means capture indefinitely until interrupted.
    """
    logger.info("Starting capture on %s (filter=%r)", iface, bpf_filter)
    try:
        sniff(
            iface=iface,
            prn=on_packet,
            store=False,
            filter=bpf_filter,
            count=packet_count,
        )
    except PermissionError as exc:
        raise PermissionError(
            "Packet capture requires root privileges. "
            "Re-run the application with sudo."
        ) from exc
    except OSError as exc:
        raise OSError(
            f"Could not open interface '{iface}' for capture: {exc}"
        ) from exc


def save_capture_to_file(
    iface: str,
    output_path: str,
    bpf_filter: Optional[str] = None,
    packet_count: int = 0,
) -> None:
    """
    Convenience wrapper that writes captured packets straight to a
    pcap file instead of (or in addition to) a live callback — useful
    for later offline analysis in Wireshark.
    """
    from scapy.utils import PcapWriter

    writer = PcapWriter(output_path, append=True, sync=True)

    def _write(pkt: Packet) -> None:
        writer.write(pkt)

    try:
        start_capture(iface, _write, bpf_filter=bpf_filter, packet_count=packet_count)
    finally:
        writer.close()
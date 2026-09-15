"""
packet_analyzer.mirror

Traffic-source abstraction supporting two ways to obtain
network-wide traffic for analysis:

  * "arp"  -> ArpSpoofSource  : software-based mirroring via ARP
                                 spoofing, works on any consumer LAN
                                 you own, no special hardware needed.
  * "span" -> SpanMirrorSource: true, passive port mirroring via a
                                 managed switch's SPAN/mirror port.

Both implement the common TrafficSource interface, so the rest of
the application (packet_analyzer, desktop_app, etc.) can treat them
interchangeably.
"""

from typing import List, Optional

from .arp_backend import ArpSpoofSource
from .base import TrafficSource
from .capture import save_capture_to_file, start_capture
from .span_backend import SpanMirrorSource

__all__ = [
    "TrafficSource",
    "ArpSpoofSource",
    "SpanMirrorSource",
    "start_capture",
    "save_capture_to_file",
    "build_source",
]


def build_source(
    mode: str,
    iface: str,
    gateway_ip: Optional[str] = None,
    subnet: Optional[str] = None,
    targets: Optional[List[str]] = None,
) -> TrafficSource:
    """
    Factory for constructing the right TrafficSource backend.

    Args:
        mode: "arp" or "span".
        iface: Network interface to use.
        gateway_ip: Required for "arp" mode — the LAN gateway's IP.
        subnet: Optional for "arp" mode — CIDR subnet to auto-discover
            hosts on, e.g. "192.168.1.0/24".
        targets: Optional for "arp" mode — explicit list of target IPs,
            overrides subnet discovery.

    Raises:
        ValueError: If `mode` is unrecognized or required args for
            that mode are missing.
    """
    if mode == "arp":
        if not gateway_ip:
            raise ValueError("gateway_ip is required for ARP spoofing mode.")
        return ArpSpoofSource(
            iface=iface, gateway_ip=gateway_ip, subnet=subnet, targets=targets
        )
    elif mode == "span":
        return SpanMirrorSource(iface=iface)
    else:
        raise ValueError(f"Unknown mirror mode: {mode!r} (expected 'arp' or 'span')")
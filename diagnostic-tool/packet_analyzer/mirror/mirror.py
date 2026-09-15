from arp_backend import ARPSpoofSource
from span_backend import SpanMirrorSource
from capture import start_capture

def build_source(mode: str, iface: str, gateway_ip: str = None, subnet: str = None):
    mode = mode.lower()
    if mode == "arp":
        if not gateway_ip or not subnet:
            raise ValueError("ARP mode requires both --gateway and --subnet arguments.")
        return ARPSpoofSource(iface=iface, gateway_ip=gateway_ip, subnet=subnet)
    elif mode == "span":
        return SpanMirrorSource(iface=iface)
    else:
        raise ValueError(f"Unknown mode: {mode}. Choose 'arp' or 'span'.")

# Expose start_capture directly from the capture module
__all__ = ["build_source", "start_capture"]
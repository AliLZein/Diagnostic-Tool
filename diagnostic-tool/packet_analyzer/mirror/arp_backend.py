"""
arp_backend.py

Implements TrafficSource using ARP spoofing (a software substitute
for port mirroring on networks/hardware that don't support real
SPAN). Intended for use ONLY on networks you own and administer.

Requires root privileges (raw socket access via scapy) and IPv4
forwarding to be enabled on this host so spoofed devices retain
internet access while their traffic is being mirrored through us.
"""

import logging
import subprocess
import threading
import time
from typing import Dict, List, Optional

from scapy.all import ARP, Ether, send, srp

from .base import TrafficSource

logger = logging.getLogger(__name__)


def _get_mac(ip: str, iface: str, timeout: float = 2.0) -> Optional[str]:
    """Resolve the MAC address for an IP via an ARP request."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=timeout,
        iface=iface,
        verbose=False,
    )
    return ans[0][1].hwsrc if ans else None


def _discover_hosts(iface: str, subnet: str, timeout: float = 3.0) -> List[str]:
    """
    Discover live hosts on a subnet via a broadcast ARP request.

    Args:
        subnet: CIDR notation, e.g. "192.168.1.0/24".
    """
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
        timeout=timeout,
        iface=iface,
        verbose=False,
    )
    return [received.psrc for _, received in ans]


def _enable_ip_forwarding() -> None:
    subprocess.run(
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        check=True,
        capture_output=True,
    )


class ArpSpoofSource(TrafficSource):
    """
    Spoofs ARP tables for one or more hosts on the LAN so their
    traffic routes through this machine, then forwards it on so the
    hosts retain connectivity while we capture a copy.

    Usage:
        source = ArpSpoofSource(
            iface="eth0",
            gateway_ip="192.168.1.1",
            subnet="192.168.1.0/24",   # whole-network mode
        )
        source.start()
        ...
        source.stop()
    """

    def __init__(
        self,
        iface: str,
        gateway_ip: str,
        subnet: Optional[str] = None,
        targets: Optional[List[str]] = None,
        spoof_interval: float = 2.0,
    ):
        """
        Args:
            iface: Interface to send/receive ARP packets on.
            gateway_ip: IP address of the LAN's default gateway/router.
            subnet: CIDR subnet to auto-discover hosts on, e.g.
                "192.168.1.0/24". Ignored if `targets` is provided.
            targets: Explicit list of target IPs to spoof, instead of
                discovering the whole subnet.
            spoof_interval: Seconds between repeated spoofed ARP
                broadcasts (real ARP tables expire/refresh, so this
                must run continuously while active).
        """
        if not targets and not subnet:
            raise ValueError("Must provide either `targets` or `subnet`.")

        self.iface = iface
        self.gateway_ip = gateway_ip
        self.subnet = subnet
        self.targets = targets
        self.spoof_interval = spoof_interval

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._real_macs: Dict[str, str] = {}
        self._lock = threading.Lock()

    @property
    def is_active(self) -> bool:
        return self._running

    def start(self) -> None:
        if self._running:
            logger.warning("ArpSpoofSource already running; ignoring start().")
            return

        _enable_ip_forwarding()

        hosts = self.targets or _discover_hosts(self.iface, self.subnet)
        if not hosts:
            raise RuntimeError(
                "No hosts discovered on subnet; check iface/subnet values."
            )

        gw_mac = _get_mac(self.gateway_ip, self.iface)
        if not gw_mac:
            raise RuntimeError(
                f"Could not resolve MAC for gateway {self.gateway_ip}. "
                "Check that iface/gateway_ip are correct and the "
                "gateway is reachable."
            )

        with self._lock:
            self._real_macs = {self.gateway_ip: gw_mac}
            for host_ip in hosts:
                mac = _get_mac(host_ip, self.iface)
                if mac:
                    self._real_macs[host_ip] = mac
                else:
                    logger.warning("Could not resolve MAC for host %s; skipping.", host_ip)

        logger.info(
            "Starting ARP spoofing on %s for %d host(s), gateway=%s",
            self.iface, len(self._real_macs) - 1, self.gateway_ip,
        )

        self._running = True
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._thread.start()

    def _spoof_loop(self) -> None:
        gw_mac = self._real_macs.get(self.gateway_ip)
        while self._running:
            with self._lock:
                host_items = [
                    (ip, mac) for ip, mac in self._real_macs.items()
                    if ip != self.gateway_ip
                ]
            for host_ip, host_mac in host_items:
                try:
                    # Tell the host that WE are the gateway.
                    send(
                        ARP(op=2, pdst=host_ip, hwdst=host_mac, psrc=self.gateway_ip),
                        iface=self.iface,
                        verbose=False,
                    )
                    # Tell the gateway that WE are the host.
                    send(
                        ARP(op=2, pdst=self.gateway_ip, hwdst=gw_mac, psrc=host_ip),
                        iface=self.iface,
                        verbose=False,
                    )
                except OSError as exc:
                    logger.error("Failed to send spoofed ARP for %s: %s", host_ip, exc)
            time.sleep(self.spoof_interval)

    def stop(self) -> None:
        if not self._running:
            return

        logger.info("Stopping ARP spoofing and restoring real ARP mappings...")
        self._running = False
        if self._thread:
            self._thread.join(timeout=self.spoof_interval + 2)

        gw_mac = self._real_macs.get(self.gateway_ip)
        with self._lock:
            items = [
                (ip, mac) for ip, mac in self._real_macs.items()
                if ip != self.gateway_ip and mac
            ]

        for host_ip, host_mac in items:
            try:
                # Restore host -> gateway mapping.
                send(
                    ARP(
                        op=2, pdst=host_ip, hwdst=host_mac,
                        psrc=self.gateway_ip, hwsrc=gw_mac,
                    ),
                    count=3, iface=self.iface, verbose=False,
                )
                # Restore gateway -> host mapping.
                send(
                    ARP(
                        op=2, pdst=self.gateway_ip, hwdst=gw_mac,
                        psrc=host_ip, hwsrc=host_mac,
                    ),
                    count=3, iface=self.iface, verbose=False,
                )
            except OSError as exc:
                logger.error("Failed to restore ARP for %s: %s", host_ip, exc)

        logger.info("ARP tables restored.")
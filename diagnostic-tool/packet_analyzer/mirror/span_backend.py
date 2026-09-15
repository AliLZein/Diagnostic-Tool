"""
span_backend.py

Implements TrafficSource for TRUE port mirroring (SPAN), where a
managed switch has already been configured to copy traffic from one
or more source ports to the port this host is plugged into. Unlike
ArpSpoofSource, this backend does not alter the network in any way —
it only ensures the local NIC is in promiscuous mode so the kernel
doesn't discard frames not addressed to this host's MAC.

Prerequisite (done outside this code, on the switch itself):
    - A managed switch configured with a monitor/mirror session,
      e.g. on a Cisco-style CLI:
          monitor session 1 source interface gi1/0/1 - 8
          monitor session 1 destination interface gi1/0/9
    - This host's NIC physically connected to the destination
      (mirror) port.
"""

import logging
import subprocess

from .base import TrafficSource

logger = logging.getLogger(__name__)


class SpanMirrorSource(TrafficSource):
    """
    Passive traffic source for use with a switch's SPAN/mirror port.

    Usage:
        source = SpanMirrorSource(iface="eth0")
        source.start()
        ...
        source.stop()
    """

    def __init__(self, iface: str):
        self.iface = iface
        self._active = False

    @property
    def is_active(self) -> bool:
        return self._active

    def start(self) -> None:
        if self._active:
            logger.warning("SpanMirrorSource already active; ignoring start().")
            return

        logger.info("Enabling promiscuous mode on %s for SPAN capture.", self.iface)
        result = subprocess.run(
            ["ip", "link", "set", self.iface, "promisc", "on"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to enable promiscuous mode on {self.iface}: "
                f"{result.stderr.strip()}"
            )
        self._active = True

    def stop(self) -> None:
        if not self._active:
            return

        logger.info("Disabling promiscuous mode on %s.", self.iface)
        result = subprocess.run(
            ["ip", "link", "set", self.iface, "promisc", "off"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            logger.error(
                "Failed to disable promiscuous mode on %s: %s",
                self.iface, result.stderr.strip(),
            )
        self._active = False
"""
base.py

Defines the common interface that every traffic-source backend
(ARP spoofing, SPAN/port mirroring, and any future backend) must
implement. This lets the rest of the application (packet_analyzer,
desktop_app UI, etc.) work with a single abstraction regardless of
how the mirrored traffic is actually obtained.
"""

from abc import ABC, abstractmethod


class TrafficSource(ABC):
    """Common interface both ARP-spoofing and SPAN backends implement."""

    @abstractmethod
    def start(self) -> None:
        """Begin whatever mechanism gets traffic flowing to this interface."""
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        """Cleanly tear down (restore ARP tables, disable promisc, etc.)."""
        raise NotImplementedError

    @property
    @abstractmethod
    def is_active(self) -> bool:
        """Whether this source is currently running."""
        raise NotImplementedError

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        # Do not suppress exceptions
        return False
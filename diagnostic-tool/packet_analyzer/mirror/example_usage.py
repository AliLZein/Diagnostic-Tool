import argparse
import logging
import signal
import sys

from mirror import build_source, start_capture

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def your_existing_analyzer_callback(packet) -> None:
    """
    Placeholder — replace this with whatever function your existing
    packet_analyzer / analysis modules already use to ingest a
    scapy packet. Keeping this as the single hand-off point means
    both backends feed the exact same downstream pipeline.
    """
    summary = packet.summary()
    logger.info("Captured: %s", summary)


def main() -> None:
    parser = argparse.ArgumentParser(description="Test the mirror module.")
    parser.add_argument("--mode", choices=["arp", "span"], required=True)
    parser.add_argument("--iface", required=True, help="Interface, e.g. eth0")
    parser.add_argument("--gateway", help="Gateway IP (required for arp mode)")
    parser.add_argument("--subnet", help="CIDR subnet for arp mode, e.g. 192.168.1.0/24")
    parser.add_argument("--filter", default=None, help="Optional BPF filter")
    args = parser.parse_args()

    source = build_source(
        mode=args.mode,
        iface=args.iface,
        gateway_ip=args.gateway,
        subnet=args.subnet,
    )

    def handle_shutdown(signum, frame):
        logger.info("Shutting down, restoring network state...")
        source.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    source.start()
    logger.info("Mirroring active (mode=%s). Press Ctrl+C to stop.", args.mode)

    try:
        start_capture(args.iface, your_existing_analyzer_callback, bpf_filter=args.filter)
    finally:
        source.stop()


if __name__ == "__main__":
    main()
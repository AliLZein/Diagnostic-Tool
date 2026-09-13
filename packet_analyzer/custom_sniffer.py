"""
packet_analyzer/custom_sniffer.py

A pure-Python packet sniffer using Windows' built-in raw socket support --
replaces Wireshark/tshark/pyshark AND their Npcap driver dependency entirely.

Includes: Unusual ports detection and diagnostic visibility counters.
"""

import socket
import struct
import time
import sys
import logging
from storage.db import log_finding

# Tracks (src_ip, src_port, dst_ip, dst_port, seq) we've already seen,
# so a repeated sequence number on the same flow = a retransmission.
_seen_segments = {}
_SEGMENT_TTL = 30  # seconds

COMMON_PORTS = {80, 443, 53, 22, 21, 25, 3389}


def _cleanup_seen_segments():
    now = time.time()
    expired = [key for key, ts in _seen_segments.items() if now - ts > _SEGMENT_TTL]
    for key in expired:
        del _seen_segments[key]


def _parse_ip_header(data):
    ip_header = data[:20]
    fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
    version_ihl = fields[0]
    ihl = (version_ihl & 0xF) * 4
    protocol = fields[6]
    src_ip = socket.inet_ntoa(fields[8])
    dst_ip = socket.inet_ntoa(fields[9])
    return {"ihl": ihl, "protocol": protocol, "src_ip": src_ip, "dst_ip": dst_ip}


def _parse_tcp_header(data, offset):
    tcp_header = data[offset:offset + 20]
    if len(tcp_header) < 20:
        return None
    fields = struct.unpack("!HHLLBBHHH", tcp_header)
    src_port, dst_port, seq, ack_seq, offset_reserved_flags = fields[0:5]
    data_offset = (offset_reserved_flags >> 4) * 4
    fin = fields[5] & 0x01
    syn = fields[5] & 0x02
    ack = fields[5] & 0x10
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "syn": bool(syn),
        "ack": bool(ack),
        "header_len": data_offset,
    }


def _extract_sni(payload):
    try:
        if len(payload) < 5 or payload[0] != 0x16:  # 0x16 = TLS Handshake
            return None
        pos = 5
        if payload[pos] != 0x01:  # 0x01 = ClientHello
            return None
        pos += 4
        pos += 2 + 32  # client version (2) + random (32)
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        cipher_suites_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len
        compression_len = payload[pos]
        pos += 1 + compression_len
        if pos + 2 > len(payload):
            return None
        extensions_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        end = pos + extensions_len
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
            pos += 4
            if ext_type == 0x00:  # server_name extension
                name_len = struct.unpack("!H", payload[pos + 3:pos + 5])[0]
                name = payload[pos + 5:pos + 5 + name_len]
                return name.decode(errors="ignore")
            pos += ext_len
    except Exception:
        return None
    return None


def _extract_http_host(payload):
    try:
        text = payload.decode(errors="ignore")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def sniff_traffic(local_ip, duration=5):
    """
    Captures traffic on `local_ip` for `duration` seconds using Windows raw sockets.
    Tracks retransmissions, unusual ports, and logs raw packet visibility counters.
    """
    if sys.platform != "win32":
        log_finding("network", "warning", "sniffer", "Custom sniffer currently only supports Windows raw sockets")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind((local_ip, 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    sock.settimeout(1.0)  # check elapsed time periodically

    retransmission_count = 0
    total_packets_seen = 0
    tcp_packets_seen = 0
    hosts_seen = {}
    unusual_ports = set()
    start = time.time()

    try:
        while time.time() - start < duration:
            try:
                raw_data, _ = sock.recvfrom(65535)
                total_packets_seen += 1
            except socket.timeout:
                continue

            ip_info = _parse_ip_header(raw_data)
            if ip_info["protocol"] != 6:  # Only process TCP packets
                continue

            tcp_info = _parse_tcp_header(raw_data, ip_info["ihl"])
            if tcp_info is None:
                continue

            tcp_packets_seen += 1

            # Check for non-standard ports above 1024
            dport = tcp_info["dst_port"]
            if dport not in COMMON_PORTS and dport > 1024:
                unusual_ports.add(dport)

            flow_key = (ip_info["src_ip"], tcp_info["src_port"],
                        ip_info["dst_ip"], tcp_info["dst_port"], tcp_info["seq"])

            if flow_key in _seen_segments:
                retransmission_count += 1
                log_finding("network", "warning", ip_info["src_ip"],
                            "TCP retransmission detected (custom sniffer)")
            else:
                _seen_segments[flow_key] = time.time()

            # Attempt extraction of target host info from payload
            payload_offset = ip_info["ihl"] + tcp_info["header_len"]
            payload = raw_data[payload_offset:]
            if payload:
                hostname = _extract_sni(payload) or _extract_http_host(payload)
                if hostname:
                    remote_ip = ip_info["dst_ip"] if ip_info["src_ip"] == local_ip else ip_info["src_ip"]
                    hosts_seen[remote_ip] = hostname

    finally:
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sock.close()

    _cleanup_seen_segments()

    for ip, hostname in hosts_seen.items():
        log_finding("network", "info", ip, f"Identified traffic destination: {hostname}")

    if unusual_ports:
        log_finding("security", "warning", local_ip, f"Unusual ports seen: {sorted(unusual_ports)}")

    # Diagnostic visibility logging (replaces guessing with exact metrics)
    summary_msg = (
        f"Capture cycle ({duration}s): {retransmission_count} retransmissions | "
        f"Packets: {tcp_packets_seen} TCP / {total_packets_seen} Total | "
        f"Hosts: {len(hosts_seen)} | Unusual Ports: {sorted(unusual_ports) if unusual_ports else 'none'}"
    )
    log_finding("network", "info", local_ip, summary_msg)
    logging.info(summary_msg)


if __name__ == "__main__":
    # Replace with your real local IP obtained via `ipconfig`
    sniff_traffic("192.168.1.100", duration=10)
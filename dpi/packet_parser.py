"""
Port of include/packet_parser.h + src/packet_parser.cpp

Extracts protocol fields from raw packet bytes:

raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header
[34-53]  TCP Header
[54+]    Payload

Network byte order is big-endian; Python's struct '>' format specifier
handles this natively (this replaces the C++ ntohs()/ntohl() calls, which
were themselves implemented portably in platform.h/platform_net.py).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


# TCP Flag constants
class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


# Protocol numbers
class Protocol:
    ICMP = 1
    TCP = 6
    UDP = 17


# EtherType values
class EtherType:
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP = 0x0806


ETH_HEADER_LEN = 14
MIN_IP_HEADER_LEN = 20
MIN_TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8


@dataclass
class ParsedPacket:
    # Timestamps
    timestamp_sec: int = 0
    timestamp_usec: int = 0

    # Ethernet layer
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0

    # IP layer (if present)
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0  # TCP=6, UDP=17, ICMP=1
    ttl: int = 0

    # Transport layer (if present)
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0

    # TCP-specific
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0

    # Payload
    payload_length: int = 0
    payload_offset: int = 0  # offset into the original raw bytes (Python has no raw pointers)


class PacketParser:
    """Class to parse raw packets."""

    @staticmethod
    def parse(raw_data: bytes, parsed: ParsedPacket) -> bool:
        """
        Parse a raw packet and fill in the ParsedPacket structure.
        `raw_data` is the full RawPacket.data; timestamp fields on `parsed`
        should already be set by the caller (mirrors the C++ RawPacket header
        being read before parse() is called).
        """
        data = raw_data
        length = len(data)
        offset = 0

        offset = PacketParser._parse_ethernet(data, length, parsed, offset)
        if offset is None:
            return False

        if parsed.ether_type == EtherType.IPv4:
            offset = PacketParser._parse_ipv4(data, length, parsed, offset)
            if offset is None:
                return False

            if parsed.protocol == Protocol.TCP:
                offset = PacketParser._parse_tcp(data, length, parsed, offset)
                if offset is None:
                    return False
            elif parsed.protocol == Protocol.UDP:
                offset = PacketParser._parse_udp(data, length, parsed, offset)
                if offset is None:
                    return False

        if offset < length:
            parsed.payload_length = length - offset
            parsed.payload_offset = offset
        else:
            parsed.payload_length = 0
            parsed.payload_offset = 0

        return True

    @staticmethod
    def _parse_ethernet(data: bytes, length: int, parsed: ParsedPacket, offset: int):
        if length < ETH_HEADER_LEN:
            return None  # Packet too short

        parsed.dest_mac = PacketParser.mac_to_string(data[0:6])
        parsed.src_mac = PacketParser.mac_to_string(data[6:12])
        parsed.ether_type = struct.unpack(">H", data[12:14])[0]

        return ETH_HEADER_LEN

    @staticmethod
    def _parse_ipv4(data: bytes, length: int, parsed: ParsedPacket, offset: int):
        if length < offset + MIN_IP_HEADER_LEN:
            return None  # Packet too short

        ip_data = data[offset:]

        version_ihl = ip_data[0]
        parsed.ip_version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F  # Header length in 32-bit words

        if parsed.ip_version != 4:
            return None  # Not IPv4

        ip_header_len = ihl * 4  # Convert to bytes
        if ip_header_len < MIN_IP_HEADER_LEN or length < offset + ip_header_len:
            return None

        parsed.ttl = ip_data[8]
        parsed.protocol = ip_data[9]

        src_ip = struct.unpack("<I", ip_data[12:16])[0]
        parsed.src_ip = PacketParser.ip_to_string(src_ip)

        dest_ip = struct.unpack("<I", ip_data[16:20])[0]
        parsed.dest_ip = PacketParser.ip_to_string(dest_ip)

        parsed.has_ip = True
        return offset + ip_header_len

    @staticmethod
    def _parse_tcp(data: bytes, length: int, parsed: ParsedPacket, offset: int):
        if length < offset + MIN_TCP_HEADER_LEN:
            return None

        tcp_data = data[offset:]

        parsed.src_port = struct.unpack(">H", tcp_data[0:2])[0]
        parsed.dest_port = struct.unpack(">H", tcp_data[2:4])[0]
        parsed.seq_number = struct.unpack(">I", tcp_data[4:8])[0]
        parsed.ack_number = struct.unpack(">I", tcp_data[8:12])[0]

        data_offset = (tcp_data[12] >> 4) & 0x0F
        tcp_header_len = data_offset * 4

        parsed.tcp_flags = tcp_data[13]

        if tcp_header_len < MIN_TCP_HEADER_LEN or length < offset + tcp_header_len:
            return None

        parsed.has_tcp = True
        return offset + tcp_header_len

    @staticmethod
    def _parse_udp(data: bytes, length: int, parsed: ParsedPacket, offset: int):
        if length < offset + UDP_HEADER_LEN:
            return None

        udp_data = data[offset:]

        parsed.src_port = struct.unpack(">H", udp_data[0:2])[0]
        parsed.dest_port = struct.unpack(">H", udp_data[2:4])[0]

        parsed.has_udp = True
        return offset + UDP_HEADER_LEN

    @staticmethod
    def mac_to_string(mac: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac[:6])

    @staticmethod
    def ip_to_string(ip: int) -> str:
        # IP is stored in network byte order (big-endian); extract each byte
        # exactly as the C++ code did (bit-shifting the little-endian-loaded uint32).
        return f"{(ip >> 0) & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"

    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        if protocol == Protocol.ICMP:
            return "ICMP"
        if protocol == Protocol.TCP:
            return "TCP"
        if protocol == Protocol.UDP:
            return "UDP"
        return f"Unknown({protocol})"

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        parts = []
        if flags & TCPFlags.SYN:
            parts.append("SYN")
        if flags & TCPFlags.ACK:
            parts.append("ACK")
        if flags & TCPFlags.FIN:
            parts.append("FIN")
        if flags & TCPFlags.RST:
            parts.append("RST")
        if flags & TCPFlags.PSH:
            parts.append("PSH")
        if flags & TCPFlags.URG:
            parts.append("URG")
        return " ".join(parts) if parts else "none"

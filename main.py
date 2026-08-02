#!/usr/bin/env python3
"""
Port of src/main.cpp

Packet Analyzer v1.0 - reads a PCAP file and prints a human-readable
summary of each packet (Ethernet / IP / TCP / UDP / payload preview).
"""

import sys
from datetime import datetime

from dpi.packet_parser import EtherType, PacketParser, ParsedPacket
from dpi.pcap_reader import PcapReader


def print_packet_summary(pkt: ParsedPacket, packet_num: int) -> None:
    dt = datetime.fromtimestamp(pkt.timestamp_sec)

    print(f"\n========== Packet #{packet_num} ==========")
    print(f"Time: {dt.strftime('%Y-%m-%d %H:%M:%S')}.{pkt.timestamp_usec:06d}")

    # Ethernet layer
    print("\n[Ethernet]")
    print(f"  Source MAC:      {pkt.src_mac}")
    print(f"  Destination MAC: {pkt.dest_mac}")
    ether_str = f"0x{pkt.ether_type:04x}"
    if pkt.ether_type == EtherType.IPv4:
        ether_str += " (IPv4)"
    elif pkt.ether_type == EtherType.IPv6:
        ether_str += " (IPv6)"
    elif pkt.ether_type == EtherType.ARP:
        ether_str += " (ARP)"
    print(f"  EtherType:       {ether_str}")

    # IP layer
    if pkt.has_ip:
        print(f"\n[IPv{pkt.ip_version}]")
        print(f"  Source IP:      {pkt.src_ip}")
        print(f"  Destination IP: {pkt.dest_ip}")
        print(f"  Protocol:       {PacketParser.protocol_to_string(pkt.protocol)}")
        print(f"  TTL:            {pkt.ttl}")

    # TCP layer
    if pkt.has_tcp:
        print("\n[TCP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")
        print(f"  Sequence Number:  {pkt.seq_number}")
        print(f"  Ack Number:       {pkt.ack_number}")
        print(f"  Flags:            {PacketParser.tcp_flags_to_string(pkt.tcp_flags)}")

    # UDP layer
    if pkt.has_udp:
        print("\n[UDP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")

    # Payload info
    if pkt.payload_length > 0:
        print("\n[Payload]")
        print(f"  Length: {pkt.payload_length} bytes")

        print("  Preview: ", end="")
        payload = pkt.payload_data if hasattr(pkt, "payload_data") else b""
        preview_len = min(pkt.payload_length, 32)
        preview = payload[:preview_len]
        print(" ".join(f"{b:02x}" for b in preview), end="")
        if pkt.payload_length > 32:
            print("...", end="")
        print()


def print_usage(program_name: str) -> None:
    print(f"Usage: {program_name} <pcap_file> [max_packets]")
    print("\nArguments:")
    print("  pcap_file   - Path to a .pcap file captured by Wireshark")
    print("  max_packets - (Optional) Maximum number of packets to display")
    print("\nExample:")
    print(f"  {program_name} capture.pcap")
    print(f"  {program_name} capture.pcap 10")


def main(argv) -> int:
    print("====================================")
    print("     Packet Analyzer v1.0")
    print("====================================\n")

    if len(argv) < 2:
        print_usage(argv[0])
        return 1

    filename = argv[1]
    max_packets = -1  # -1 means no limit

    if len(argv) >= 3:
        max_packets = int(argv[2])

    reader = PcapReader()
    if not reader.open(filename):
        return 1

    print("\n--- Reading packets ---")

    packet_count = 0
    parse_errors = 0

    while True:
        raw = reader.read_next_packet()
        if raw is None:
            break

        packet_count += 1

        parsed = ParsedPacket(timestamp_sec=raw.header.ts_sec, timestamp_usec=raw.header.ts_usec)
        # attach payload_data property lookalike via closure below
        if PacketParser.parse(raw.data, parsed):
            # give the printer access to the raw payload bytes
            parsed.payload_data = raw.data[parsed.payload_offset: parsed.payload_offset + parsed.payload_length]
            print_packet_summary(parsed, packet_count)
        else:
            print(f"Warning: Failed to parse packet #{packet_count}", file=sys.stderr)
            parse_errors += 1

        if max_packets > 0 and packet_count >= max_packets:
            print(f"\n(Stopped after {max_packets} packets)")
            break

    print("\n====================================")
    print("Summary:")
    print(f"  Total packets read:  {packet_count}")
    print(f"  Parse errors:        {parse_errors}")
    print("====================================")

    reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

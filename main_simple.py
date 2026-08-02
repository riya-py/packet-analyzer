#!/usr/bin/env python3
"""
Port of src/main_simple.cpp

Simple single-threaded test version: reads a PCAP and prints each
packet's 5-tuple, plus the extracted TLS SNI where present.
"""

import sys

from dpi.packet_parser import PacketParser, ParsedPacket
from dpi.pcap_reader import PcapReader
from dpi.sni_extractor import SNIExtractor


def main(argv) -> int:
    if len(argv) < 2:
        print(f"Usage: {argv[0]} <pcap_file>", file=sys.stderr)
        return 1

    reader = PcapReader()
    if not reader.open(argv[1]):
        return 1

    count = 0
    tls_count = 0

    print("Processing packets...")

    while True:
        raw = reader.read_next_packet()
        if raw is None:
            break

        count += 1

        parsed = ParsedPacket(timestamp_sec=raw.header.ts_sec, timestamp_usec=raw.header.ts_usec)
        if not PacketParser.parse(raw.data, parsed):
            continue

        if not parsed.has_ip:
            continue

        line = f"Packet {count}: {parsed.src_ip}:{parsed.src_port} -> {parsed.dest_ip}:{parsed.dest_port}"

        # Try SNI extraction for HTTPS packets
        if parsed.has_tcp and parsed.dest_port == 443 and parsed.payload_length > 0:
            data = raw.data

            payload_offset = 14  # Ethernet
            ip_ihl = data[14] & 0x0F
            payload_offset += ip_ihl * 4
            tcp_offset = (data[payload_offset + 12] >> 4) & 0x0F
            payload_offset += tcp_offset * 4

            if payload_offset < len(data):
                payload = data[payload_offset:]
                payload_len = len(payload)
                sni = SNIExtractor.extract(payload, payload_len)
                if sni:
                    line += f" [SNI: {sni}]"
                    tls_count += 1

        print(line)

    print(f"\nTotal packets: {count}")
    print(f"SNI extracted: {tls_count}")

    reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

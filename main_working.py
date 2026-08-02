#!/usr/bin/env python3
"""
Port of src/main_working.cpp

"Working DPI Engine" - Simplified but functional, single-threaded.
This is the direct Python equivalent of the C++ file your README calls
out as the ★ SIMPLE VERSION ★ (built into dpi_simple / dpi_simple.exe).
"""

import sys
from dataclasses import dataclass, field
from typing import Dict, List

from dpi.packet_parser import PacketParser, ParsedPacket
from dpi.pcap_reader import PcapPacketHeader, PcapReader
from dpi.sni_extractor import HTTPHostExtractor, SNIExtractor
from dpi.types import AppType, FiveTuple, app_type_to_string, sni_to_app_type


# ----------------------------------------------------------------------
# Simplified connection tracking
# ----------------------------------------------------------------------
@dataclass
class Flow:
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False


# ----------------------------------------------------------------------
# Blocking rules
# ----------------------------------------------------------------------
class BlockingRules:
    def __init__(self) -> None:
        self.blocked_ips: set = set()
        self.blocked_apps: set = set()
        self.blocked_domains: List[str] = []  # Simple substring match

    @staticmethod
    def _parse_ip(ip: str) -> int:
        result = 0
        octet = 0
        shift = 0
        for c in ip:
            if c == ".":
                result |= (octet << shift)
                shift += 8
                octet = 0
            elif c.isdigit():
                octet = octet * 10 + int(c)
        return result | (octet << shift)

    def block_ip(self, ip: str) -> None:
        addr = self._parse_ip(ip)
        self.blocked_ips.add(addr)
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app: str) -> None:
        for a in AppType:
            if app_type_to_string(a) == app:
                self.blocked_apps.add(a)
                print(f"[Rules] Blocked app: {app}")
                return
        print(f"[Rules] Unknown app: {app}", file=sys.stderr)

    def block_domain(self, domain: str) -> None:
        self.blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        if src_ip in self.blocked_ips:
            return True
        if app in self.blocked_apps:
            return True
        for dom in self.blocked_domains:
            if dom in sni:
                return True
        return False


def print_usage(prog: str) -> None:
    print(f"""
DPI Engine - Deep Packet Inspection System
==========================================

Usage: {prog} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  {prog} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
""")


def _parse_ip_str(ip: str) -> int:
    result = 0
    octet = 0
    shift = 0
    for c in ip:
        if c == ".":
            result |= (octet << shift)
            shift += 8
            octet = 0
        elif c.isdigit():
            octet = octet * 10 + int(c)
    return result | (octet << shift)


def main(argv) -> int:
    if len(argv) < 3:
        print_usage(argv[0])
        return 1

    input_file = argv[1]
    output_file = argv[2]

    rules = BlockingRules()

    i = 3
    while i < len(argv):
        arg = argv[i]
        if arg == "--block-ip" and i + 1 < len(argv):
            i += 1
            rules.block_ip(argv[i])
        elif arg == "--block-app" and i + 1 < len(argv):
            i += 1
            rules.block_app(argv[i])
        elif arg == "--block-domain" and i + 1 < len(argv):
            i += 1
            rules.block_domain(argv[i])
        i += 1

    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                    DPI ENGINE v1.0                            ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    reader = PcapReader()
    if not reader.open(input_file):
        return 1

    try:
        output = open(output_file, "wb")
    except OSError:
        print("Error: Cannot open output file", file=sys.stderr)
        return 1

    header = reader.get_global_header()
    output.write(header.pack())

    flows: Dict[FiveTuple, Flow] = {}

    total_packets = 0
    forwarded = 0
    dropped = 0
    app_stats: Dict[AppType, int] = {}

    print("[DPI] Processing packets...")

    while True:
        raw = reader.read_next_packet()
        if raw is None:
            break

        total_packets += 1

        parsed = ParsedPacket(timestamp_sec=raw.header.ts_sec, timestamp_usec=raw.header.ts_usec)
        if not PacketParser.parse(raw.data, parsed):
            continue
        if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            continue

        tuple_ = FiveTuple(
            src_ip=_parse_ip_str(parsed.src_ip),
            dst_ip=_parse_ip_str(parsed.dest_ip),
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol,
        )

        flow = flows.get(tuple_)
        if flow is None:
            flow = Flow(tuple=tuple_)
            flows[tuple_] = flow
        flow.packets += 1
        flow.bytes += len(raw.data)

        data = raw.data

        # Try SNI extraction - even for flows already marked as generic HTTPS
        if (
            (flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTPS)
            and not flow.sni
            and parsed.has_tcp
            and parsed.dest_port == 443
        ):
            payload_offset = 14
            ip_ihl = data[14] & 0x0F
            payload_offset += ip_ihl * 4

            if payload_offset + 12 < len(data):
                tcp_offset = (data[payload_offset + 12] >> 4) & 0x0F
                payload_offset += tcp_offset * 4

                if payload_offset < len(data):
                    payload = data[payload_offset:]
                    payload_len = len(payload)
                    if payload_len > 5:  # Minimum TLS record header
                        sni = SNIExtractor.extract(payload, payload_len)
                        if sni:
                            flow.sni = sni
                            flow.app_type = sni_to_app_type(sni)

        # HTTP Host extraction
        if (
            (flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTP)
            and not flow.sni
            and parsed.has_tcp
            and parsed.dest_port == 80
        ):
            payload_offset = 14
            ip_ihl = data[14] & 0x0F
            payload_offset += ip_ihl * 4

            if payload_offset + 12 < len(data):
                tcp_offset = (data[payload_offset + 12] >> 4) & 0x0F
                payload_offset += tcp_offset * 4

                if payload_offset < len(data):
                    payload = data[payload_offset:]
                    payload_len = len(payload)
                    host = HTTPHostExtractor.extract(payload, payload_len)
                    if host:
                        flow.sni = host
                        flow.app_type = sni_to_app_type(host)

        # DNS classification
        if flow.app_type == AppType.UNKNOWN and (parsed.dest_port == 53 or parsed.src_port == 53):
            flow.app_type = AppType.DNS

        # Port-based fallback
        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP

        # Check blocking rules
        if not flow.blocked:
            flow.blocked = rules.is_blocked(tuple_.src_ip, flow.app_type, flow.sni)
            if flow.blocked:
                line = f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({app_type_to_string(flow.app_type)}"
                if flow.sni:
                    line += f": {flow.sni}"
                line += ")"
                print(line)

        # Update app stats
        app_stats[flow.app_type] = app_stats.get(flow.app_type, 0) + 1

        # Forward or drop
        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            pkt_hdr = PcapPacketHeader(
                ts_sec=raw.header.ts_sec,
                ts_usec=raw.header.ts_usec,
                incl_len=len(raw.data),
                orig_len=len(raw.data),
            )
            output.write(pkt_hdr.pack())
            output.write(raw.data)

    reader.close()
    output.close()

    # Print report
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                      PROCESSING REPORT                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Total Packets:      {total_packets:>10}                             ║")
    print(f"║ Forwarded:          {forwarded:>10}                             ║")
    print(f"║ Dropped:            {dropped:>10}                             ║")
    print(f"║ Active Flows:       {len(flows):>10}                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║                    APPLICATION BREAKDOWN                     ║")
    print("╠══════════════════════════════════════════════════════════════╣")

    sorted_apps = sorted(app_stats.items(), key=lambda kv: kv[1], reverse=True)

    for app, count in sorted_apps:
        pct = 100.0 * count / total_packets if total_packets else 0.0
        bar_len = int(pct / 5)
        bar = "#" * bar_len

        print(f"║ {app_type_to_string(app):<15}{count:>8} {pct:>5.1f}% {bar:<20}  ║")

    print("╚══════════════════════════════════════════════════════════════╝")

    # List unique SNIs
    print("\n[Detected Applications/Domains]")
    unique_snis: Dict[str, AppType] = {}
    for flow in flows.values():
        if flow.sni:
            unique_snis[flow.sni] = flow.app_type
    for sni, app in unique_snis.items():
        print(f"  - {sni} -> {app_type_to_string(app)}")

    print(f"\nOutput written to: {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

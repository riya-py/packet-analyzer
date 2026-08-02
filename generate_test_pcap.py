#!/usr/bin/env python3
"""
generate_test_pcap.py

NOTE: This file was not part of your uploaded src.zip/include.zip, so this
is a reconstruction (not a line-for-line port) written to exercise the
ported engine end-to-end. It builds a small .pcap containing a mix of
plain TCP/UDP packets, DNS queries, an HTTP request, and TLS Client Hellos
with SNI for a few different domains, matching the kinds of traffic your
README's sample report describes (YouTube, Facebook, DNS, HTTPS, etc.).

If you have the original generate_test_pcap.py, drop it in this folder to
replace this file exactly - everything else in this project doesn't depend
on its internals, only on the test_dpi.pcap file it produces.
"""

import socket
import struct

PCAP_MAGIC = 0xA1B2C3D4


def eth_header(src_mac: bytes, dst_mac: bytes, ethertype: int) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", ethertype)


def ip_header(src_ip: str, dst_ip: str, proto: int, payload_len: int) -> bytes:
    total_len = 20 + payload_len
    return struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0, 64, proto, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )


def tcp_header(src_port: int, dst_port: int, flags: int, payload_len: int) -> bytes:
    return struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port, 1000, 0, (5 << 4), flags, 65535, 0, 0,
    )


def udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    length = 8 + payload_len
    return struct.pack(">HHHH", src_port, dst_port, length, 0)


def tls_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode()
    server_name_list = struct.pack(">B H", 0x00, len(sni_bytes)) + sni_bytes
    ext_sni_body = struct.pack(">H", len(server_name_list)) + server_name_list
    ext_sni = struct.pack(">HH", 0x0000, len(ext_sni_body)) + ext_sni_body

    extensions = ext_sni
    extensions_block = struct.pack(">H", len(extensions)) + extensions

    session_id = b""
    cipher_suites = struct.pack(">H", 2) + b"\x13\x01"
    compression = b"\x01\x00"

    body = (
        struct.pack(">H", 0x0303)          # client version
        + b"\x00" * 32                      # random
        + struct.pack(">B", len(session_id)) + session_id
        + cipher_suites
        + compression
        + extensions_block
    )

    handshake = struct.pack(">B", 0x01) + struct.pack(">I", len(body))[1:] + body
    record = struct.pack(">BHH", 0x16, 0x0301, len(handshake))[0:1] + struct.pack(">H", 0x0301) + struct.pack(">H", len(handshake)) + handshake
    return record


def http_get(host: str) -> bytes:
    return f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n\r\n".encode()


def dns_query(domain: str) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(struct.pack(">B", len(p)) + p.encode() for p in domain.split(".")) + b"\x00"
    question = qname + struct.pack(">HH", 1, 1)
    return header + question


def build_packet(src_mac, dst_mac, src_ip, dst_ip, proto, src_port, dst_port, payload, flags=0x18):
    if proto == 6:
        transport = tcp_header(src_port, dst_port, flags, len(payload))
    else:
        transport = udp_header(src_port, dst_port, len(payload))

    ip = ip_header(src_ip, dst_ip, proto, len(transport) + len(payload))
    eth = eth_header(src_mac, dst_mac, 0x0800)
    return eth + ip + transport + payload


def write_pcap(filename: str, packets):
    with open(filename, "wb") as f:
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1))
        ts = 1700000000
        for pkt in packets:
            f.write(struct.pack("<IIII", ts, 0, len(pkt), len(pkt)))
            f.write(pkt)
            ts += 1


def main():
    src_mac = bytes.fromhex("001122334455")
    dst_mac = bytes.fromhex("aabbccddeeff")
    client_ip = "192.168.1.100"

    packets = []

    sni_targets = [
        ("142.250.185.206", "www.youtube.com"),
        ("157.240.22.35", "www.facebook.com"),
        ("142.250.80.46", "www.google.com"),
        ("140.82.112.3", "github.com"),
        ("104.16.132.229", "example.tiktok.com"),
    ]

    for dst_ip, sni in sni_targets:
        # SYN
        packets.append(build_packet(src_mac, dst_mac, client_ip, dst_ip, 6, 54321, 443, b"", flags=0x02))
        # SYN-ACK-ish (simplified, direction not modeled)
        packets.append(build_packet(src_mac, dst_mac, dst_ip, client_ip, 6, 443, 54321, b"", flags=0x12))
        # ACK
        packets.append(build_packet(src_mac, dst_mac, client_ip, dst_ip, 6, 54321, 443, b"", flags=0x10))
        # Client Hello with SNI
        hello = tls_client_hello(sni)
        packets.append(build_packet(src_mac, dst_mac, client_ip, dst_ip, 6, 54321, 443, hello, flags=0x18))

    # Plain HTTP request
    packets.append(build_packet(src_mac, dst_mac, client_ip, "93.184.216.34", 6, 51000, 80, http_get("example.com"), flags=0x18))

    # DNS queries
    for domain in ("www.youtube.com", "example.com"):
        packets.append(build_packet(src_mac, dst_mac, client_ip, "8.8.8.8", 17, 53000, 53, dns_query(domain)))

    write_pcap("test_dpi.pcap", packets)
    print(f"Created test_dpi.pcap with {len(packets)} packets")


if __name__ == "__main__":
    main()

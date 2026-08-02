"""
Port of include/pcap_reader.h + src/pcap_reader.cpp

Reads network captures saved by Wireshark (.pcap format).

PCAP Global Header (24 bytes) - read once at the start of the file.
PCAP Packet Header (16 bytes) - precedes every packet's raw bytes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

PCAP_MAGIC_NATIVE = 0xA1B2C3D4   # Native byte order
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1  # Swapped byte order

_GLOBAL_HEADER_FMT = "<IHHiIII"   # native (little-endian) layout, matches struct packing on x86
_GLOBAL_HEADER_LEN = struct.calcsize(_GLOBAL_HEADER_FMT)

_PACKET_HEADER_FMT = "<IIII"
_PACKET_HEADER_LEN = struct.calcsize(_PACKET_HEADER_FMT)


@dataclass
class PcapGlobalHeader:
    magic_number: int = 0
    version_major: int = 0
    version_minor: int = 0
    thiszone: int = 0
    sigfigs: int = 0
    snaplen: int = 0
    network: int = 0  # Data link type (1 = Ethernet)

    def pack(self) -> bytes:
        return struct.pack(
            _GLOBAL_HEADER_FMT,
            self.magic_number,
            self.version_major,
            self.version_minor,
            self.thiszone,
            self.sigfigs,
            self.snaplen,
            self.network,
        )


@dataclass
class PcapPacketHeader:
    ts_sec: int = 0
    ts_usec: int = 0
    incl_len: int = 0
    orig_len: int = 0

    def pack(self) -> bytes:
        return struct.pack(_PACKET_HEADER_FMT, self.ts_sec, self.ts_usec, self.incl_len, self.orig_len)


@dataclass
class RawPacket:
    header: PcapPacketHeader = field(default_factory=PcapPacketHeader)
    data: bytes = b""


class PcapReader:
    """Class to read PCAP files."""

    def __init__(self) -> None:
        self._file = None
        self.global_header = PcapGlobalHeader()
        self._needs_byte_swap = False

    def __del__(self):
        self.close()

    def open(self, filename: str) -> bool:
        # Close any previously opened file
        self.close()

        try:
            # Open in binary mode - crucial for reading raw bytes
            self._file = open(filename, "rb")
        except OSError:
            print(f"Error: Could not open file: {filename}")
            return False

        raw = self._file.read(_GLOBAL_HEADER_LEN)
        if len(raw) != _GLOBAL_HEADER_LEN:
            print("Error: Could not read PCAP global header")
            self.close()
            return False

        magic, = struct.unpack("<I", raw[0:4])

        if magic == PCAP_MAGIC_NATIVE:
            self._needs_byte_swap = False
            fields = struct.unpack(_GLOBAL_HEADER_FMT, raw)
        elif magic == PCAP_MAGIC_SWAPPED:
            self._needs_byte_swap = True
            # Re-parse with swapped (big-endian) layout
            fields = struct.unpack(">IHHiIII", raw)
        else:
            print(f"Error: Invalid PCAP magic number: 0x{magic:x}")
            self.close()
            return False

        self.global_header = PcapGlobalHeader(*fields)

        print(f"Opened PCAP file: {filename}")
        print(f"  Version: {self.global_header.version_major}.{self.global_header.version_minor}")
        print(f"  Snaplen: {self.global_header.snaplen} bytes")
        link_desc = " (Ethernet)" if self.global_header.network == 1 else ""
        print(f"  Link type: {self.global_header.network}{link_desc}")

        return True

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
        self._needs_byte_swap = False

    def read_next_packet(self) -> Optional[RawPacket]:
        """Read the next packet, returns None if no more packets."""
        if self._file is None:
            return None

        raw_hdr = self._file.read(_PACKET_HEADER_LEN)
        if len(raw_hdr) != _PACKET_HEADER_LEN:
            # End of file or error
            return None

        fmt = ">IIII" if self._needs_byte_swap else "<IIII"
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, raw_hdr)

        header = PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len)

        # Sanity check on packet length
        if header.incl_len > self.global_header.snaplen or header.incl_len > 65535:
            print(f"Error: Invalid packet length: {header.incl_len}")
            return None

        data = self._file.read(header.incl_len)
        if len(data) != header.incl_len:
            print("Error: Could not read packet data")
            return None

        return RawPacket(header=header, data=data)

    def get_global_header(self) -> PcapGlobalHeader:
        return self.global_header

    def is_open(self) -> bool:
        return self._file is not None

    def needs_byte_swap(self) -> bool:
        return self._needs_byte_swap

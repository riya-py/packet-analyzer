"""
Port of include/sni_extractor.h + src/sni_extractor.cpp

SNI Extractor - Parses TLS Client Hello to extract Server Name Indication.

TLS Client Hello Structure (simplified):

Record Layer:
  - Content Type (1 byte): 0x16 = Handshake
  - Version (2 bytes): 0x0301 = TLS 1.0, 0x0303 = TLS 1.2
  - Length (2 bytes)

Handshake Layer:
  - Handshake Type (1 byte): 0x01 = Client Hello
  - Length (3 bytes)
  - Client Version (2 bytes)
  - Random (32 bytes)
  - Session ID Length (1 byte)
  - Session ID (variable)
  - Cipher Suites Length (2 bytes)
  - Cipher Suites (variable)
  - Compression Methods Length (1 byte)
  - Compression Methods (variable)
  - Extensions Length (2 bytes)
  - Extensions (variable)

SNI Extension (type 0x0000):
  - Extension Type (2 bytes): 0x0000
  - Extension Length (2 bytes)
  - SNI List Length (2 bytes)
  - SNI Type (1 byte): 0x00 = hostname
  - SNI Length (2 bytes)
  - SNI Value (variable): The hostname!
"""

from __future__ import annotations

from typing import Optional


CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXTENSION_SNI = 0x0000
SNI_TYPE_HOSTNAME = 0x00


def _read_u16_be(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _read_u24_be(data: bytes, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


class SNIExtractor:
    """TLS Client Hello / SNI extraction."""

    @staticmethod
    def is_tls_client_hello(payload: bytes, length: int) -> bool:
        # Minimum TLS record: 5 bytes header + 4 bytes handshake header
        if length < 9:
            return False

        # Byte 0: Content Type (should be 0x16 = Handshake)
        if payload[0] != CONTENT_TYPE_HANDSHAKE:
            return False

        # Bytes 1-2: TLS Version. Accept 0x0300 (SSL 3.0) through 0x0304 (TLS 1.3)
        version = _read_u16_be(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False

        # Bytes 3-4: Record length
        record_length = _read_u16_be(payload, 3)
        if record_length > length - 5:
            return False

        # Byte 5: Handshake Type (should be 0x01 = Client Hello)
        if payload[5] != HANDSHAKE_CLIENT_HELLO:
            return False

        return True

    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        if not SNIExtractor.is_tls_client_hello(payload, length):
            return None

        # Skip TLS record header (5 bytes)
        offset = 5

        # Skip handshake header: type (1) + length (3)
        offset += 4

        # Client Hello body: version (2) + random (32)
        offset += 2
        offset += 32

        # Session ID
        if offset >= length:
            return None
        session_id_length = payload[offset]
        offset += 1 + session_id_length

        # Cipher suites
        if offset + 2 > length:
            return None
        cipher_suites_length = _read_u16_be(payload, offset)
        offset += 2 + cipher_suites_length

        # Compression methods
        if offset >= length:
            return None
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length

        # Extensions
        if offset + 2 > length:
            return None
        extensions_length = _read_u16_be(payload, offset)
        offset += 2

        extensions_end = offset + extensions_length
        if extensions_end > length:
            extensions_end = length  # Truncated, but try to parse anyway

        # Parse extensions to find SNI
        while offset + 4 <= extensions_end:
            extension_type = _read_u16_be(payload, offset)
            extension_length = _read_u16_be(payload, offset + 2)
            offset += 4

            if offset + extension_length > extensions_end:
                break

            if extension_type == EXTENSION_SNI:
                # Structure: SNI List Length (2) + SNI Type (1) + SNI Length (2) + SNI Value
                if extension_length < 5:
                    break

                sni_list_length = _read_u16_be(payload, offset)
                if sni_list_length < 3:
                    break

                sni_type = payload[offset + 2]
                sni_length = _read_u16_be(payload, offset + 3)

                if sni_type != SNI_TYPE_HOSTNAME:
                    break
                if sni_length > extension_length - 5:
                    break

                sni_bytes = payload[offset + 5: offset + 5 + sni_length]
                return sni_bytes.decode("utf-8", errors="replace")

            offset += extension_length

        return None

    @staticmethod
    def extract_extensions(payload: bytes, length: int):
        """Extract all extensions (for debugging/logging). Abbreviated, as in the original."""
        return []


class QUICSNIExtractor:
    """QUIC Initial packets also contain TLS Client Hello (in CRYPTO frames)."""

    @staticmethod
    def is_quic_initial(payload: bytes, length: int) -> bool:
        if length < 5:
            return False

        first_byte = payload[0]

        # Long header form
        if (first_byte & 0x80) == 0:
            return False

        # Common QUIC versions: 0x00000001 (v1), 0xff000000+ (drafts) - lenient here
        return True

    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        if not QUICSNIExtractor.is_quic_initial(payload, length):
            return None

        # Search for TLS Client Hello pattern within the QUIC packet
        for i in range(length - 50):
            if payload[i] == 0x01:  # Client Hello handshake type
                start = i - 5
                if start < 0:
                    continue
                result = SNIExtractor.extract(payload[start:], length - i + 5)
                if result:
                    return result

        return None


class HTTPHostExtractor:
    """Extract Host header from unencrypted HTTP requests."""

    _METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")

    @staticmethod
    def is_http_request(payload: bytes, length: int) -> bool:
        if length < 4:
            return False
        prefix = payload[0:4]
        return prefix in HTTPHostExtractor._METHODS

    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        if not HTTPHostExtractor.is_http_request(payload, length):
            return None

        host_header_len = 6  # "Host: "

        i = 0
        while i + host_header_len < length:
            c0, c1, c2, c3, c4 = payload[i], payload[i + 1], payload[i + 2], payload[i + 3], payload[i + 4]
            if (
                c0 in (ord("H"), ord("h"))
                and c1 in (ord("o"), ord("O"))
                and c2 in (ord("s"), ord("S"))
                and c3 in (ord("t"), ord("T"))
                and c4 == ord(":")
            ):
                start = i + 5
                while start < length and payload[start] in (ord(" "), ord("\t")):
                    start += 1

                end = start
                while end < length and payload[end] not in (ord("\r"), ord("\n")):
                    end += 1

                if end > start:
                    host = payload[start:end].decode("utf-8", errors="replace")
                    colon_pos = host.find(":")
                    if colon_pos != -1:
                        host = host[:colon_pos]
                    return host
            i += 1

        return None


class DNSExtractor:
    """Extract queried domain from a DNS request."""

    @staticmethod
    def is_dns_query(payload: bytes, length: int) -> bool:
        # Minimum DNS header is 12 bytes
        if length < 12:
            return False

        flags = payload[2]
        if flags & 0x80:
            return False  # This is a response, not a query

        qdcount = (payload[4] << 8) | payload[5]
        if qdcount == 0:
            return False

        return True

    @staticmethod
    def extract_query(payload: bytes, length: int) -> Optional[str]:
        if not DNSExtractor.is_dns_query(payload, length):
            return None

        offset = 12
        labels = []

        while offset < length:
            label_length = payload[offset]

            if label_length == 0:
                break  # End of domain name

            if label_length > 63:
                break  # Compression pointer or invalid

            offset += 1
            if offset + label_length > length:
                break

            labels.append(payload[offset:offset + label_length].decode("utf-8", errors="replace"))
            offset += label_length

        domain = ".".join(labels)
        return domain if domain else None

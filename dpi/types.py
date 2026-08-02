"""
Port of include/types.h + src/types.cpp

Core data structures used throughout the DPI engine:
  - FiveTuple: uniquely identifies a connection/flow
  - AppType: application classification enum
  - ConnectionState / PacketAction: state machine enums
  - Connection: tracked per-flow entry
  - PacketJob: packet wrapper passed between threads/queues
  - DPIStats: global atomic-ish counters
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ============================================================================
# Five-Tuple: Uniquely identifies a connection/flow
# ============================================================================
@dataclass(frozen=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int  # TCP=6, UDP=17

    def reverse(self) -> "FiveTuple":
        """Create reverse tuple (for matching bidirectional flows)."""
        return FiveTuple(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)

    def __str__(self) -> str:
        def fmt_ip(ip: int) -> str:
            return f"{(ip >> 0) & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"

        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return f"{fmt_ip(self.src_ip)}:{self.src_port} -> {fmt_ip(self.dst_ip)}:{self.dst_port} ({proto})"

    # NOTE: Python's built-in dataclass(frozen=True) already provides a
    # correct, well-distributed __hash__/__eq__ based on all fields, which
    # is what FiveTupleHash + operator== did in C++. A dict keyed on
    # FiveTuple behaves exactly like std::unordered_map<FiveTuple, ..., FiveTupleHash>.


# ============================================================================
# Application Classification
# ============================================================================
class AppType(Enum):
    UNKNOWN = 0
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    TLS = auto()
    QUIC = auto()
    # Specific applications (detected via SNI)
    GOOGLE = auto()
    FACEBOOK = auto()
    YOUTUBE = auto()
    TWITTER = auto()
    INSTAGRAM = auto()
    NETFLIX = auto()
    AMAZON = auto()
    MICROSOFT = auto()
    APPLE = auto()
    WHATSAPP = auto()
    TELEGRAM = auto()
    TIKTOK = auto()
    SPOTIFY = auto()
    ZOOM = auto()
    DISCORD = auto()
    GITHUB = auto()
    CLOUDFLARE = auto()


_APP_TYPE_NAMES = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.TLS: "TLS",
    AppType.QUIC: "QUIC",
    AppType.GOOGLE: "Google",
    AppType.FACEBOOK: "Facebook",
    AppType.YOUTUBE: "YouTube",
    AppType.TWITTER: "Twitter/X",
    AppType.INSTAGRAM: "Instagram",
    AppType.NETFLIX: "Netflix",
    AppType.AMAZON: "Amazon",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
    AppType.WHATSAPP: "WhatsApp",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.ZOOM: "Zoom",
    AppType.DISCORD: "Discord",
    AppType.GITHUB: "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}


def app_type_to_string(app_type: AppType) -> str:
    return _APP_TYPE_NAMES.get(app_type, "Unknown")


def sni_to_app_type(sni: str) -> AppType:
    """Map SNI/domain to application type (mirrors sniToAppType in types.cpp)."""
    if not sni:
        return AppType.UNKNOWN

    lower_sni = sni.lower()

    # Google (including YouTube, which is owned by Google)
    if any(s in lower_sni for s in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE

    # YouTube
    if any(s in lower_sni for s in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")):
        return AppType.YOUTUBE

    # Facebook/Meta
    if any(s in lower_sni for s in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")):
        return AppType.FACEBOOK

    # Instagram (owned by Meta)
    if any(s in lower_sni for s in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM

    # WhatsApp (owned by Meta)
    if any(s in lower_sni for s in ("whatsapp", "wa.me")):
        return AppType.WHATSAPP

    # Twitter/X
    if any(s in lower_sni for s in ("twitter", "twimg", "x.com", "t.co")):
        return AppType.TWITTER

    # Netflix
    if any(s in lower_sni for s in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX

    # Amazon
    if any(s in lower_sni for s in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON

    # Microsoft
    if any(s in lower_sni for s in ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")):
        return AppType.MICROSOFT

    # Apple
    if any(s in lower_sni for s in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE

    # Telegram
    if any(s in lower_sni for s in ("telegram", "t.me")):
        return AppType.TELEGRAM

    # TikTok
    if any(s in lower_sni for s in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")):
        return AppType.TIKTOK

    # Spotify
    if any(s in lower_sni for s in ("spotify", "scdn.co")):
        return AppType.SPOTIFY

    # Zoom
    if "zoom" in lower_sni:
        return AppType.ZOOM

    # Discord
    if any(s in lower_sni for s in ("discord", "discordapp")):
        return AppType.DISCORD

    # GitHub
    if any(s in lower_sni for s in ("github", "githubusercontent")):
        return AppType.GITHUB

    # Cloudflare
    if any(s in lower_sni for s in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    # If SNI is present but not recognized, still mark as TLS/HTTPS
    return AppType.HTTPS


# ============================================================================
# Connection State
# ============================================================================
class ConnectionState(Enum):
    NEW = auto()
    ESTABLISHED = auto()
    CLASSIFIED = auto()
    BLOCKED = auto()
    CLOSED = auto()


# ============================================================================
# Packet Action (what to do with the packet)
# ============================================================================
class PacketAction(Enum):
    FORWARD = auto()  # Send to internet
    DROP = auto()      # Block/drop the packet
    INSPECT = auto()   # Needs further inspection
    LOG_ONLY = auto()  # Forward but log


# ============================================================================
# Connection Entry (tracked per flow)
# ============================================================================
@dataclass
class Connection:
    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""

    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0

    first_seen: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)

    action: PacketAction = PacketAction.FORWARD

    # For TCP state tracking
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False


# ============================================================================
# Packet wrapper for queue passing
# ============================================================================
@dataclass
class PacketJob:
    packet_id: int
    tuple: FiveTuple
    data: bytes
    eth_offset: int = 0
    ip_offset: int = 0
    transport_offset: int = 0
    payload_offset: int = 0
    payload_length: int = 0
    tcp_flags: int = 0

    ts_sec: int = 0
    ts_usec: int = 0

    @property
    def payload_data(self) -> bytes:
        """Points into original packet, like the C++ raw pointer did."""
        if self.payload_length and self.payload_offset < len(self.data):
            return self.data[self.payload_offset:self.payload_offset + self.payload_length]
        return b""


# ============================================================================
# Statistics - thread-safe counters (C++ used std::atomic<uint64_t>)
# ============================================================================
class DPIStats:
    """
    Plain ints aren't atomic across threads in a way that guarantees no lost
    updates under the GIL for compound operations, so each counter gets its
    own lock-free-ish increment guarded by a lightweight lock, mirroring the
    thread-safety guarantee of std::atomic<uint64_t> in the original code.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded_packets = 0
        self.dropped_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.other_packets = 0
        self.active_connections = 0

    def increment(self, field_name: str, amount: int = 1) -> None:
        with self._lock:
            setattr(self, field_name, getattr(self, field_name) + amount)

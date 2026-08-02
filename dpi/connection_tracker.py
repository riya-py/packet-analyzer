"""
Port of include/connection_tracker.h + src/connection_tracker.cpp

Connection Tracker - Maintains flow table for all active connections.

Each FP thread has its own ConnectionTracker instance (no sharing needed
since connections are consistently hashed to the same FP).

Features:
- Track connection state (NEW -> ESTABLISHED -> CLASSIFIED -> CLOSED)
- Store classification results (app type, SNI)
- Maintain per-flow statistics
- Timeout inactive connections
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .types import AppType, Connection, ConnectionState, FiveTuple, PacketAction


class ConnectionTracker:
    def __init__(self, fp_id: int, max_connections: int = 100_000) -> None:
        self.fp_id = fp_id
        self.max_connections = max_connections

        # Connection table. FiveTuple's __hash__/__eq__ ensure consistent
        # mapping, so we don't need to handle bidirectional flows specially here.
        self._connections: Dict[FiveTuple, Connection] = {}

        self._total_seen = 0
        self._classified_count = 0
        self._blocked_count = 0

    def get_or_create_connection(self, tuple_: FiveTuple) -> Connection:
        conn = self._connections.get(tuple_)
        if conn is not None:
            return conn

        # Check if we need to evict old connections
        if len(self._connections) >= self.max_connections:
            self._evict_oldest()

        now = time.monotonic()
        conn = Connection(tuple=tuple_, state=ConnectionState.NEW, first_seen=now, last_seen=now)
        self._connections[tuple_] = conn
        self._total_seen += 1

        return conn

    def get_connection(self, tuple_: FiveTuple) -> Optional[Connection]:
        conn = self._connections.get(tuple_)
        if conn is not None:
            return conn

        # Try reverse tuple (for bidirectional matching)
        return self._connections.get(tuple_.reverse())

    def update_connection(self, conn: Optional[Connection], packet_size: int, is_outbound: bool) -> None:
        if conn is None:
            return

        conn.last_seen = time.monotonic()

        if is_outbound:
            conn.packets_out += 1
            conn.bytes_out += packet_size
        else:
            conn.packets_in += 1
            conn.bytes_in += packet_size

    def classify_connection(self, conn: Optional[Connection], app: AppType, sni: str) -> None:
        if conn is None:
            return

        if conn.state != ConnectionState.CLASSIFIED:
            conn.app_type = app
            conn.sni = sni
            conn.state = ConnectionState.CLASSIFIED
            self._classified_count += 1

    def block_connection(self, conn: Optional[Connection]) -> None:
        if conn is None:
            return

        conn.state = ConnectionState.BLOCKED
        conn.action = PacketAction.DROP
        self._blocked_count += 1

    def close_connection(self, tuple_: FiveTuple) -> None:
        conn = self._connections.get(tuple_)
        if conn is not None:
            conn.state = ConnectionState.CLOSED

    def cleanup_stale(self, timeout_seconds: float = 300.0) -> int:
        now = time.monotonic()
        removed = 0

        for tuple_ in list(self._connections.keys()):
            conn = self._connections[tuple_]
            age = now - conn.last_seen
            if age > timeout_seconds or conn.state == ConnectionState.CLOSED:
                del self._connections[tuple_]
                removed += 1

        return removed

    def get_all_connections(self) -> List[Connection]:
        return list(self._connections.values())

    def get_active_count(self) -> int:
        return len(self._connections)

    @dataclass
    class TrackerStats:
        active_connections: int
        total_connections_seen: int
        classified_connections: int
        blocked_connections: int

    def get_stats(self) -> "ConnectionTracker.TrackerStats":
        return ConnectionTracker.TrackerStats(
            active_connections=len(self._connections),
            total_connections_seen=self._total_seen,
            classified_connections=self._classified_count,
            blocked_connections=self._blocked_count,
        )

    def clear(self) -> None:
        self._connections.clear()

    def for_each(self, callback: Callable[[Connection], None]) -> None:
        for conn in self._connections.values():
            callback(conn)

    def _evict_oldest(self) -> None:
        if not self._connections:
            return

        oldest_tuple = min(self._connections, key=lambda t: self._connections[t].last_seen)
        del self._connections[oldest_tuple]


class GlobalConnectionTable:
    """Aggregates stats from all FP trackers."""

    def __init__(self, num_fps: int) -> None:
        self._trackers: List[Optional[ConnectionTracker]] = [None] * num_fps
        self._lock = threading.Lock()

    def register_tracker(self, fp_id: int, tracker: ConnectionTracker) -> None:
        with self._lock:
            if fp_id < len(self._trackers):
                self._trackers[fp_id] = tracker

    @dataclass
    class GlobalStats:
        total_active_connections: int = 0
        total_connections_seen: int = 0
        app_distribution: Dict[AppType, int] = field(default_factory=dict)
        top_domains: List[Tuple[str, int]] = field(default_factory=list)

    def get_global_stats(self) -> "GlobalConnectionTable.GlobalStats":
        with self._lock:
            trackers = list(self._trackers)

        stats = GlobalConnectionTable.GlobalStats()
        domain_counts: Dict[str, int] = {}

        for tracker in trackers:
            if tracker is None:
                continue

            tracker_stats = tracker.get_stats()
            stats.total_active_connections += tracker_stats.active_connections
            stats.total_connections_seen += tracker_stats.total_connections_seen

            def collect(conn: Connection) -> None:
                stats.app_distribution[conn.app_type] = stats.app_distribution.get(conn.app_type, 0) + 1
                if conn.sni:
                    domain_counts[conn.sni] = domain_counts.get(conn.sni, 0) + 1

            tracker.for_each(collect)

        domain_vec = sorted(domain_counts.items(), key=lambda kv: kv[1], reverse=True)
        stats.top_domains = domain_vec[:20]

        return stats

    def generate_report(self) -> str:
        from .types import app_type_to_string

        stats = self.get_global_stats()

        lines = []
        lines.append("\n╔══════════════════════════════════════════════════════════════╗")
        lines.append("║               CONNECTION STATISTICS REPORT                    ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")

        lines.append(f"║ Active Connections:     {stats.total_active_connections:>10}                          ║")
        lines.append(f"║ Total Connections Seen: {stats.total_connections_seen:>10}                          ║")

        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append("║                    APPLICATION BREAKDOWN                      ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")

        total = sum(stats.app_distribution.values())
        sorted_apps = sorted(stats.app_distribution.items(), key=lambda kv: kv[1], reverse=True)

        for app, count in sorted_apps:
            pct = (100.0 * count / total) if total > 0 else 0.0
            lines.append(f"║ {app_type_to_string(app):<20}{count:>10} ({pct:>5.1f}%)           ║")

        if stats.top_domains:
            lines.append("╠══════════════════════════════════════════════════════════════╣")
            lines.append("║                      TOP DOMAINS                             ║")
            lines.append("╠══════════════════════════════════════════════════════════════╣")

            for domain, count in stats.top_domains:
                if len(domain) > 35:
                    domain = domain[:32] + "..."
                lines.append(f"║ {domain:<40}{count:>10}           ║")

        lines.append("╚══════════════════════════════════════════════════════════════╝")

        return "\n".join(lines) + "\n"

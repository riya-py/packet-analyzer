"""
Port of include/fast_path.h + src/fast_path.cpp

Fast Path Processor Thread

Each FP thread is responsible for:
1. Receiving packets from its input queue (fed by LB)
2. Connection tracking (maintaining flow state)
3. Deep Packet Inspection (SNI extraction, protocol detection)
4. Rule matching (blocking decisions)
5. Forwarding or dropping packets

FP threads are the workhorses of the DPI engine. They do the heavy lifting
of actually inspecting packet contents and making decisions.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, List, Optional

from .connection_tracker import ConnectionTracker
from .rule_manager import RuleManager
from .sni_extractor import DNSExtractor, HTTPHostExtractor, SNIExtractor
from .thread_safe_queue import ThreadSafeQueue
from .types import AppType, Connection, ConnectionState, PacketAction, PacketJob, sni_to_app_type

# Callback type for packet output (forwarding): (PacketJob, PacketAction) -> None
PacketOutputCallback = Callable[[PacketJob, PacketAction], None]

_SYN = 0x02
_ACK = 0x10
_FIN = 0x01
_RST = 0x04


class FastPathProcessor:
    def __init__(self, fp_id: int, rule_manager: Optional[RuleManager], output_callback: Optional[PacketOutputCallback]) -> None:
        self.fp_id = fp_id

        self._input_queue: ThreadSafeQueue[PacketJob] = ThreadSafeQueue(10000)
        self._conn_tracker = ConnectionTracker(fp_id)
        self._rule_manager = rule_manager
        self._output_callback = output_callback

        self._stats_lock = threading.Lock()
        self._packets_processed = 0
        self._packets_forwarded = 0
        self._packets_dropped = 0
        self._sni_extractions = 0
        self._classification_hits = 0

        self._running = False
        self._thread: threading.Thread = None

    def start(self) -> None:
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

        print(f"[FP{self.fp_id}] Started")

    def stop(self) -> None:
        if not self._running:
            return

        self._running = False
        self._input_queue.shutdown()

        if self._thread is not None:
            self._thread.join()

        print(f"[FP{self.fp_id}] Stopped (processed {self._packets_processed} packets)")

    def get_input_queue(self) -> ThreadSafeQueue:
        return self._input_queue

    def get_connection_tracker(self) -> ConnectionTracker:
        return self._conn_tracker

    @dataclass
    class FPStats:
        packets_processed: int
        packets_forwarded: int
        packets_dropped: int
        connections_tracked: int
        sni_extractions: int
        classification_hits: int

    def get_stats(self) -> "FastPathProcessor.FPStats":
        with self._stats_lock:
            return FastPathProcessor.FPStats(
                packets_processed=self._packets_processed,
                packets_forwarded=self._packets_forwarded,
                packets_dropped=self._packets_dropped,
                connections_tracked=self._conn_tracker.get_active_count(),
                sni_extractions=self._sni_extractions,
                classification_hits=self._classification_hits,
            )

    def get_id(self) -> int:
        return self.fp_id

    def is_running(self) -> bool:
        return self._running

    def _run(self) -> None:
        while self._running:
            job = self._input_queue.pop_with_timeout(0.1)

            if job is None:
                # Periodically cleanup stale connections
                self._conn_tracker.cleanup_stale(300)
                continue

            with self._stats_lock:
                self._packets_processed += 1

            action = self._process_packet(job)

            if self._output_callback:
                self._output_callback(job, action)

            with self._stats_lock:
                if action == PacketAction.DROP:
                    self._packets_dropped += 1
                else:
                    self._packets_forwarded += 1

    def _process_packet(self, job: PacketJob) -> PacketAction:
        conn = self._conn_tracker.get_or_create_connection(job.tuple)
        if conn is None:
            return PacketAction.FORWARD

        # Update connection stats
        is_outbound = True  # In this model, all packets from user are outbound
        self._conn_tracker.update_connection(conn, len(job.data), is_outbound)

        # Update TCP state if applicable
        if job.tuple.protocol == 6:  # TCP
            self._update_tcp_state(conn, job.tcp_flags)

        # If connection is already blocked, drop immediately
        if conn.state == ConnectionState.BLOCKED:
            return PacketAction.DROP

        # If connection not yet classified, try to inspect payload
        if conn.state != ConnectionState.CLASSIFIED and job.payload_length > 0:
            self._inspect_payload(job, conn)

        # Check rules (even for classified connections, as rules might change)
        return self._check_rules(job, conn)

    def _inspect_payload(self, job: PacketJob, conn: Connection) -> None:
        if job.payload_length == 0 or job.payload_offset >= len(job.data):
            return

        payload = job.payload_data

        # Try TLS SNI extraction first (most common for HTTPS)
        if self._try_extract_sni(job, conn):
            return

        # Try HTTP Host header extraction
        if self._try_extract_http_host(job, conn):
            return

        # Check for DNS (port 53)
        if job.tuple.dst_port == 53 or job.tuple.src_port == 53:
            domain = DNSExtractor.extract_query(payload, job.payload_length)
            if domain:
                self._conn_tracker.classify_connection(conn, AppType.DNS, domain)
                return

        # Basic port-based classification as fallback
        if job.tuple.dst_port == 80:
            self._conn_tracker.classify_connection(conn, AppType.HTTP, "")
        elif job.tuple.dst_port == 443:
            self._conn_tracker.classify_connection(conn, AppType.HTTPS, "")

    def _try_extract_sni(self, job: PacketJob, conn: Connection) -> bool:
        # Only for port 443 (HTTPS) or if it looks like TLS
        if job.tuple.dst_port != 443 and job.payload_length < 50:
            return False

        if job.payload_offset >= len(job.data) or job.payload_length == 0:
            return False

        payload = job.payload_data
        sni = SNIExtractor.extract(payload, job.payload_length)
        if sni:
            with self._stats_lock:
                self._sni_extractions += 1

            app = sni_to_app_type(sni)
            self._conn_tracker.classify_connection(conn, app, sni)

            if app != AppType.UNKNOWN and app != AppType.HTTPS:
                with self._stats_lock:
                    self._classification_hits += 1

            return True

        return False

    def _try_extract_http_host(self, job: PacketJob, conn: Connection) -> bool:
        # Only for port 80 (HTTP)
        if job.tuple.dst_port != 80:
            return False

        if job.payload_offset >= len(job.data) or job.payload_length == 0:
            return False

        payload = job.payload_data
        host = HTTPHostExtractor.extract(payload, job.payload_length)
        if host:
            app = sni_to_app_type(host)
            self._conn_tracker.classify_connection(conn, app, host)

            if app != AppType.UNKNOWN and app != AppType.HTTP:
                with self._stats_lock:
                    self._classification_hits += 1

            return True

        return False

    def _check_rules(self, job: PacketJob, conn: Connection) -> PacketAction:
        if self._rule_manager is None:
            return PacketAction.FORWARD

        src_ip = job.tuple.src_ip

        block_reason = self._rule_manager.should_block(src_ip, job.tuple.dst_port, conn.app_type, conn.sni)

        if block_reason:
            type_names = {
                RuleManager.BlockReasonType.IP: "IP",
                RuleManager.BlockReasonType.APP: "App",
                RuleManager.BlockReasonType.DOMAIN: "Domain",
                RuleManager.BlockReasonType.PORT: "Port",
            }
            label = type_names.get(block_reason.type, "?")
            print(f"[FP{self.fp_id}] BLOCKED packet: {label} {block_reason.detail}")

            self._conn_tracker.block_connection(conn)

            return PacketAction.DROP

        return PacketAction.FORWARD

    @staticmethod
    def _update_tcp_state(conn: Connection, tcp_flags: int) -> None:
        if tcp_flags & _SYN:
            if tcp_flags & _ACK:
                conn.syn_ack_seen = True
            else:
                conn.syn_seen = True

        if conn.syn_seen and conn.syn_ack_seen and (tcp_flags & _ACK):
            if conn.state == ConnectionState.NEW:
                conn.state = ConnectionState.ESTABLISHED

        if tcp_flags & _FIN:
            conn.fin_seen = True

        if tcp_flags & _RST:
            conn.state = ConnectionState.CLOSED

        if conn.fin_seen and (tcp_flags & _ACK):
            conn.state = ConnectionState.CLOSED


class FPManager:
    """Creates and manages multiple FP threads."""

    def __init__(self, num_fps: int, rule_manager: Optional[RuleManager], output_callback: Optional[PacketOutputCallback]) -> None:
        self._fps: List[FastPathProcessor] = [
            FastPathProcessor(i, rule_manager, output_callback) for i in range(num_fps)
        ]

        print(f"[FPManager] Created {num_fps} fast path processors")

    def start_all(self) -> None:
        for fp in self._fps:
            fp.start()

    def stop_all(self) -> None:
        for fp in self._fps:
            fp.stop()

    def get_fp(self, fp_id: int) -> FastPathProcessor:
        return self._fps[fp_id]

    def get_fp_queue(self, fp_id: int) -> ThreadSafeQueue:
        return self._fps[fp_id].get_input_queue()

    def get_queue_ptrs(self) -> List[ThreadSafeQueue]:
        return [fp.get_input_queue() for fp in self._fps]

    def get_num_fps(self) -> int:
        return len(self._fps)

    @dataclass
    class AggregatedStats:
        total_processed: int = 0
        total_forwarded: int = 0
        total_dropped: int = 0
        total_connections: int = 0

    def get_aggregated_stats(self) -> "FPManager.AggregatedStats":
        stats = FPManager.AggregatedStats()
        for fp in self._fps:
            fp_stats = fp.get_stats()
            stats.total_processed += fp_stats.packets_processed
            stats.total_forwarded += fp_stats.packets_forwarded
            stats.total_dropped += fp_stats.packets_dropped
            stats.total_connections += fp_stats.connections_tracked
        return stats

    def generate_classification_report(self) -> str:
        from .types import app_type_to_string

        app_counts = {}
        domain_counts = {}
        total_classified = 0
        total_unknown = 0

        for fp in self._fps:
            def collect(conn: Connection) -> None:
                nonlocal total_classified, total_unknown
                app_counts[conn.app_type] = app_counts.get(conn.app_type, 0) + 1

                if conn.app_type == AppType.UNKNOWN:
                    total_unknown += 1
                else:
                    total_classified += 1

                if conn.sni:
                    domain_counts[conn.sni] = domain_counts.get(conn.sni, 0) + 1

            fp.get_connection_tracker().for_each(collect)

        lines = []
        lines.append("\n╔══════════════════════════════════════════════════════════════╗")
        lines.append("║                 APPLICATION CLASSIFICATION REPORT             ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")

        total = total_classified + total_unknown
        classified_pct = (100.0 * total_classified / total) if total > 0 else 0.0
        unknown_pct = (100.0 * total_unknown / total) if total > 0 else 0.0

        lines.append(f"║ Total Connections:    {total:>10}                           ║")
        lines.append(f"║ Classified:           {total_classified:>10} ({classified_pct:.1f}%)                  ║")
        lines.append(f"║ Unidentified:         {total_unknown:>10} ({unknown_pct:.1f}%)                  ║")

        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append("║                    APPLICATION DISTRIBUTION                   ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")

        sorted_apps = sorted(app_counts.items(), key=lambda kv: kv[1], reverse=True)

        for app, count in sorted_apps:
            pct = (100.0 * count / total) if total > 0 else 0.0
            bar_len = int(pct / 5)  # 20 chars max
            bar = "#" * bar_len

            lines.append(
                f"║ {app_type_to_string(app):<15}{count:>8} {pct:>5.1f}% {bar:<20}   ║"
            )

        lines.append("╚══════════════════════════════════════════════════════════════╝")

        return "\n".join(lines) + "\n"

"""
Port of include/dpi_engine.h + src/dpi_engine.cpp

DPI Engine - Main orchestrator (modular version).

Architecture Overview:

  +------------------+
  |   PCAP Reader    |  (Reads packets from input file)
  +--------+---------+
           |
           v (hash to select LB)
  +--------+----------+
  |   Load Balancers  |  (N LB threads)
  +----+--------+-----+
       |        |
       v        v (hash to select FP within LB's pool)
  +----+--------+-----+
  |  Fast Path Procs  |  (M FP threads)
  +----+--------+-----+
       |        |
       v        v
  +----+--------+-----+
  |   Output Queue    |  (Packets to forward)
  +----+--------+-----+
       |
       v
  +----+--------+-----+
  |   Output Writer   |  (Writes to output PCAP)
  +-------------------+
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from . import pcap_reader as pcap_reader_mod
from .connection_tracker import GlobalConnectionTable
from .fast_path import FPManager
from .load_balancer import LBManager
from .packet_parser import PacketParser, ParsedPacket
from .pcap_reader import PcapPacketHeader, PcapReader
from .rule_manager import RuleManager
from .thread_safe_queue import ThreadSafeQueue
from .types import AppType, DPIStats, FiveTuple, PacketAction, PacketJob, app_type_to_string


class DPIEngine:
    @dataclass
    class Config:
        num_load_balancers: int = 2
        fps_per_lb: int = 2
        queue_size: int = 10000
        rules_file: str = ""
        verbose: bool = False

    def __init__(self, config: "DPIEngine.Config") -> None:
        self.config = config

        self._rule_manager: RuleManager = None
        self._global_conn_table: GlobalConnectionTable = None

        self._fp_manager: FPManager = None
        self._lb_manager: LBManager = None

        self._output_queue: ThreadSafeQueue[PacketJob] = ThreadSafeQueue(10000)
        self._output_thread: threading.Thread = None
        self._output_file = None
        self._output_lock = threading.Lock()

        self.stats = DPIStats()

        self._running = False
        self._processing_complete = False

        self._reader_thread: threading.Thread = None

        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                    DPI ENGINE v1.0                            ║")
        print("║               Deep Packet Inspection System                   ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ Configuration:                                                ║")
        print(f"║   Load Balancers:    {config.num_load_balancers:>3}                                       ║")
        print(f"║   FPs per LB:        {config.fps_per_lb:>3}                                       ║")
        print(f"║   Total FP threads:  {config.num_load_balancers * config.fps_per_lb:>3}                                       ║")
        print("╚══════════════════════════════════════════════════════════════╝")

    def initialize(self) -> bool:
        self._rule_manager = RuleManager()

        if self.config.rules_file:
            self._rule_manager.load_rules(self.config.rules_file)

        def output_cb(job: PacketJob, action: PacketAction) -> None:
            self._handle_output(job, action)

        total_fps = self.config.num_load_balancers * self.config.fps_per_lb
        self._fp_manager = FPManager(total_fps, self._rule_manager, output_cb)

        self._lb_manager = LBManager(
            self.config.num_load_balancers,
            self.config.fps_per_lb,
            self._fp_manager.get_queue_ptrs(),
        )

        self._global_conn_table = GlobalConnectionTable(total_fps)
        for i in range(total_fps):
            self._global_conn_table.register_tracker(i, self._fp_manager.get_fp(i).get_connection_tracker())

        print("[DPIEngine] Initialized successfully")
        return True

    def start(self) -> None:
        if self._running:
            return

        self._running = True
        self._processing_complete = False

        self._output_thread = threading.Thread(target=self._output_thread_func, daemon=True)
        self._output_thread.start()

        self._fp_manager.start_all()
        self._lb_manager.start_all()

        print("[DPIEngine] All threads started")

    def stop(self) -> None:
        if not self._running:
            return

        self._running = False

        if self._lb_manager:
            self._lb_manager.stop_all()

        if self._fp_manager:
            self._fp_manager.stop_all()

        self._output_queue.shutdown()
        if self._output_thread is not None:
            self._output_thread.join()

        print("[DPIEngine] All threads stopped")

    def wait_for_completion(self) -> None:
        if self._reader_thread is not None:
            self._reader_thread.join()

        # Wait a bit for queues to drain
        time.sleep(0.5)

        self._processing_complete = True

    def process_file(self, input_file: str, output_file: str) -> bool:
        print(f"\n[DPIEngine] Processing: {input_file}")
        print(f"[DPIEngine] Output to:  {output_file}\n")

        if self._rule_manager is None:
            if not self.initialize():
                return False

        try:
            self._output_file = open(output_file, "wb")
        except OSError:
            print("[DPIEngine] Error: Cannot open output file")
            return False

        self.start()

        self._reader_thread = threading.Thread(target=self._reader_thread_func, args=(input_file,), daemon=True)
        self._reader_thread.start()

        self.wait_for_completion()

        # Give some time for final packets to process
        time.sleep(0.2)

        self.stop()

        if self._output_file is not None:
            self._output_file.close()
            self._output_file = None

        print(self.generate_report())
        print(self._fp_manager.generate_classification_report())

        return True

    def _reader_thread_func(self, input_file: str) -> None:
        reader = PcapReader()

        if not reader.open(input_file):
            print("[Reader] Error: Cannot open input file")
            return

        self._write_output_header(reader.get_global_header())

        packet_id = 0

        print("[Reader] Starting packet processing...")

        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break

            parsed = ParsedPacket(timestamp_sec=raw.header.ts_sec, timestamp_usec=raw.header.ts_usec)
            if not PacketParser.parse(raw.data, parsed):
                continue  # Skip unparseable packets

            if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                continue

            job = self._create_packet_job(raw, parsed, packet_id)
            packet_id += 1

            self.stats.increment("total_packets")
            self.stats.increment("total_bytes", len(raw.data))

            if parsed.has_tcp:
                self.stats.increment("tcp_packets")
            elif parsed.has_udp:
                self.stats.increment("udp_packets")

            lb = self._lb_manager.get_lb_for_packet(job.tuple)
            lb.get_input_queue().push(job)

        print(f"[Reader] Finished reading {packet_id} packets")
        reader.close()

    @staticmethod
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
        result |= (octet << shift)
        return result

    def _create_packet_job(self, raw, parsed: ParsedPacket, packet_id: int) -> PacketJob:
        tuple_ = FiveTuple(
            src_ip=self._parse_ip_str(parsed.src_ip),
            dst_ip=self._parse_ip_str(parsed.dest_ip),
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol,
        )

        data = raw.data

        # Calculate offsets
        transport_offset = 14  # Ethernet header is 14 bytes
        payload_offset = transport_offset

        if len(data) > 14:
            ip_ihl = data[14] & 0x0F
            ip_header_len = ip_ihl * 4
            transport_offset = 14 + ip_header_len
            payload_offset = transport_offset

            if parsed.has_tcp and len(data) > transport_offset:
                tcp_data_offset = (data[transport_offset + 12] >> 4) & 0x0F
                tcp_header_len = tcp_data_offset * 4
                payload_offset = transport_offset + tcp_header_len
            elif parsed.has_udp:
                payload_offset = transport_offset + 8  # UDP header is 8 bytes

        payload_length = 0
        if payload_offset < len(data):
            payload_length = len(data) - payload_offset

        return PacketJob(
            packet_id=packet_id,
            tuple=tuple_,
            data=data,
            eth_offset=0,
            ip_offset=14,
            transport_offset=transport_offset,
            payload_offset=payload_offset,
            payload_length=payload_length,
            tcp_flags=parsed.tcp_flags,
            ts_sec=raw.header.ts_sec,
            ts_usec=raw.header.ts_usec,
        )

    def _output_thread_func(self) -> None:
        while self._running or not self._output_queue.empty():
            job = self._output_queue.pop_with_timeout(0.1)
            if job is not None:
                self._write_output_packet(job)

    def _handle_output(self, job: PacketJob, action: PacketAction) -> None:
        if action == PacketAction.DROP:
            self.stats.increment("dropped_packets")
            return

        self.stats.increment("forwarded_packets")
        self._output_queue.push(job)

    def _write_output_header(self, header) -> bool:
        with self._output_lock:
            if self._output_file is None:
                return False
            self._output_file.write(header.pack())
            return True

    def _write_output_packet(self, job: PacketJob) -> None:
        with self._output_lock:
            if self._output_file is None:
                return

            pkt_header = PcapPacketHeader(
                ts_sec=job.ts_sec,
                ts_usec=job.ts_usec,
                incl_len=len(job.data),
                orig_len=len(job.data),
            )

            self._output_file.write(pkt_header.pack())
            self._output_file.write(job.data)

    # ========== Rule Management API ==========

    def block_ip(self, ip: str) -> None:
        if self._rule_manager:
            self._rule_manager.block_ip(ip)

    def unblock_ip(self, ip: str) -> None:
        if self._rule_manager:
            self._rule_manager.unblock_ip(ip)

    def block_app(self, app) -> None:
        if isinstance(app, str):
            for a in AppType:
                if app_type_to_string(a) == app:
                    self.block_app(a)
                    return
            print(f"[DPIEngine] Unknown app: {app}")
            return

        if self._rule_manager:
            self._rule_manager.block_app(app)

    def unblock_app(self, app) -> None:
        if isinstance(app, str):
            for a in AppType:
                if app_type_to_string(a) == app:
                    self.unblock_app(a)
                    return
            return

        if self._rule_manager:
            self._rule_manager.unblock_app(app)

    def block_domain(self, domain: str) -> None:
        if self._rule_manager:
            self._rule_manager.block_domain(domain)

    def unblock_domain(self, domain: str) -> None:
        if self._rule_manager:
            self._rule_manager.unblock_domain(domain)

    def load_rules(self, filename: str) -> bool:
        if self._rule_manager:
            return self._rule_manager.load_rules(filename)
        return False

    def save_rules(self, filename: str) -> bool:
        if self._rule_manager:
            return self._rule_manager.save_rules(filename)
        return False

    # ========== Reporting ==========

    def generate_report(self) -> str:
        lines = []
        lines.append("\n╔══════════════════════════════════════════════════════════════╗")
        lines.append("║                    DPI ENGINE STATISTICS                      ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")

        lines.append("║ PACKET STATISTICS                                             ║")
        lines.append(f"║   Total Packets:      {self.stats.total_packets:>12}                        ║")
        lines.append(f"║   Total Bytes:        {self.stats.total_bytes:>12}                        ║")
        lines.append(f"║   TCP Packets:        {self.stats.tcp_packets:>12}                        ║")
        lines.append(f"║   UDP Packets:        {self.stats.udp_packets:>12}                        ║")

        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append("║ FILTERING STATISTICS                                          ║")
        lines.append(f"║   Forwarded:          {self.stats.forwarded_packets:>12}                        ║")
        lines.append(f"║   Dropped/Blocked:    {self.stats.dropped_packets:>12}                        ║")

        if self.stats.total_packets > 0:
            drop_rate = 100.0 * self.stats.dropped_packets / self.stats.total_packets
            lines.append(f"║   Drop Rate:          {drop_rate:>11.2f}%                        ║")

        if self._lb_manager:
            lb_stats = self._lb_manager.get_aggregated_stats()
            lines.append("╠══════════════════════════════════════════════════════════════╣")
            lines.append("║ LOAD BALANCER STATISTICS                                      ║")
            lines.append(f"║   LB Received:        {lb_stats.total_received:>12}                        ║")
            lines.append(f"║   LB Dispatched:      {lb_stats.total_dispatched:>12}                        ║")

        if self._fp_manager:
            fp_stats = self._fp_manager.get_aggregated_stats()
            lines.append("╠══════════════════════════════════════════════════════════════╣")
            lines.append("║ FAST PATH STATISTICS                                          ║")
            lines.append(f"║   FP Processed:       {fp_stats.total_processed:>12}                        ║")
            lines.append(f"║   FP Forwarded:       {fp_stats.total_forwarded:>12}                        ║")
            lines.append(f"║   FP Dropped:         {fp_stats.total_dropped:>12}                        ║")
            lines.append(f"║   Active Connections: {fp_stats.total_connections:>12}                        ║")

        if self._rule_manager:
            rule_stats = self._rule_manager.get_stats()
            lines.append("╠══════════════════════════════════════════════════════════════╣")
            lines.append("║ BLOCKING RULES                                                ║")
            lines.append(f"║   Blocked IPs:        {rule_stats.blocked_ips:>12}                        ║")
            lines.append(f"║   Blocked Apps:       {rule_stats.blocked_apps:>12}                        ║")
            lines.append(f"║   Blocked Domains:    {rule_stats.blocked_domains:>12}                        ║")
            lines.append(f"║   Blocked Ports:      {rule_stats.blocked_ports:>12}                        ║")

        lines.append("╚══════════════════════════════════════════════════════════════╝")

        return "\n".join(lines) + "\n"

    def generate_classification_report(self) -> str:
        if self._fp_manager:
            return self._fp_manager.generate_classification_report()
        return ""

    def get_stats(self) -> DPIStats:
        return self.stats

    def print_status(self) -> None:
        print("\n--- Live Status ---")
        print(
            f"Packets: {self.stats.total_packets}"
            f" | Forwarded: {self.stats.forwarded_packets}"
            f" | Dropped: {self.stats.dropped_packets}"
        )

        if self._fp_manager:
            fp_stats = self._fp_manager.get_aggregated_stats()
            print(f"Connections: {fp_stats.total_connections}")

    def get_rule_manager(self) -> RuleManager:
        return self._rule_manager

    def is_running(self) -> bool:
        return self._running

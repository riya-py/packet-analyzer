#!/usr/bin/env python3
"""
Port of src/dpi_mt.cpp

Multi-threaded DPI Engine - self-contained (matches your README's
"dpi_engine" / dpi_engine.exe multi-threaded build target).

Architecture: Reader -> LB threads -> FP threads -> Output

This module intentionally defines its own TSQueue / Rules / Stats /
FastPath / LoadBalancer / DPIEngine classes (mirroring dpi_mt.cpp, which
does NOT use the modular dpi/ package) rather than importing from dpi/,
to keep this a faithful 1:1 port of that specific file.
"""

from __future__ import annotations

import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dpi.packet_parser import PacketParser, ParsedPacket
from dpi.pcap_reader import PcapPacketHeader, PcapReader
from dpi.sni_extractor import HTTPHostExtractor, SNIExtractor
from dpi.types import AppType, FiveTuple, app_type_to_string


# =============================================================================
# Thread-Safe Queue
# =============================================================================
class TSQueue:
    def __init__(self, max_size: int = 10000) -> None:
        self._queue: deque = deque()
        self._max_size = max_size
        self._shutdown_flag = False

        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._not_full = threading.Condition(self._lock)

    def push(self, item) -> None:
        with self._lock:
            while len(self._queue) >= self._max_size and not self._shutdown_flag:
                self._not_full.wait()
            if self._shutdown_flag:
                return
            self._queue.append(item)
            self._not_empty.notify()

    def pop(self, timeout_ms: int = 100):
        with self._lock:
            got = self._not_empty.wait_for(
                lambda: bool(self._queue) or self._shutdown_flag, timeout=timeout_ms / 1000.0
            )
            if not got:
                return None
            if not self._queue:
                return None
            item = self._queue.popleft()
            self._not_full.notify()
            return item

    def shutdown(self) -> None:
        with self._lock:
            self._shutdown_flag = True
            self._not_empty.notify_all()
            self._not_full.notify_all()

    def size(self) -> int:
        with self._lock:
            return len(self._queue)

    def is_shutdown(self) -> bool:
        return self._shutdown_flag


# =============================================================================
# Packet Job - Contains all packet data (self-contained, no pointers)
# =============================================================================
@dataclass
class Packet:
    id: int
    ts_sec: int
    ts_usec: int
    tuple: FiveTuple
    data: bytes
    tcp_flags: int
    payload_offset: int
    payload_length: int


# =============================================================================
# Flow Entry
# =============================================================================
@dataclass
class FlowEntry:
    tuple: Optional[FiveTuple] = None
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False
    classified: bool = False


# =============================================================================
# Blocking Rules
# =============================================================================
class Rules:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._blocked_ips: set = set()
        self._blocked_apps: set = set()
        self._blocked_domains: List[str] = []

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
        with self._lock:
            self._blocked_ips.add(self._parse_ip(ip))
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app: str) -> None:
        with self._lock:
            for a in AppType:
                if app_type_to_string(a) == app:
                    self._blocked_apps.add(a)
                    print(f"[Rules] Blocked app: {app}")
                    return
        print(f"[Rules] Unknown app: {app}", file=sys.stderr)

    def block_domain(self, domain: str) -> None:
        with self._lock:
            self._blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        with self._lock:
            if src_ip in self._blocked_ips:
                return True
            if app in self._blocked_apps:
                return True
            for dom in self._blocked_domains:
                if dom in sni:
                    return True
            return False


# =============================================================================
# Statistics (thread-safe)
# =============================================================================
class Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded = 0
        self.dropped = 0
        self.tcp_packets = 0
        self.udp_packets = 0

        self.app_mutex = threading.Lock()
        self.app_counts: Dict[AppType, int] = {}
        self.detected_snis: Dict[str, AppType] = {}

    def incr(self, field_name: str, amount: int = 1) -> None:
        with self._lock:
            setattr(self, field_name, getattr(self, field_name) + amount)

    def record_app(self, app: AppType, sni: str) -> None:
        with self.app_mutex:
            self.app_counts[app] = self.app_counts.get(app, 0) + 1
            if sni:
                self.detected_snis[sni] = app


# =============================================================================
# Fast Path Processor (one per FP thread)
# =============================================================================
class FastPath:
    def __init__(self, id_: int, rules: Rules, stats: Stats, output_queue: TSQueue) -> None:
        self.id_ = id_
        self.rules_ = rules
        self.stats_ = stats
        self.output_queue_ = output_queue

        self.input_queue_ = TSQueue()
        self.flows_: Dict[FiveTuple, FlowEntry] = {}

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._processed_lock = threading.Lock()
        self._processed = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.input_queue_.shutdown()
        if self._thread is not None:
            self._thread.join()

    def queue(self) -> TSQueue:
        return self.input_queue_

    def processed(self) -> int:
        with self._processed_lock:
            return self._processed

    def _run(self) -> None:
        while self._running:
            pkt = self.input_queue_.pop(100)
            if pkt is None:
                continue

            with self._processed_lock:
                self._processed += 1

            flow = self.flows_.get(pkt.tuple)
            if flow is None:
                flow = FlowEntry(tuple=pkt.tuple)
                self.flows_[pkt.tuple] = flow
            flow.packets += 1
            flow.bytes += len(pkt.data)

            if not flow.classified:
                self._classify_flow(pkt, flow)

            if not flow.blocked:
                flow.blocked = self.rules_.is_blocked(pkt.tuple.src_ip, flow.app_type, flow.sni)

            self.stats_.record_app(flow.app_type, flow.sni)

            if flow.blocked:
                self.stats_.incr("dropped")
            else:
                self.stats_.incr("forwarded")
                self.output_queue_.push(pkt)

    @staticmethod
    def _classify_flow(pkt: Packet, flow: FlowEntry) -> None:
        # Try SNI extraction for HTTPS
        if pkt.tuple.dst_port == 443 and pkt.payload_length > 5:
            payload = pkt.data[pkt.payload_offset:]
            sni = SNIExtractor.extract(payload, pkt.payload_length)
            if sni:
                flow.sni = sni
                from dpi.types import sni_to_app_type
                flow.app_type = sni_to_app_type(sni)
                flow.classified = True
                return

        # Try HTTP Host extraction
        if pkt.tuple.dst_port == 80 and pkt.payload_length > 10:
            payload = pkt.data[pkt.payload_offset:]
            host = HTTPHostExtractor.extract(payload, pkt.payload_length)
            if host:
                flow.sni = host
                from dpi.types import sni_to_app_type
                flow.app_type = sni_to_app_type(host)
                flow.classified = True
                return

        # DNS
        if pkt.tuple.dst_port == 53 or pkt.tuple.src_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return

        # Port-based fallback (but don't mark as classified - might get SNI later)
        if pkt.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif pkt.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP


# =============================================================================
# Load Balancer (one per LB thread)
# =============================================================================
class LoadBalancer:
    def __init__(self, id_: int, fps: List[FastPath]) -> None:
        self.id_ = id_
        self.fps_ = fps
        self.num_fps_ = len(fps)

        self.input_queue_ = TSQueue()

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._dispatched_lock = threading.Lock()
        self._dispatched = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.input_queue_.shutdown()
        if self._thread is not None:
            self._thread.join()

    def queue(self) -> TSQueue:
        return self.input_queue_

    def dispatched(self) -> int:
        with self._dispatched_lock:
            return self._dispatched

    def _run(self) -> None:
        while self._running:
            pkt = self.input_queue_.pop(100)
            if pkt is None:
                continue

            fp_idx = hash(pkt.tuple) % self.num_fps_
            self.fps_[fp_idx].queue().push(pkt)

            with self._dispatched_lock:
                self._dispatched += 1


# =============================================================================
# DPI Engine
# =============================================================================
class DPIEngine:
    @dataclass
    class Config:
        num_lbs: int = 2
        fps_per_lb: int = 2

    def __init__(self, cfg: "DPIEngine.Config") -> None:
        self.config_ = cfg
        total_fps = cfg.num_lbs * cfg.fps_per_lb

        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║              DPI ENGINE v2.0 (Multi-threaded)                 ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Load Balancers: {cfg.num_lbs:>2}    FPs per LB: {cfg.fps_per_lb:>2}    Total FPs: {total_fps:>2}     ║")
        print("╚══════════════════════════════════════════════════════════════╝\n")

        self.rules_ = Rules()
        self.stats_ = Stats()
        self.output_queue_ = TSQueue()

        # Create FP threads
        self.fps_: List[FastPath] = [
            FastPath(i, self.rules_, self.stats_, self.output_queue_) for i in range(total_fps)
        ]

        # Create LB threads, each managing a subset of FPs
        self.lbs_: List[LoadBalancer] = []
        for lb in range(cfg.num_lbs):
            start = lb * cfg.fps_per_lb
            lb_fps = self.fps_[start: start + cfg.fps_per_lb]
            self.lbs_.append(LoadBalancer(lb, lb_fps))

    def block_ip(self, ip: str) -> None:
        self.rules_.block_ip(ip)

    def block_app(self, app: str) -> None:
        self.rules_.block_app(app)

    def block_domain(self, dom: str) -> None:
        self.rules_.block_domain(dom)

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
        return result | (octet << shift)

    def process(self, input_file: str, output_file: str) -> bool:
        reader = PcapReader()
        if not reader.open(input_file):
            return False

        try:
            output = open(output_file, "wb")
        except OSError:
            print("Cannot open output file", file=sys.stderr)
            return False

        hdr = reader.get_global_header()
        output.write(hdr.pack())

        # Start all threads
        for fp in self.fps_:
            fp.start()
        for lb in self.lbs_:
            lb.start()

        # Start output writer thread
        output_running = threading.Event()
        output_running.set()

        def output_worker():
            while output_running.is_set() or self.output_queue_.size() > 0:
                pkt = self.output_queue_.pop(50)
                if pkt is None:
                    continue

                phdr = PcapPacketHeader(
                    ts_sec=pkt.ts_sec, ts_usec=pkt.ts_usec, incl_len=len(pkt.data), orig_len=len(pkt.data)
                )
                output.write(phdr.pack())
                output.write(pkt.data)

        output_thread = threading.Thread(target=output_worker, daemon=True)
        output_thread.start()

        # Read and dispatch packets
        print("[Reader] Processing packets...")

        pkt_id = 0

        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break

            parsed = ParsedPacket(timestamp_sec=raw.header.ts_sec, timestamp_usec=raw.header.ts_usec)
            if not PacketParser.parse(raw.data, parsed):
                continue
            if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                continue

            tuple_ = FiveTuple(
                src_ip=self._parse_ip_str(parsed.src_ip),
                dst_ip=self._parse_ip_str(parsed.dest_ip),
                src_port=parsed.src_port,
                dst_port=parsed.dest_port,
                protocol=parsed.protocol,
            )

            data = raw.data
            payload_offset = 14  # Ethernet
            payload_length = 0

            if len(data) > 14:
                ip_ihl = data[14] & 0x0F
                payload_offset += ip_ihl * 4

                if parsed.has_tcp and payload_offset + 12 < len(data):
                    tcp_off = (data[payload_offset + 12] >> 4) & 0x0F
                    payload_offset += tcp_off * 4
                elif parsed.has_udp:
                    payload_offset += 8

                if payload_offset < len(data):
                    payload_length = len(data) - payload_offset
                else:
                    payload_length = 0

            pkt = Packet(
                id=pkt_id,
                ts_sec=raw.header.ts_sec,
                ts_usec=raw.header.ts_usec,
                tuple=tuple_,
                data=data,
                tcp_flags=parsed.tcp_flags,
                payload_offset=payload_offset,
                payload_length=payload_length,
            )
            pkt_id += 1

            self.stats_.incr("total_packets")
            self.stats_.incr("total_bytes", len(data))
            if parsed.has_tcp:
                self.stats_.incr("tcp_packets")
            elif parsed.has_udp:
                self.stats_.incr("udp_packets")

            lb_idx = hash(tuple_) % len(self.lbs_)
            self.lbs_[lb_idx].queue().push(pkt)

        print(f"[Reader] Done reading {pkt_id} packets")
        reader.close()

        # Wait for queues to drain
        time.sleep(0.5)

        # Stop all threads
        for lb in self.lbs_:
            lb.stop()
        for fp in self.fps_:
            fp.stop()

        output_running.clear()
        self.output_queue_.shutdown()
        output_thread.join()

        output.close()

        self._print_report()

        return True

    def _print_report(self) -> None:
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                      PROCESSING REPORT                        ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Total Packets:      {self.stats_.total_packets:>12}                           ║")
        print(f"║ Total Bytes:        {self.stats_.total_bytes:>12}                           ║")
        print(f"║ TCP Packets:        {self.stats_.tcp_packets:>12}                           ║")
        print(f"║ UDP Packets:        {self.stats_.udp_packets:>12}                           ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Forwarded:          {self.stats_.forwarded:>12}                           ║")
        print(f"║ Dropped:            {self.stats_.dropped:>12}                           ║")

        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ THREAD STATISTICS                                             ║")
        for i, lb in enumerate(self.lbs_):
            print(f"║   LB{i} dispatched:   {lb.dispatched():>12}                           ║")
        for i, fp in enumerate(self.fps_):
            print(f"║   FP{i} processed:    {fp.processed():>12}                           ║")

        print("╠══════════════════════════════════════════════════════════════╣")
        print("║                   APPLICATION BREAKDOWN                       ║")
        print("╠══════════════════════════════════════════════════════════════╣")

        with self.stats_.app_mutex:
            sorted_apps = sorted(self.stats_.app_counts.items(), key=lambda kv: kv[1], reverse=True)
            total = self.stats_.total_packets
            for app, count in sorted_apps:
                pct = 100.0 * count / total if total else 0.0
                bar = "#" * int(pct / 5)
                print(f"║ {app_type_to_string(app):<15}{count:>8} {pct:>5.1f}% {bar:<20}  ║")

            print("╚══════════════════════════════════════════════════════════════╝")

            if self.stats_.detected_snis:
                print("\n[Detected Domains/SNIs]")
                for sni, app in self.stats_.detected_snis.items():
                    print(f"  - {sni} -> {app_type_to_string(app)}")


# =============================================================================
# Main
# =============================================================================
def print_usage(prog: str) -> None:
    print(f"""
DPI Engine v2.0 - Multi-threaded Deep Packet Inspection
========================================================

Usage: {prog} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)

Example:
  {prog} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
""")


def main(argv) -> int:
    if len(argv) < 3:
        print_usage(argv[0])
        return 1

    input_ = argv[1]
    output = argv[2]

    cfg = DPIEngine.Config()
    block_ips: List[str] = []
    block_apps: List[str] = []
    block_domains: List[str] = []

    i = 3
    while i < len(argv):
        arg = argv[i]
        if arg == "--block-ip" and i + 1 < len(argv):
            i += 1
            block_ips.append(argv[i])
        elif arg == "--block-app" and i + 1 < len(argv):
            i += 1
            block_apps.append(argv[i])
        elif arg == "--block-domain" and i + 1 < len(argv):
            i += 1
            block_domains.append(argv[i])
        elif arg == "--lbs" and i + 1 < len(argv):
            i += 1
            cfg.num_lbs = int(argv[i])
        elif arg == "--fps" and i + 1 < len(argv):
            i += 1
            cfg.fps_per_lb = int(argv[i])
        i += 1

    engine = DPIEngine(cfg)

    for ip in block_ips:
        engine.block_ip(ip)
    for app in block_apps:
        engine.block_app(app)
    for dom in block_domains:
        engine.block_domain(dom)

    if not engine.process(input_, output):
        return 1

    print(f"\nOutput written to: {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

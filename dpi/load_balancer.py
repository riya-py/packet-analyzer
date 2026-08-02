"""
Port of include/load_balancer.h + src/load_balancer.cpp

Load Balancer Thread

Architecture:
  Reader Thread -> LB Queues -> LB Threads -> FP Queues -> FP Threads

Each LB thread:
1. Receives packets from its input queue (fed by reader)
2. Extracts five-tuple from packet
3. Hashes the tuple to determine target FP
4. Forwards packet to appropriate FP queue

Load Balancing Strategy:
- Consistent hashing ensures same flow always goes to same FP
- This is critical for proper connection tracking and DPI

Example with 2 LBs and 4 FPs:
  LB0 handles FP0, FP1 (hash % 2 == 0 or 1)
  LB1 handles FP2, FP3 (hash % 2 == 0 or 1, but offset by 2)
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import List

from .thread_safe_queue import ThreadSafeQueue
from .types import FiveTuple, PacketJob


class LoadBalancer:
    def __init__(self, lb_id: int, fp_queues: List[ThreadSafeQueue], fp_start_id: int) -> None:
        self.lb_id = lb_id
        self._fp_start_id = fp_start_id
        self._num_fps = len(fp_queues)

        self._input_queue: ThreadSafeQueue[PacketJob] = ThreadSafeQueue(10000)
        self._fp_queues = fp_queues

        self._packets_received = 0
        self._packets_dispatched = 0
        self._per_fp_counts = [0] * len(fp_queues)
        self._stats_lock = threading.Lock()

        self._running = False
        self._thread: threading.Thread = None

    def start(self) -> None:
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

        print(f"[LB{self.lb_id}] Started (serving FP{self._fp_start_id}-FP{self._fp_start_id + self._num_fps - 1})")

    def stop(self) -> None:
        if not self._running:
            return

        self._running = False
        self._input_queue.shutdown()

        if self._thread is not None:
            self._thread.join()

        print(f"[LB{self.lb_id}] Stopped")

    def get_input_queue(self) -> ThreadSafeQueue:
        return self._input_queue

    @dataclass
    class LBStats:
        packets_received: int = 0
        packets_dispatched: int = 0
        per_fp_packets: List[int] = field(default_factory=list)

    def get_stats(self) -> "LoadBalancer.LBStats":
        with self._stats_lock:
            return LoadBalancer.LBStats(self._packets_received, self._packets_dispatched, list(self._per_fp_counts))

    def get_id(self) -> int:
        return self.lb_id

    def is_running(self) -> bool:
        return self._running

    def _run(self) -> None:
        while self._running:
            job = self._input_queue.pop_with_timeout(0.1)

            if job is None:
                continue  # Timeout or shutdown

            with self._stats_lock:
                self._packets_received += 1

            fp_index = self._select_fp(job.tuple)

            self._fp_queues[fp_index].push(job)

            with self._stats_lock:
                self._packets_dispatched += 1
                self._per_fp_counts[fp_index] += 1

    def _select_fp(self, tuple_: FiveTuple) -> int:
        return hash(tuple_) % self._num_fps


class LBManager:
    """Creates and manages multiple LB threads."""

    def __init__(self, num_lbs: int, fps_per_lb: int, fp_queues: List[ThreadSafeQueue]) -> None:
        self._fps_per_lb = fps_per_lb
        self._lbs: List[LoadBalancer] = []

        for lb_id in range(num_lbs):
            fp_start = lb_id * fps_per_lb
            lb_fp_queues = fp_queues[fp_start: fp_start + fps_per_lb]
            self._lbs.append(LoadBalancer(lb_id, lb_fp_queues, fp_start))

        print(f"[LBManager] Created {num_lbs} load balancers, {fps_per_lb} FPs each")

    def start_all(self) -> None:
        for lb in self._lbs:
            lb.start()

    def stop_all(self) -> None:
        for lb in self._lbs:
            lb.stop()

    def get_lb_for_packet(self, tuple_: FiveTuple) -> LoadBalancer:
        lb_index = hash(tuple_) % len(self._lbs)
        return self._lbs[lb_index]

    def get_lb(self, lb_id: int) -> LoadBalancer:
        return self._lbs[lb_id]

    def get_num_lbs(self) -> int:
        return len(self._lbs)

    @dataclass
    class AggregatedStats:
        total_received: int = 0
        total_dispatched: int = 0

    def get_aggregated_stats(self) -> "LBManager.AggregatedStats":
        stats = LBManager.AggregatedStats()
        for lb in self._lbs:
            lb_stats = lb.get_stats()
            stats.total_received += lb_stats.packets_received
            stats.total_dispatched += lb_stats.packets_dispatched
        return stats

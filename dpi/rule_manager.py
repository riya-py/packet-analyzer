"""
Port of include/rule_manager.h + src/rule_manager.cpp

Rule Manager - Manages blocking/filtering rules.

Rules can be:
1. IP-based: Block specific source IPs
2. App-based: Block specific applications (detected via SNI)
3. Domain-based: Block specific domains
4. Port-based: Block specific destination ports

Rules are thread-safe for concurrent access from FP threads. C++ used
std::shared_mutex (readers-writer lock) per rule category; Python's
threading.Lock doesn't distinguish readers from writers, but since GIL-bound
set/dict operations are already atomic for our purposes, a single lock per
category gives the same safety guarantee.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional

from .types import AppType, app_type_to_string


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
    result |= (octet << shift)
    return result


def _ip_to_string(ip: int) -> str:
    return f"{(ip >> 0) & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"


class RuleManager:
    class BlockReasonType(Enum):
        IP = auto()
        APP = auto()
        DOMAIN = auto()
        PORT = auto()

    @dataclass
    class BlockReason:
        type: "RuleManager.BlockReasonType"
        detail: str

    @dataclass
    class RuleStats:
        blocked_ips: int
        blocked_apps: int
        blocked_domains: int
        blocked_ports: int

    def __init__(self) -> None:
        self._ip_lock = threading.Lock()
        self._blocked_ips: set = set()

        self._app_lock = threading.Lock()
        self._blocked_apps: set = set()

        self._domain_lock = threading.Lock()
        self._blocked_domains: set = set()
        self._domain_patterns: List[str] = []  # For wildcard matching

        self._port_lock = threading.Lock()
        self._blocked_ports: set = set()

    # ========== IP Blocking ==========

    def block_ip(self, ip) -> None:
        addr = _parse_ip(ip) if isinstance(ip, str) else ip
        with self._ip_lock:
            self._blocked_ips.add(addr)
        print(f"[RuleManager] Blocked IP: {_ip_to_string(addr)}")

    def unblock_ip(self, ip) -> None:
        addr = _parse_ip(ip) if isinstance(ip, str) else ip
        with self._ip_lock:
            self._blocked_ips.discard(addr)
        print(f"[RuleManager] Unblocked IP: {_ip_to_string(addr)}")

    def is_ip_blocked(self, ip: int) -> bool:
        with self._ip_lock:
            return ip in self._blocked_ips

    def get_blocked_ips(self) -> List[str]:
        with self._ip_lock:
            return [_ip_to_string(ip) for ip in self._blocked_ips]

    # ========== Application Blocking ==========

    def block_app(self, app: AppType) -> None:
        with self._app_lock:
            self._blocked_apps.add(app)
        print(f"[RuleManager] Blocked app: {app_type_to_string(app)}")

    def unblock_app(self, app: AppType) -> None:
        with self._app_lock:
            self._blocked_apps.discard(app)
        print(f"[RuleManager] Unblocked app: {app_type_to_string(app)}")

    def is_app_blocked(self, app: AppType) -> bool:
        with self._app_lock:
            return app in self._blocked_apps

    def get_blocked_apps(self) -> List[AppType]:
        with self._app_lock:
            return list(self._blocked_apps)

    # ========== Domain Blocking ==========

    def block_domain(self, domain: str) -> None:
        with self._domain_lock:
            if "*" in domain:
                self._domain_patterns.append(domain)
            else:
                self._blocked_domains.add(domain)
        print(f"[RuleManager] Blocked domain: {domain}")

    def unblock_domain(self, domain: str) -> None:
        with self._domain_lock:
            if "*" in domain:
                if domain in self._domain_patterns:
                    self._domain_patterns.remove(domain)
            else:
                self._blocked_domains.discard(domain)
        print(f"[RuleManager] Unblocked domain: {domain}")

    @staticmethod
    def _domain_matches_pattern(domain: str, pattern: str) -> bool:
        # Handle *.example.com pattern
        if len(pattern) >= 2 and pattern[0] == "*" and pattern[1] == ".":
            suffix = pattern[1:]  # .example.com

            if domain.endswith(suffix):
                return True

            # Also match the bare domain (example.com matches *.example.com)
            if domain == pattern[2:]:
                return True

        return False

    def is_domain_blocked(self, domain: str) -> bool:
        with self._domain_lock:
            if domain in self._blocked_domains:
                return True

            lower_domain = domain.lower()
            for pattern in self._domain_patterns:
                if self._domain_matches_pattern(lower_domain, pattern.lower()):
                    return True

        return False

    def get_blocked_domains(self) -> List[str]:
        with self._domain_lock:
            return list(self._blocked_domains) + list(self._domain_patterns)

    # ========== Port Blocking ==========

    def block_port(self, port: int) -> None:
        with self._port_lock:
            self._blocked_ports.add(port)
        print(f"[RuleManager] Blocked port: {port}")

    def unblock_port(self, port: int) -> None:
        with self._port_lock:
            self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        with self._port_lock:
            return port in self._blocked_ports

    # ========== Combined Check ==========

    def should_block(self, src_ip: int, dst_port: int, app: AppType, domain: str) -> Optional["RuleManager.BlockReason"]:
        # Check IP first (most specific)
        if self.is_ip_blocked(src_ip):
            return RuleManager.BlockReason(RuleManager.BlockReasonType.IP, _ip_to_string(src_ip))

        # Check port
        if self.is_port_blocked(dst_port):
            return RuleManager.BlockReason(RuleManager.BlockReasonType.PORT, str(dst_port))

        # Check app
        if self.is_app_blocked(app):
            return RuleManager.BlockReason(RuleManager.BlockReasonType.APP, app_type_to_string(app))

        # Check domain
        if domain and self.is_domain_blocked(domain):
            return RuleManager.BlockReason(RuleManager.BlockReasonType.DOMAIN, domain)

        return None

    # ========== Rule Persistence ==========

    def save_rules(self, filename: str) -> bool:
        try:
            with open(filename, "w") as f:
                f.write("[BLOCKED_IPS]\n")
                for ip in self.get_blocked_ips():
                    f.write(f"{ip}\n")

                f.write("\n[BLOCKED_APPS]\n")
                for app in self.get_blocked_apps():
                    f.write(f"{app_type_to_string(app)}\n")

                f.write("\n[BLOCKED_DOMAINS]\n")
                for domain in self.get_blocked_domains():
                    f.write(f"{domain}\n")

                f.write("\n[BLOCKED_PORTS]\n")
                with self._port_lock:
                    for port in self._blocked_ports:
                        f.write(f"{port}\n")
        except OSError:
            return False

        print(f"[RuleManager] Rules saved to: {filename}")
        return True

    def load_rules(self, filename: str) -> bool:
        try:
            f = open(filename, "r")
        except OSError:
            return False

        current_section = ""
        with f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue

                if line[0] == "[":
                    current_section = line
                    continue

                if current_section == "[BLOCKED_IPS]":
                    self.block_ip(line)
                elif current_section == "[BLOCKED_APPS]":
                    for app in AppType:
                        if app_type_to_string(app) == line:
                            self.block_app(app)
                            break
                elif current_section == "[BLOCKED_DOMAINS]":
                    self.block_domain(line)
                elif current_section == "[BLOCKED_PORTS]":
                    self.block_port(int(line))

        print(f"[RuleManager] Rules loaded from: {filename}")
        return True

    def clear_all(self) -> None:
        with self._ip_lock:
            self._blocked_ips.clear()
        with self._app_lock:
            self._blocked_apps.clear()
        with self._domain_lock:
            self._blocked_domains.clear()
            self._domain_patterns.clear()
        with self._port_lock:
            self._blocked_ports.clear()
        print("[RuleManager] All rules cleared")

    def get_stats(self) -> "RuleManager.RuleStats":
        with self._ip_lock:
            blocked_ips = len(self._blocked_ips)
        with self._app_lock:
            blocked_apps = len(self._blocked_apps)
        with self._domain_lock:
            blocked_domains = len(self._blocked_domains) + len(self._domain_patterns)
        with self._port_lock:
            blocked_ports = len(self._blocked_ports)

        return RuleManager.RuleStats(blocked_ips, blocked_apps, blocked_domains, blocked_ports)

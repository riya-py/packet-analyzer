# DPI Engine (Python Port) - Deep Packet Inspection System

This is a **1:1 functional port** of the original DPI Engine to Python.
Every file below corresponds directly to a header/source pair (or a
single `.` for the two self-contained versions), and implements the
**exact same logic** — same byte offsets, same TLS/HTTP/DNS parsing rules,
same blocking rules, same thread architecture, same report formatting.
Nothing about *what* the engine does was changed; only the language.

If you've read the original README, this document mirrors its
structure section-for-section so you can cross-reference directly.

## Table of Contents
1. [What is DPI?](#1-what-is-dpi)
2. [Project Overview](#2-project-overview)
3. [File Structure](#3-file-structure)
4. [Python Implementation Mapping](#4-c-to-python-mapping)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Module](#7-deep-dive-each-module)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Running the Engine](#10-running-the-engine)
11. [Understanding the Output](#11-understanding-the-output)
12. [Notes on the Port: Threading & the GIL](#12-notes-on-the-port-threading--the-gil)

---

## 1. What is DPI?

Deep Packet Inspection (DPI) examines the contents of network packets as
they pass through a checkpoint, rather than just their headers. This
engine reads a `.pcap` capture, classifies each connection by application
(YouTube, Facebook, TikTok, etc.) using TLS SNI / HTTP Host / DNS query
inspection, applies IP/app/domain/port blocking rules, and writes the
surviving packets to an output `.pcap`.

```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

## 2. Project Overview

Just like the original, there are **two independently runnable engines**,
because that's what the original codebase actually had (`main_working.`
and `dpi_mt.` are self-contained files, separate from the "modular"
`dpi_engine.` + friends used by `main_dpi.`). The Python port
preserves this exact split — nothing was merged or "cleaned up".

| Version | File | Use Case |
|---|---|---|
| Simple (single-threaded, self-contained) | `main_working.py` | Learning, small captures |
| Multi-threaded (self-contained) | `dpi_mt.py` | Matches your README's `dpi_engine.exe` build target |
| Modular multi-threaded | `main_dpi.py` + `dpi/` package | Same architecture, split into reusable modules |

Plus two small inspection/debug tools:

| File | Purpose |
|---|---|
| `main.py` | Full packet dump/inspector (from `main.`) |
| `main_simple.py` | Minimal SNI-extraction test tool (from `main_simple.`) |

## 3. File Structure

```
dpi_python/
├── dpi/                          # The modular library (mirrors include/ + most of src/)
│   ├── __init__.py
│   ├── types.py                  # FiveTuple, AppType, Connection, PacketJob, DPIStats
│   ├── pcap_reader.py            # PCAP file reading
│   ├── packet_parser.py          # Ethernet/IP/TCP/UDP header parsing
│   ├── sni_extractor.py          # TLS SNI / HTTP Host / DNS / QUIC extraction
│   ├── rule_manager.py           # IP/App/Domain/Port blocking rules
│   ├── connection_tracker.py     # Per-flow state tracking + global stats
│   ├── thread_safe_queue.py      # Blocking producer/consumer queue
│   ├── load_balancer.py          # LoadBalancer + LBManager
│   ├── fast_path.py              # FastPathProcessor + FPManager
│   └── dpi_engine.py             # Main orchestrator (modular version)
│
├── main.py                       # ★ Packet dump tool (main.) ★
├── main_simple.py                # ★ SNI test tool (main_simple.) ★
├── main_working.py               # ★ SIMPLE VERSION ★ (main_working.)
├── dpi_mt.py                     # ★ MULTI-THREADED VERSION ★ (dpi_mt.)
├── main_dpi.py                   # Modular multi-threaded CLI (main_dpi.)
│
├── generate_test_pcap.py         # Creates test data (see note below)
├── test_dpi.pcap                 # Sample capture (generated)
├── requirements.txt               # No external deps — stdlib only
└── README.md                     # This file
```

## 4. Python Implementation Mapping

| Original concept | Python equivalent |
|---|---|
| `struct FiveTuple` + `FiveTupleHash` | `@dataclass(frozen=True) class FiveTuple` — Python auto-derives a correct `__hash__`/`__eq__` from all fields, same as the custom hash combiner did |
| `enum class AppType` | `class AppType(Enum)` |
| `std::optional<std::string>` | Return `None` / `Optional[str]` |
| `ntohs()` / `ntohl()` (via `platform.h`) | `struct.unpack(">H", ...)` / `struct.unpack(">I", ...)` — Python's `struct` module handles network (big-endian) byte order natively, so no manual byte-swap helper is needed |
| `std::unordered_map<FiveTuple, Flow, FiveTupleHash>` | `dict[FiveTuple, Flow]` |
| `std::shared_mutex` (readers-writer lock) | `threading.Lock()` per rule category (Python has no stdlib RW-lock; a plain lock gives the same correctness guarantee here since operations are short) |
| `std::atomic<uint64_t>` | Plain `int` + `threading.Lock()`-guarded increments |
| `ThreadSafeQueue<T>` (mutex + 2 condition variables) | `collections.deque` + `threading.Condition` (same blocking push/pop/timeout/shutdown semantics) |
| `std::thread` | `threading.Thread(daemon=True)` |
| Raw pointers into packet buffers (`const uint8_t*`) | Python `bytes` slicing (`data[offset:offset+length]`) — no raw pointers exist in Python, so offsets are tracked and sliced instead |

## 5. The Journey of a Packet (Simple Version)

Trace a packet through `main_working.py` — identical steps to the original:

**Step 1: Read PCAP File**
```python
reader = PcapReader()
reader.open("capture.pcap")
```
Opens the file in binary mode, reads the 24-byte global header via
`struct.unpack`, and validates the magic number (`0xa1b2c3d4`, handling the
swapped-endian variant exactly like the version did).

**Step 2: Read Each Packet**
```python
while True:
    raw = reader.read_next_packet()
    if raw is None:
        break
    # raw.data contains the packet bytes, raw.header has ts/length
```

**Step 3: Parse Protocol Headers**
```python
parsed = ParsedPacket(timestamp_sec=raw.header.ts_sec, timestamp_usec=raw.header.ts_usec)
PacketParser.parse(raw.data, parsed)
```
Same byte layout as the original:
```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header
[34-53]  TCP Header
[54+]    Payload
```

**Step 4: Create Five-Tuple and Look Up Flow**
```python
tuple_ = FiveTuple(src_ip, dst_ip, src_port, dst_port, protocol)
flow = flows.get(tuple_) or Flow(tuple=tuple_)  # get-or-create, same as flows[tuple] in 
```

**Step 5: Extract SNI (Deep Packet Inspection)**
```python
if flow.tuple.dst_port == 443:
    sni = SNIExtractor.extract(payload, payload_length)
    if sni:
        flow.sni = sni
        flow.app_type = sni_to_app_type(sni)   # "www.youtube.com" -> AppType.YOUTUBE
```

**Step 6: Check Blocking Rules**
```python
if rules.is_blocked(tuple_.src_ip, flow.app_type, flow.sni):
    flow.blocked = True
```

**Step 7: Forward or Drop** — same as : blocked packets are skipped;
forwarded packets get a `PcapPacketHeader` + raw bytes written to the
output file.

**Step 8: Generate Report** — same ASCII-box report format as the
original, app counts sorted descending with a `#`-bar visualization.

## 6. The Journey of a Packet (Multi-threaded Version)

`dpi_mt.py` uses the exact same architecture as `dpi_mt.`:

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              └───────────────────────┘
```

Consistent hashing (`hash(tuple) % num_fps`) still guarantees the same
5-tuple always lands on the same FP thread, exactly as in — this is
critical for connection tracking to work correctly, and Python's `dict`
hashing of the frozen `FiveTuple` dataclass gives the same "same flow →
same worker" guarantee that `FiveTupleHash` did.

```python
class FastPath:
    def _run(self):
        while self._running:
            pkt = self.input_queue_.pop(100)   # 100ms timeout, like popWithTimeout()
            if pkt is None:
                continue
            flow = self.flows_.get(pkt.tuple) or FlowEntry(tuple=pkt.tuple)
            if not flow.classified:
                self._classify_flow(pkt, flow)
            if not flow.blocked:
                flow.blocked = self.rules_.is_blocked(pkt.tuple.src_ip, flow.app_type, flow.sni)
            if flow.blocked:
                self.stats_.incr("dropped")
            else:
                self.stats_.incr("forwarded")
                self.output_queue_.push(pkt)
```

**`ThreadSafeQueue`** is a direct port of the template class: a
`collections.deque` guarded by a `threading.Lock`, with two
`threading.Condition`s (`not_empty` / `not_full`) standing in for the two
`std::condition_variable`s. `push()` blocks while full, `pop()` blocks
while empty, `pop(timeout_ms)` mirrors `popWithTimeout()`, and
`shutdown()` wakes every waiting thread — same behavior, same API shape.

## 7. Deep Dive: Each Module

**`dpi/pcap_reader.py`** — Reads PCAP global/packet headers via
`struct.unpack`, handles both native (`0xa1b2c3d4`) and swapped
(`0xd4c3b2a1`) magic numbers, with the same 65535-byte sanity check on
packet length as the original.

**`dpi/packet_parser.py`** — Parses Ethernet (14 bytes) → IPv4 (20+ bytes,
variable via IHL) → TCP (20+ bytes, variable via data offset) / UDP (fixed
8 bytes). Network byte order is read with `struct.unpack(">H"/">I", ...)`,
which replaces the `ntohs()`/`ntohl()` wrappers — Python's `struct`
module handles this portably without needing the `platform.h`
byte-swap-detection dance the code did.

**`dpi/sni_extractor.py`** — `SNIExtractor`, `HTTPHostExtractor`,
`DNSExtractor`, `QUICSNIExtractor`: identical byte-offset walking logic to
`sni_extractor.`, including the exact TLS Client Hello field skip order
(version → random → session ID → cipher suites → compression → extensions
→ SNI extension).

**`dpi/rule_manager.py`** — `RuleManager`: IP/App/Domain/Port blocking
with the same wildcard domain matching (`*.example.com` also matches the
bare `example.com`), and the same `[BLOCKED_IPS]`/`[BLOCKED_APPS]`/
`[BLOCKED_DOMAINS]`/`[BLOCKED_PORTS]` file format for `save_rules()` /
`load_rules()`.

**`dpi/connection_tracker.py`** — `ConnectionTracker` (per-FP flow table,
LRU eviction when full, stale-connection cleanup) and
`GlobalConnectionTable` (aggregates stats + top-20 domains across all FPs,
same report format).

**`dpi/load_balancer.py`** / **`dpi/fast_path.py`** — `LoadBalancer` +
`LBManager`, `FastPathProcessor` + `FPManager`: same two-level consistent
hashing, same TCP-state-machine tracking (SYN → SYN-ACK → ESTABLISHED,
FIN/RST → CLOSED), same rule-checking-per-packet logic (rules are
re-checked even for already-classified connections, matching the 
comment `// Check rules (even for classified connections, as rules might change)`).

**`dpi/dpi_engine.py`** — `DPIEngine`: the modular orchestrator wiring
`RuleManager` + `FPManager` + `LBManager` + `GlobalConnectionTable`
together, plus the reader/output threads and the full statistics report
generator.

## 8. How SNI Extraction Works

Unchanged from the original — even though HTTPS is encrypted, the domain
name is visible in plaintext in the first packet of the handshake:

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

```python
class SNIExtractor:
    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        if not SNIExtractor.is_tls_client_hello(payload, length):
            return None
        offset = 5                      # skip TLS record header
        offset += 4                     # skip handshake type + length
        offset += 2 + 32                # skip client version + random
        session_id_length = payload[offset]
        offset += 1 + session_id_length
        cipher_suites_length = _read_u16_be(payload, offset)
        offset += 2 + cipher_suites_length
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length
        extensions_length = _read_u16_be(payload, offset)
        offset += 2
        # ... walk extensions looking for type 0x0000 (SNI) ...
```

This is byte-for-byte the same walk as `sni_extractor.`; only the
pointer arithmetic became slice/index arithmetic.

## 9. How Blocking Works

Same three-tier check, same order (IP → Port → App → Domain), same
flow-level blocking (once a flow is marked blocked, every subsequent
packet on that flow is dropped without re-inspection):

```
Packet arrives
      │
      ▼
Is source IP in blocked list?  ──Yes──► DROP
      │No
      ▼
Is destination port blocked?   ──Yes──► DROP
      │No
      ▼
Is app type in blocked list?   ──Yes──► DROP
      │No
      ▼
Does SNI match blocked domain? ──Yes──► DROP
      │No
      ▼
            FORWARD
```

## 10. Running the Engine

 No external dependencies either (see
`requirements.txt`); everything is stdlib (`struct`, `threading`,
`dataclasses`, `enum`, `collections`).

**Prerequisites:** Python 3.9+ (uses `from __future__ import annotations`
and modern `dataclasses`/`typing` features; 3.9+ is a safe floor).

**Create test data:**
```bash
python3 generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

**Simple version:**
```bash
python3 main_working.py test_dpi.pcap output.pcap
```

**Multi-threaded version:**
```bash
python3 dpi_mt.py test_dpi.pcap output.pcap
```

**With blocking:**
```bash
python3 dpi_mt.py test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Modular version (with wildcard domains + rules file):**
```bash
python3 main_dpi.py test_dpi.pcap output.pcap \
    --block-domain "*.tiktok.com" \
    --rules blocking_rules.txt \
    --lbs 4 --fps 4
# Creates 4 LB threads × 4 FP threads = 16 processing threads
```

**Packet inspector / SNI test tool:**
```bash
python3 main.py test_dpi.pcap 10        # dump first 10 packets in detail
python3 main_simple.py test_dpi.pcap    # quick 5-tuple + SNI listing
```

## 11. Understanding the Output

Identical report sections and format to the original — packet counts,
forward/drop counts, per-thread dispatch/processed counts, and an
application breakdown with a `#`-bar chart:

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4         ║
╚══════════════════════════════════════════════════════════════╝
...
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ YouTube               4   5.2% #                               ║
...
```

## 12. Notes on the Port: Threading & the GIL

The two multi-threaded versions (`dpi_mt.py`, `main_dpi.py` +
`dpi/dpi_engine.py`) use `threading.Thread` + a hand-rolled blocking
queue, faithfully reproducing the Reader → LB → FP → Output pipeline
**architecturally** — same number of threads, same hashing, same queue
backpressure behavior.

One honest difference worth knowing: CPython's Global Interpreter Lock
(GIL) means these threads don't get true CPU parallelism the way 
`std::thread`s do — only one thread executes Python bytecode at a time.
For I/O-bound work (which packet processing partly is, given file/queue
waits) you'll still see real concurrency benefit from the pipeline
structure, but you won't get the same multi-core throughput scaling the
version gets from 4+ FP threads doing CPU-bound TLS parsing
simultaneously. The logic, output, and behavior are identical either way
— only raw throughput on CPU-bound workloads differs. If you ever need
true parallelism in Python, the usual next step is `multiprocessing`
(separate processes, no GIL) or `asyncio` for I/O-bound scaling, but
that would change the architecture, so it's out of scope for this
functionality-preserving port.
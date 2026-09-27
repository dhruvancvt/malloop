"""Host-side fake DNS for `simulated` detonations.

Every A query is answered with a per-domain sinkhole address in TEST-NET-1 (192.0.2.0/24), so the sample
proceeds to connect and its target ports show up in the capture, while nothing it sends is ever addressed
to a real host (the host doesn't route, and the sinkhole isn't its address). Queries are sample-controlled:
parsing is bounded, only single-question standard queries are answered, and nothing is resolved for real.
"""
import hashlib
import ipaddress
import socket
import struct
import threading
from collections import Counter
from typing import NamedTuple

SINKHOLE_PREFIX = "192.0.2."
MAX_QUERY_BYTES = 512
MAX_DISTINCT = 500
LIST_CAP = 30
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
          65: "HTTPS", 255: "ANY"}


class Query(NamedTuple):
    txid: int
    flags: int
    name: str
    qtype: int
    qclass: int
    end: int


def sinkhole_for(name: str) -> str:
    """Deterministic, so a connection in the pcap can be mapped back to the name that produced it."""
    n = int.from_bytes(hashlib.sha256(name.lower().encode()).digest()[:2], "big") % 254 + 1
    return f"{SINKHOLE_PREFIX}{n}"


def parse_query(data: bytes) -> Query | None:
    """A single-question standard query, or None for anything else (responses, compression, malformed)."""
    if not 12 <= len(data) <= MAX_QUERY_BYTES:
        return None
    txid, flags, qdcount = struct.unpack(">HHH", data[:6])
    if flags & 0x8000 or (flags >> 11) & 0xF or qdcount != 1:
        return None
    labels, i = [], 12
    while True:
        if i >= len(data):
            return None
        length = data[i]
        if length == 0:
            i += 1
            break
        if length > 63:  # also rejects compression pointers, which a question never needs
            return None
        label = data[i + 1:i + 1 + length]
        if len(label) != length:
            return None
        labels.append(label.decode("ascii", "replace"))
        i += 1 + length
        if i - 12 > 255:
            return None
    if i + 4 > len(data):
        return None
    qtype, qclass = struct.unpack(">HH", data[i:i + 4])
    return Query(txid, flags, ".".join(labels).lower(), qtype, qclass, i + 4)


def build_response(data: bytes, q: Query) -> tuple[bytes, str | None]:
    """A for IN gets the sinkhole; every other type gets NOERROR with no answers (NXDOMAIN would make the
    guest's resolver cache the whole name as nonexistent and skip the A lookup)."""
    answer_ip = sinkhole_for(q.name) if q.qtype == 1 and q.qclass == 1 else None
    flags = 0x8000 | 0x0400 | (q.flags & 0x0100) | 0x0080  # QR, AA, copy RD, RA; rcode 0
    header = struct.pack(">HHHHHH", q.txid, flags, 1, 1 if answer_ip else 0, 0, 0)
    body = data[12:q.end]
    if answer_ip:
        body += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(answer_ip)
    return header + body, answer_ip


class FakeDNS:
    """Answers DNS on one host-only address for the duration of a `with` block, from a background thread.

    Degrades instead of raising: a missing or wildcard bind address, or a port already in use, leaves
    `summary()` reporting why it was skipped, and the detonation carries on without it.
    """

    def __init__(self, bind: str, port: int):
        self.bind, self.port = bind, port
        self.error: str | None = None
        self.seen: Counter = Counter()
        self.answers: dict[tuple[str, int], str | None] = {}
        self.dropped = 0
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def __enter__(self) -> "FakeDNS":
        try:
            addr = ipaddress.IPv4Address(self.bind)
        except ValueError:
            self.error = f"MALLOOP_FAKEDNS_BIND must be a host-only IPv4 address, got {self.bind!r}"
            return self
        if addr.is_unspecified:
            self.error = "refusing to bind the fake DNS to a wildcard address; use the host-only address"
            return self
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((self.bind, self.port))
        except OSError as e:
            sock.close()
            self.error = f"could not bind {self.bind}:{self.port}: {e}"
            return self
        sock.settimeout(0.5)
        self._sock = sock
        self.port = sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, name="malloop-fakedns", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> bool:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self._sock:
            self._sock.close()
        return False

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                # Full-size buffer: on Windows a datagram larger than the buffer raises instead of truncating,
                # which would otherwise let one oversized packet shut the responder down.
                data, addr = self._sock.recvfrom(65535)
            except (TimeoutError, ConnectionResetError):  # Windows reports ICMP port-unreachable as a reset
                continue
            except OSError:
                break
            q = parse_query(data)
            if q is None:
                continue
            response, answer = build_response(data, q)
            key = (q.name, q.qtype)
            if key in self.seen or len(self.seen) < MAX_DISTINCT:
                self.seen[key] += 1
                self.answers[key] = answer
            else:
                self.dropped += 1
            try:
                self._sock.sendto(response, addr)
            except OSError:
                pass

    def summary(self) -> dict:
        if self.error:
            return {"skipped": self.error}
        return {
            "listening": f"{self.bind}:{self.port}",
            "queries": [{"name": name, "type": QTYPES.get(qtype, qtype), "answer": self.answers[(name, qtype)],
                         "count": count} for (name, qtype), count in self.seen.most_common(LIST_CAP)],
            "distinct_queries": len(self.seen),
            "dropped": self.dropped,
        }

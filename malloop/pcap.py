"""Bounded, stdlib-only summary of the classic libpcap files VirtualBox writes during detonation.

Everything on the wire is sample-controlled: the file is read one record at a time, every record length is
checked against the bytes actually present, input size and packet count are capped, and only a small
summary (DNS names asked, connections attempted) ever reaches the model.
"""
import socket
import struct
from collections import Counter
from pathlib import Path

from .fakedns import SINKHOLE_PREFIX, parse_query, sinkhole_for

_BYTE_ORDER = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",   # microsecond timestamps
               b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}   # nanosecond timestamps
_PCAPNG = b"\x0a\x0d\x0d\x0a"
LINKTYPE_ETHERNET = 1
MAX_RECORD = 262144
LIST_CAP = 30


class _Stats:
    def __init__(self):
        self.dns = Counter()
        self.resolvers = Counter()
        self.syn = Counter()
        self.udp = Counter()
        self.ignored = Counter()


def _frame(frame: bytes, s: _Stats, guest: tuple[str, int] | None) -> None:
    if len(frame) < 14:  # VirtualBox starts every trace with a short dummy record
        s.ignored["other"] += 1
        return
    if frame[0] & 1:  # group bit on the destination MAC: ARP requests, LLMNR, mDNS, SSDP, NBNS
        s.ignored["broadcast_multicast"] += 1
        return
    ethertype, off = int.from_bytes(frame[12:14], "big"), 14
    if ethertype == 0x8100 and len(frame) >= 18:
        ethertype, off = int.from_bytes(frame[16:18], "big"), 18
    if ethertype == 0x86DD:
        s.ignored["ipv6"] += 1
        return
    ip = frame[off:]
    if ethertype != 0x0800 or len(ip) < 20 or ip[0] >> 4 != 4 or not 20 <= (ip[0] & 0x0F) * 4 <= len(ip):
        s.ignored["other"] += 1
        return
    ihl = (ip[0] & 0x0F) * 4
    ip = ip[:max(ihl, min(int.from_bytes(ip[2:4], "big"), len(ip)))]  # drop Ethernet padding, trust nothing more
    if int.from_bytes(ip[6:8], "big") & 0x1FFF:
        s.ignored["fragments"] += 1
        return
    proto, src, dst, l4 = ip[9], socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20]), ip[ihl:]
    if proto not in (6, 17) or len(l4) < 8:
        s.ignored["other"] += 1
        return
    sport, dport = struct.unpack(">HH", l4[:4])
    if guest and proto == 6 and ((src, sport) == guest or (dst, dport) == guest):
        s.ignored["guest_agent"] += 1
        return
    if guest and dst == guest[0]:  # replies coming back to the guest, including our own fake DNS answers
        s.ignored["inbound"] += 1
        return
    if proto == 6:
        if len(l4) >= 14 and l4[13] & 0x02 and not l4[13] & 0x10:  # SYN without ACK: a connection attempt
            s.syn[f"{dst}:{dport}"] += 1
    elif dport == 53 and (q := parse_query(l4[8:])):
        s.dns[q.name] += 1
        s.resolvers[dst] += 1
    else:
        s.udp[f"{dst}:{dport}"] += 1


def summarize(path: Path, guest: tuple[str, int] | None, max_bytes: int, max_packets: int) -> dict:
    """`guest` is the guest agent's (ip, port): its control channel is dropped, as is traffic addressed to the guest."""
    s = _Stats()
    packets = frame_bytes = 0
    truncated = False
    with path.open("rb") as f:
        head = f.read(24)
        if head[:4] == _PCAPNG:
            return {"error": "pcapng is not supported"}
        order = _BYTE_ORDER.get(head[:4])
        if order is None or len(head) < 24:
            return {"error": "not a pcap file"}
        linktype = struct.unpack(order + "I", head[20:24])[0]
        if linktype != LINKTYPE_ETHERNET:
            return {"error": f"unsupported link type {linktype}"}
        consumed = 24
        while True:
            rec = f.read(16)
            if not rec:
                break
            incl = struct.unpack(order + "I", rec[8:12])[0] if len(rec) == 16 else None
            if incl is None or incl > MAX_RECORD or consumed + 16 + incl > max_bytes or packets >= max_packets:
                truncated = True
                break
            frame = f.read(incl)
            if len(frame) < incl:
                truncated = True
                break
            consumed += 16 + incl
            packets += 1
            frame_bytes += incl
            _frame(frame, s, guest)

    sinkholed: dict[str, set[str]] = {}
    for name in s.dns:
        sinkholed.setdefault(sinkhole_for(name), set()).add(name)

    def dest(d: str, c: int) -> dict:
        entry = {"dst": d, "count": c}
        if d.startswith(SINKHOLE_PREFIX):
            entry["via_dns"] = ", ".join(sorted(sinkholed.get(d.rsplit(":", 1)[0], ()))) or "unknown"
        return entry

    out = {
        "packets": packets,
        "bytes": frame_bytes,
        "truncated": truncated,
        "dns_queries": [{"name": n, "count": c} for n, c in s.dns.most_common(LIST_CAP)],
        "dns_servers_asked": dict(s.resolvers.most_common(LIST_CAP)),
        "tcp_connect_attempts": [dest(d, c) for d, c in s.syn.most_common(LIST_CAP)],
        "udp_destinations": [dest(d, c) for d, c in s.udp.most_common(LIST_CAP)],
        "ignored": dict(s.ignored),
    }
    if any(e.get("via_dns") for e in out["tcp_connect_attempts"] + out["udp_destinations"]):
        out["note"] = (f"{SINKHOLE_PREFIX}0/24 is the lab's DNS sinkhole, not a real destination: "
                       "report the via_dns domain and port, not the sinkhole address.")
    return out

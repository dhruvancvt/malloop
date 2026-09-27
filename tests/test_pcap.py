"""PCAP summary tests. Captures are built byte-by-byte here (no committed .pcap files, per sample-guard),
shaped like what VirtualBox's NIC trace writes: classic libpcap, Ethernet, a short dummy first record."""
import random
import socket
import struct

import pytest

from malloop import pcap
from malloop.fakedns import sinkhole_for

GUEST = ("192.168.56.10", 8765)
HOST = "192.168.56.1"
GUEST_MAC, HOST_MAC = b"\x08\x00\x27\x11\xf5\x70", b"\x0a\x00\x27\x00\x00\x0d"


def eth(payload: bytes, ethertype: int = 0x0800, dst: bytes = HOST_MAC, src: bytes = GUEST_MAC) -> bytes:
    return dst + src + ethertype.to_bytes(2, "big") + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, frag: int = 0) -> bytes:
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, frag, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload


def tcp(sport: int, dport: int, flags: int) -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 8192, 0, 0)


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)


def syn(dst: str, port: int, src: str = GUEST[0]) -> bytes:
    return eth(ipv4(src, dst, 6, tcp(49700, port, 0x02)))


def dns_frame(name: str, server: str = HOST) -> bytes:
    return eth(ipv4(GUEST[0], server, 17, udp(53000, 53, dns_query(name))))


def build_pcap(frames: list[bytes], order: str = "<", magic: int = 0xA1B2C3D4, linktype: int = 1,
               dummy: bool = True) -> bytes:
    out = struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    records = ([b"\x00" * 4] if dummy else []) + frames
    for i, frame in enumerate(records):
        orig = 60 if dummy and i == 0 else len(frame)
        out += struct.pack(order + "IIII", 0, i, len(frame), orig) + frame
    return out


def summarize(tmp_path, data: bytes, **kw) -> dict:
    path = tmp_path / "t.pcap"
    path.write_bytes(data)
    return pcap.summarize(path, kw.pop("guest", GUEST), kw.pop("max_bytes", 1 << 26), kw.pop("max_packets", 10**6))


def test_extracts_dns_and_connections_and_maps_sinkholes(tmp_path):
    sink = sinkhole_for("evil.example.xyz")
    frames = [
        dns_frame("Evil.Example.XYZ"),
        syn(sink, 443), syn(sink, 443),                               # resolved through the sinkhole
        syn("203.0.113.7", 8080),                                     # hardcoded C2 address
        eth(ipv4(GUEST[0], "198.51.100.9", 17, udp(50000, 9999))),
        eth(ipv4(HOST, GUEST[0], 6, tcp(50001, GUEST[1], 0x02)), dst=GUEST_MAC, src=HOST_MAC),  # guest agent
        eth(ipv4("203.0.113.7", GUEST[0], 6, tcp(8080, 49700, 0x12)), dst=GUEST_MAC),          # inbound SYN-ACK
        eth(ipv4(HOST, GUEST[0], 17, udp(53, 53000, b"x" * 20)), dst=GUEST_MAC),               # our DNS answer
        eth(ipv4(GUEST[0], "224.0.0.252", 17, udp(5355, 5355)), dst=b"\x01\x00\x5e\x00\x00\xfc"),  # LLMNR
        eth(b"\x60" + b"\x00" * 39, ethertype=0x86DD),
    ]
    s = summarize(tmp_path, build_pcap(frames))

    assert s["packets"] == len(frames) + 1 and not s["truncated"]
    assert s["dns_queries"] == [{"name": "evil.example.xyz", "count": 1}]
    assert s["dns_servers_asked"] == {HOST: 1}
    assert {"dst": f"{sink}:443", "count": 2, "via_dns": "evil.example.xyz"} in s["tcp_connect_attempts"]
    assert {"dst": "203.0.113.7:8080", "count": 1} in s["tcp_connect_attempts"]
    assert s["udp_destinations"] == [{"dst": "198.51.100.9:9999", "count": 1}]
    assert s["ignored"] == {"other": 1, "guest_agent": 1, "inbound": 2, "broadcast_multicast": 1, "ipv6": 1}
    assert "not a real destination" in s["note"]


def test_hardcoded_resolver_is_reported(tmp_path):
    s = summarize(tmp_path, build_pcap([dns_frame("c2.example", server="8.8.8.8")]))
    assert s["dns_servers_asked"] == {"8.8.8.8": 1}
    assert "note" not in s


@pytest.mark.parametrize("order,magic", [(">", 0xA1B2C3D4), ("<", 0xA1B23C4D), (">", 0xA1B23C4D)])
def test_byte_orders_and_nanosecond_files(tmp_path, order, magic):
    s = summarize(tmp_path, build_pcap([dns_frame("x.example")], order=order, magic=magic))
    assert s["dns_queries"] == [{"name": "x.example", "count": 1}]


@pytest.mark.parametrize("data,error", [
    (b"\x0a\x0d\x0d\x0a" + b"\x00" * 40, "pcapng is not supported"),
    (b"MZ\x90\x00" + b"\x00" * 40, "not a pcap file"),
    (b"", "not a pcap file"),
    (b"\xd4\xc3\xb2\xa1" + b"\x00" * 8, "not a pcap file"),
])
def test_rejects_what_it_cannot_read(tmp_path, data, error):
    assert summarize(tmp_path, data) == {"error": error}


def test_rejects_other_link_types(tmp_path):
    assert summarize(tmp_path, build_pcap([], linktype=101)) == {"error": "unsupported link type 101"}


def test_record_claiming_more_than_is_present_stops_cleanly(tmp_path):
    good = build_pcap([dns_frame("a.example")])
    lying = struct.pack("<IIII", 0, 0, 5000, 5000) + b"\x00" * 10
    s = summarize(tmp_path, good + lying)
    assert s["truncated"] and s["packets"] == 2
    assert s["dns_queries"] == [{"name": "a.example", "count": 1}]


def test_torn_record_header_stops_cleanly(tmp_path):
    s = summarize(tmp_path, build_pcap([dns_frame("a.example")]) + b"\x00" * 7)
    assert s["truncated"] and s["packets"] == 2


def test_oversized_record_is_not_read(tmp_path):
    s = summarize(tmp_path, build_pcap([]) + struct.pack("<IIII", 0, 0, pcap.MAX_RECORD + 1, 0))
    assert s["truncated"] and s["packets"] == 1


def test_packet_and_byte_caps(tmp_path):
    data = build_pcap([dns_frame(f"n{i}.example") for i in range(10)])
    assert summarize(tmp_path, data, max_packets=3)["packets"] == 3
    s = summarize(tmp_path, data, max_bytes=200)
    assert s["truncated"] and s["packets"] < 5


def test_malformed_frames_dont_crash_and_aren_t_counted(tmp_path):
    compressed = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack(">HH", 1, 1)
    long_label = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x40" + b"a" * 64 + b"\x00\x00\x01\x00\x01"
    frames = [
        eth(b"\x4f" + b"\x00" * 10),                                              # IHL says 60 bytes, has 11
        eth(b"\x44" + b"\x00" * 30),                                              # IHL below the minimum
        eth(ipv4(GUEST[0], "203.0.113.1", 6, tcp(1, 2, 0x02), frag=5)),           # non-first fragment
        eth(ipv4(GUEST[0], "203.0.113.1", 6, b"\x00\x01")),                       # TCP header cut short
        eth(ipv4(GUEST[0], HOST, 17, udp(1, 53, compressed))),
        eth(ipv4(GUEST[0], HOST, 17, udp(1, 53, long_label))),
    ]
    s = summarize(tmp_path, build_pcap(frames))
    assert s["packets"] == len(frames) + 1 and not s["truncated"]
    assert s["dns_queries"] == [] and s["tcp_connect_attempts"] == []


def test_random_garbage_frames_never_raise(tmp_path):
    rng = random.Random(1337)
    frames = [bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200))) for _ in range(400)]
    frames += [eth(bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 120)))) for _ in range(400)]
    s = summarize(tmp_path, build_pcap(frames))
    assert s["packets"] == len(frames) + 1

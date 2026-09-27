"""Fake DNS tests: a real responder on loopback, a real UDP client, real wire bytes."""
import socket
import struct

import pytest
from test_pcap import dns_query

from malloop import fakedns
from malloop.fakedns import FakeDNS, sinkhole_for


def ask(port: int, payload: bytes, timeout: float = 2.0) -> bytes | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(payload, ("127.0.0.1", port))
        try:
            return s.recv(4096)
        except TimeoutError:
            return None


def answer_ip(reply: bytes) -> str | None:
    txid, flags, qd, an = struct.unpack(">HHHH", reply[:8])
    return socket.inet_ntoa(reply[-4:]) if an else None


def test_a_query_gets_its_domains_sinkhole():
    with FakeDNS("127.0.0.1", 0) as dns:
        reply = ask(dns.port, dns_query("C2.Example.xyz", txid=0xBEEF))
    txid, flags, qd, an = struct.unpack(">HHHH", reply[:8])
    assert txid == 0xBEEF and flags & 0x8000 and flags & 0x000F == 0 and (qd, an) == (1, 1)
    assert answer_ip(reply) == sinkhole_for("c2.example.xyz")


def test_other_types_get_nodata_not_nxdomain():
    with FakeDNS("127.0.0.1", 0) as dns:
        reply = ask(dns.port, dns_query("c2.example.xyz", qtype=28))
    flags, qd, an = struct.unpack(">HHH", reply[2:8])
    assert flags & 0x000F == 0 and an == 0   # NOERROR: the name "exists", so the A lookup still happens


@pytest.mark.parametrize("payload", [
    b"\x00" * 5,                                                            # shorter than a header
    struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\x00\x00\x01\x00\x01",  # a response, not a query
    struct.pack(">HHHHHH", 1, 0x0100, 2, 0, 0, 0) + b"\x00\x00\x01\x00\x01",  # two questions
    struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01",  # compression pointer
    struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x05abc",               # label runs off the end
    dns_query("a" * 60 + ".x") + b"\x00" * 600,                             # oversized datagram
])
def test_malformed_input_is_ignored_and_the_server_keeps_answering(payload):
    with FakeDNS("127.0.0.1", 0) as dns:
        assert ask(dns.port, payload, timeout=0.5) is None
        assert ask(dns.port, dns_query("still.alive")) is not None
    assert [q["name"] for q in dns.summary()["queries"]] == ["still.alive"]


def test_summary_counts_repeats_and_caps_distinct_names(monkeypatch):
    monkeypatch.setattr(fakedns, "MAX_DISTINCT", 3)
    with FakeDNS("127.0.0.1", 0) as dns:
        for name in ["a.example", "a.example", "b.example", "c.example", "d.example", "e.example"]:
            ask(dns.port, dns_query(name))
    s = dns.summary()
    assert s["queries"][0] == {"name": "a.example", "type": "A", "answer": sinkhole_for("a.example"), "count": 2}
    assert s["distinct_queries"] == 3 and s["dropped"] == 2


@pytest.mark.parametrize("bind,why", [("0.0.0.0", "wildcard"), ("", "IPv4"), ("not-an-ip", "IPv4")])
def test_refuses_to_bind_anything_but_a_specific_address(bind, why):
    with FakeDNS(bind, 0) as dns:
        pass
    assert why in dns.summary()["skipped"]


def test_port_in_use_degrades_instead_of_raising():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as taken:
        taken.bind(("127.0.0.1", 0))
        with FakeDNS("127.0.0.1", taken.getsockname()[1]) as dns:
            pass
    assert "could not bind" in dns.summary()["skipped"]


def test_sinkhole_is_stable_case_insensitive_and_in_test_net():
    ip = sinkhole_for("Evil.COM")
    assert ip == sinkhole_for("evil.com")
    assert ip.startswith("192.0.2.") and 1 <= int(ip.rsplit(".", 1)[1]) <= 254

from malloop.triage import entropy, extract_iocs, strings


def test_entropy_bounds():
    assert entropy(b"") == 0.0
    assert entropy(b"\x00" * 1000) == 0.0
    assert abs(entropy(bytes(range(256)) * 4) - 8.0) < 1e-9


def test_strings_ascii_and_utf16():
    # Wide strings in real binaries sit on aligned, null-padded boundaries
    data = b"\x00\x01hello world\x00\x00" + "wide string".encode("utf-16le") + b"\xff"
    found = strings(data)
    assert "hello world" in found
    assert "wide string" in found


def test_ioc_extraction():
    iocs = extract_iocs(["GET http://evil.example.xyz/payload.bin", "HKCU\\Software\\Run\\x", "10.1.2.3"])
    assert "http://evil.example.xyz/payload.bin" in iocs["url"]
    assert "10.1.2.3" in iocs["ipv4"]
    assert iocs["registry"] == ["HKCU\\Software\\Run\\x"]

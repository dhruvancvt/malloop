"""Unpacker tests. All fixtures are synthesized here; no real malware is involved."""
import bz2
import io
import plistlib
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from malloop import config, unpack
from malloop.triage import sniff_type
from malloop.unpack import pick_primary, unpack_tree

FAKE_PE = b"MZ" + b"\x90" * 62 + b"This program cannot be run in DOS mode" + b"\x00" * 400


# ---------------------------------------------------------------- fixture builders

def make_macho64(body_len: int = 3000) -> bytes:
    """Minimal valid thin x86_64 Mach-O: header + one LC_SEGMENT_64 covering the whole file."""
    total = 4096 + body_len
    seg = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT", 0x100000000, total, 0, total, 5, 5, 0, 0)
    hdr = struct.pack("<IiiIIII I", 0xFEEDFACF, 0x01000007, 3, 2, 1, len(seg), 0, 0)
    blob = hdr + seg
    return blob + b"\x00" * (4096 - len(blob)) + bytes(range(256)) * (body_len // 256) + b"\xcc" * (body_len % 256)


def make_fat(slices: list[bytes]) -> bytes:
    offset, headers, bodies = 4096, b"", b""
    for i, s in enumerate(slices):
        headers += struct.pack(">iIIII", 0x01000007, 3, offset + len(bodies), len(s), 12)
        bodies += s
        if i < len(slices) - 1:  # slices are page-aligned; a real fat file ends at its last slice
            bodies += b"\x00" * (-len(s) % 4096)
    head = struct.pack(">II", 0xCAFEBABE, len(slices)) + headers
    return head + b"\x00" * (4096 - len(head)) + bodies


def adc_literals(data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 128):
        chunk = data[i:i + 128]
        out.append(0x80 | (len(chunk) - 1))
        out += chunk
    return bytes(out)


def make_dmg(raw: bytes, force_first_type: int | None = None) -> bytes:
    """Build a UDIF image of `raw` using a mix of chunk encodings."""
    assert len(raw) % 512 == 0
    sectors = len(raw) // 512
    encoders = [
        (unpack.UDIF_ZLIB, zlib.compress),
        (unpack.UDIF_RAW, lambda b: b),
        (unpack.UDIF_BZIP2, bz2.compress),
        (unpack.UDIF_ADC, adc_literals),
    ]
    data_fork, chunks, per = bytearray(), [], 8
    for i, sec in enumerate(range(0, sectors, per)):
        cnt = min(per, sectors - sec)
        piece = raw[sec * 512:(sec + cnt) * 512]
        if not any(piece):
            chunks.append((unpack.UDIF_ZERO, sec, cnt, len(data_fork), 0))
            continue
        etype, enc = encoders[i % len(encoders)]
        if force_first_type is not None and i == 0:
            etype = force_first_type
        comp = enc(piece)
        chunks.append((etype, sec, cnt, len(data_fork), len(comp)))
        data_fork += comp
    chunks.append((unpack.UDIF_END, sectors, 0, len(data_fork), 0))

    mish = bytearray(struct.pack(">4sIQQQII", b"mish", 1, 0, sectors, 0, 0, 0))
    mish += b"\x00" * (200 - len(mish)) + struct.pack(">I", len(chunks))
    for etype, sec, cnt, off, ln in chunks:
        mish += struct.pack(">IIQQQQ", etype, 0, sec, cnt, off, ln)

    plist = plistlib.dumps({"resource-fork": {"blkx": [{"Name": "disk image (Apple_HFS : 1)", "Data": bytes(mish)}]}})
    xml_off = len(data_fork)
    koly = bytearray(512)
    koly[0:4] = b"koly"
    struct.pack_into(">I", koly, 4, 4)
    struct.pack_into(">I", koly, 8, 512)
    struct.pack_into(">QQ", koly, 24, 0, len(data_fork))
    struct.pack_into(">QQ", koly, 216, xml_off, len(plist))
    struct.pack_into(">Q", koly, 492, sectors)
    return bytes(data_fork) + plist + bytes(koly)


def zip_bytes(entries: dict[str, bytes], symlinks: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, target)
    return buf.getvalue()


def aes_zip_bytes(entries: dict[str, bytes], password: bytes) -> bytes:
    pyzipper = pytest.importorskip("pyzipper")
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password)
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.fixture(autouse=True)
def no_7zip(monkeypatch):
    """Exercise the pure-Python paths regardless of what's installed."""
    monkeypatch.setattr(unpack, "seven_zip", lambda: None)


# ---------------------------------------------------------------- tests

def test_nested_encrypted_zip(tmp_path):
    inner = aes_zip_bytes({"payload/dropper.exe": FAKE_PE, "readme.txt": b"hello"}, b"infected")
    outer = zip_bytes({"inner.zip": inner, "copy.exe": FAKE_PE, "docs/a.txt": b"x"})
    sample = tmp_path / "outer.zip"
    sample.write_bytes(outer)

    nodes = unpack_tree(sample, tmp_path / "out")
    by_name = {n["name"]: n for n in nodes}

    assert nodes[0]["type"] == "zip" and nodes[0]["method"] == "zipfile"
    assert by_name["inner.zip"]["type"] == "zip"
    dropper = by_name["payload/dropper.exe"]
    assert dropper["type"] == "pe" and dropper["depth"] == 2
    assert any("infected" in n for n in by_name["inner.zip"]["notes"])
    # Depth-first: dropper.exe (inside inner.zip) is seen first, so the identical copy.exe is the duplicate
    assert by_name["copy.exe"]["duplicate_of"] == dropper["id"]


def test_zip_slip_symlink_and_bomb_are_refused(tmp_path):
    bomb = b"\x00" * (20 * 1024 * 1024)
    data = zip_bytes({"../../escape.txt": b"pwn", "C:/Windows/evil.dll": b"x", "ok.txt": b"fine", "bomb.bin": bomb},
                     symlinks={"link": "/etc/passwd"})
    sample = tmp_path / "evil.zip"
    sample.write_bytes(data)
    out = tmp_path / "out"

    nodes = unpack_tree(sample, out)
    names = {n["name"] for n in nodes[1:]}
    notes = " ".join(nodes[0]["notes"])

    # traversal components are stripped, never written outside the run dir
    assert not (tmp_path / "escape.txt").exists()
    assert all(Path(n["path"]).resolve().is_relative_to(out.resolve()) for n in nodes[1:])
    assert "ok.txt" in names
    assert "link" not in names and "skipped symlink" in notes
    assert "bomb.bin" not in names and "compression ratio" in notes


def test_file_limit_stops_unpacking(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "UNPACK_MAX_FILES", 3)
    sample = tmp_path / "many.zip"
    sample.write_bytes(zip_bytes({f"f{i}.txt": bytes([i]) * 10 for i in range(10)}))
    nodes = unpack_tree(sample, tmp_path / "out")
    assert any("file limit" in n for n in nodes[0]["notes"])


def test_depth_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "UNPACK_MAX_DEPTH", 2)
    data = zip_bytes({"leaf.exe": FAKE_PE})
    for i in range(4):
        data = zip_bytes({f"level{i}.zip": data})
    sample = tmp_path / "deep.zip"
    sample.write_bytes(data)
    nodes = unpack_tree(sample, tmp_path / "out")
    assert max(n["depth"] for n in nodes) == 2
    assert any("depth limit" in note for n in nodes for note in n["notes"])


def test_adc_backreference():
    # literal "abc", then 2-byte back-ref: length 3+3=6, offset 2 -> repeats "abc"
    src = bytes([0x82]) + b"abc" + bytes([(3 << 2) | 0, 2])
    assert unpack._adc_decompress(src, 9) == b"abcabcabc"


def test_dmg_decode_and_carve(tmp_path):
    thin = make_macho64(5000)
    fat = make_fat([make_macho64(2000), make_macho64(2500)])
    image = bytearray(512 * 200)
    image[4096:4096 + len(thin)] = thin
    fat_off = 4096 * 8
    image[fat_off:fat_off + len(fat)] = fat
    # Decoys that must NOT be carved: unaligned magic, and a Java class file (shares 0xCAFEBABE)
    image[70001:70005] = b"\xcf\xfa\xed\xfe"
    image[4096 * 20:4096 * 20 + 8] = b"\xca\xfe\xba\xbe\x00\x00\x00\x34"
    raw = bytes(image[: (len(image) // 512) * 512])

    sample = tmp_path / "App.dmg"
    sample.write_bytes(make_dmg(raw))
    assert sniff_type(sample) == "dmg"

    nodes = unpack_tree(sample, tmp_path / "out")
    root, children = nodes[0], nodes[1:]
    assert root["method"] == "udif+carve"
    carved = {Path(n["path"]).read_bytes() for n in children}
    assert thin in carved
    assert fat in carved                       # fat binary carved whole
    assert len(children) == 2                  # its inner slices and the decoys were not carved separately
    assert {n["type"] for n in children} == {"macho", "macho-fat"}
    assert not any(p.name == "_image.raw" for p in (tmp_path / "out").rglob("*"))


def test_dmg_inside_zip_picks_macho_primary(tmp_path):
    raw = bytearray(512 * 40)
    thin = make_macho64(3000)
    raw[4096:4096 + len(thin)] = thin
    dmg = make_dmg(bytes(raw))
    sample = tmp_path / "download.zip"
    sample.write_bytes(zip_bytes({"Installer.dmg": dmg, "notes.txt": b"hi"}))

    nodes = unpack_tree(sample, tmp_path / "out")
    assert [n["type"] for n in nodes] == ["zip", "dmg", "macho", "unknown"]
    primary = pick_primary(nodes, {})
    assert primary["type"] == "macho" and primary["depth"] == 2


def test_lzfse_chunk_reported_not_crashing(tmp_path):
    sample = tmp_path / "lzfse.dmg"
    sample.write_bytes(make_dmg(b"\x01" * 512 * 16, force_first_type=unpack.UDIF_LZFSE))
    nodes = unpack_tree(sample, tmp_path / "out")
    assert nodes[0]["method"] == "udif+carve"
    assert any("LZFSE" in n for n in nodes[0]["notes"]), nodes[0]["notes"]

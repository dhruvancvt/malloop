"""Recursive, bounded container unpacking (ZIP, DMG, and anything 7-Zip understands when it's installed).

Produces a flat list of nodes forming a tree. Nothing is ever executed. Every extraction is bounded by
depth, file count, total bytes and compression ratio, and output paths are confined to the run directory.

DMG strategy:
  1. If 7-Zip is available, extract the real filesystem (HFS+/APFS) with names and paths.
  2. Otherwise, decode the UDIF container ourselves into a raw disk image and carve Mach-O binaries
     from it. Carved files lose their names but keep full contents.
"""
import bz2
import hashlib
import lzma
import mmap
import os
import plistlib
import re
import shutil
import struct
import subprocess
import zlib
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

from . import config
from .triage import sniff_type

CONTAINER_TYPES = {"zip", "dmg", "7z", "rar", "hfs", "apfs"}
ARCHIVE_PASSWORDS = [b"infected", b"malware", b"virus"]
CHUNK = 1 << 20


class UnpackError(Exception):
    pass


class Budget:
    def __init__(self):
        self.files = 0
        self.bytes = 0

    def charge(self, nbytes: int = 0, files: int = 0) -> None:
        self.files += files
        self.bytes += nbytes
        if self.files > config.UNPACK_MAX_FILES:
            raise UnpackError(f"file limit reached ({config.UNPACK_MAX_FILES})")
        if self.bytes > config.UNPACK_MAX_TOTAL_BYTES:
            raise UnpackError(f"byte limit reached ({config.UNPACK_MAX_TOTAL_BYTES})")


@dataclass
class Node:
    id: str
    path: str                 # on-disk location (inside the run dir)
    name: str                 # path as it appeared inside the parent container
    type: str
    size: int
    sha256: str
    depth: int
    parent: str | None = None
    method: str | None = None  # how its children were extracted
    children: list[str] = field(default_factory=list)
    duplicate_of: str | None = None
    notes: list[str] = field(default_factory=list)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(CHUNK):
            h.update(block)
    return h.hexdigest()


def _safe_join(dest: Path, member: str) -> Path | None:
    """Map an archive member name to a path under dest, or None if it would escape (zip-slip)."""
    parts = [p for p in PurePosixPath(member.replace("\\", "/")).parts
             if p not in ("", ".", "..", "/") and ":" not in p]
    if not parts:
        return None
    target = dest.joinpath(*parts).resolve()
    return target if target.is_relative_to(dest.resolve()) else None


def seven_zip() -> str | None:
    if config.SEVEN_ZIP and Path(config.SEVEN_ZIP).exists():
        return config.SEVEN_ZIP
    for cand in ("7z", "7zz"):
        if found := shutil.which(cand):
            return found
    for cand in (r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"):
        if Path(cand).exists():
            return cand
    return None


# ---------------------------------------------------------------- ZIP

def _open_zip(path: Path):
    try:
        import pyzipper  # handles AES-encrypted zips (common for shared samples)
        return pyzipper.AESZipFile(path)
    except ImportError:
        return zipfile.ZipFile(path)


def extract_zip(path: Path, dest: Path, budget: Budget) -> tuple[list[tuple[Path, str]], list[str]]:
    out, notes = [], []
    with _open_zip(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                notes.append(f"skipped symlink: {info.filename}")
                continue
            if info.compress_size and info.file_size / info.compress_size > config.UNPACK_MAX_RATIO:
                notes.append(f"skipped (compression ratio > {config.UNPACK_MAX_RATIO}, possible bomb): {info.filename}")
                continue
            target = _safe_join(dest, info.filename)
            if target is None:
                notes.append(f"skipped unsafe path: {info.filename!r}")
                continue
            budget.charge(files=1)
            data_ok = False
            for pwd in [None, *ARCHIVE_PASSWORDS]:
                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, pwd=pwd) as src, target.open("wb") as dst:
                        # Don't trust the header's declared size: count what actually comes out.
                        while block := src.read(CHUNK):
                            budget.charge(nbytes=len(block))
                            dst.write(block)
                    if pwd:
                        notes.append(f"decrypted with password {pwd.decode()!r}: {info.filename}")
                    data_ok = True
                    break
                except (RuntimeError, zipfile.BadZipFile) as e:
                    if "password" in str(e).lower() or "encrypted" in str(e).lower():
                        continue
                    notes.append(f"failed {info.filename}: {e}")
                    break
                except NotImplementedError as e:
                    notes.append(f"failed {info.filename}: {e} (install pyzipper for AES zips)")
                    break
            if data_ok:
                out.append((target, info.filename))
            else:
                target.unlink(missing_ok=True)
                if not any(info.filename in n for n in notes):
                    notes.append(f"encrypted with unknown password: {info.filename}")
    return out, notes


# ---------------------------------------------------------------- 7-Zip (DMG filesystems, 7z, rar, hfs, apfs)

def extract_7z(path: Path, dest: Path, budget: Budget) -> tuple[list[tuple[Path, str]], list[str]]:
    exe = seven_zip()
    if not exe:
        raise UnpackError("7-Zip not installed")
    pw = "-p" + ARCHIVE_PASSWORDS[0].decode()
    listing = subprocess.run([exe, "l", "-slt", "-ba", pw, str(path)], capture_output=True, text=True,
                             errors="replace", timeout=300).stdout
    sizes = [int(m) for m in re.findall(r"^Size = (\d+)$", listing, re.M)]
    # Charge the declared totals up front so a bomb is refused before anything is written.
    budget.charge(nbytes=sum(sizes), files=len(sizes))
    dest.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([exe, "x", "-y", "-bd", pw, f"-o{dest}", str(path)], capture_output=True,
                          text=True, errors="replace", timeout=1800)
    notes = [] if proc.returncode == 0 else [f"7z exit {proc.returncode}: {proc.stderr.strip()[-300:]}"]
    root = dest.resolve()
    out = []
    for p in dest.rglob("*"):
        if p.is_symlink():
            p.unlink()
            notes.append(f"removed symlink: {p.relative_to(dest)}")
        elif p.is_file() and p.resolve().is_relative_to(root):
            out.append((p, p.relative_to(dest).as_posix()))
    return out, notes


# ---------------------------------------------------------------- DMG without 7-Zip: UDIF decode + carve

UDIF_ZERO, UDIF_RAW, UDIF_IGNORE = 0x00000000, 0x00000001, 0x00000002
UDIF_ADC, UDIF_ZLIB, UDIF_BZIP2, UDIF_LZFSE, UDIF_LZMA = 0x80000004, 0x80000005, 0x80000006, 0x80000007, 0x80000008
UDIF_COMMENT, UDIF_END = 0x7FFFFFFE, 0xFFFFFFFF


def _adc_decompress(src: bytes, out_len: int) -> bytes:
    out = bytearray()
    i = 0
    while i < len(src) and len(out) < out_len:
        b = src[i]
        if b & 0x80:                                   # literal run
            n = (b & 0x7F) + 1
            out += src[i + 1:i + 1 + n]
            i += 1 + n
            continue
        if b & 0x40:                                   # 3-byte back-reference
            n, off = (b & 0x3F) + 4, (src[i + 1] << 8) | src[i + 2]
            i += 3
        else:                                          # 2-byte back-reference
            n, off = ((b >> 2) & 0x0F) + 3, ((b & 0x03) << 8) | src[i + 1]
            i += 2
        for _ in range(n):
            out.append(out[-off - 1])
    return bytes(out[:out_len])


def udif_to_raw(dmg: Path, raw_path: Path, budget: Budget) -> list[str]:
    notes = []
    with dmg.open("rb") as f:
        f.seek(-512, os.SEEK_END)
        koly = f.read(512)
        if koly[:4] != b"koly":
            raise UnpackError("not a UDIF image (no koly trailer)")
        data_fork_off = struct.unpack(">Q", koly[24:32])[0]
        xml_off, xml_len = struct.unpack(">QQ", koly[216:232])
        sector_count = struct.unpack(">Q", koly[492:500])[0]
        if not xml_len:
            raise UnpackError("legacy DMG without XML plist; needs 7-Zip")
        total = sector_count * 512
        budget.charge(nbytes=total)
        f.seek(xml_off)
        blkx = plistlib.loads(f.read(xml_len))["resource-fork"]["blkx"]

        unsupported: dict[str, int] = {}
        with raw_path.open("wb") as out:
            out.truncate(total)
            for part in blkx:
                mish = part["Data"]
                if mish[:4] != b"mish":
                    continue
                part_sector = struct.unpack(">Q", mish[8:16])[0]
                part_data_off = struct.unpack(">Q", mish[24:32])[0]
                nchunks = struct.unpack(">I", mish[200:204])[0]
                for i in range(nchunks):
                    etype, _, sec, cnt, coff, clen = struct.unpack(">IIQQQQ", mish[204 + 40 * i:244 + 40 * i])
                    if etype in (UDIF_END, UDIF_COMMENT, UDIF_ZERO, UDIF_IGNORE):
                        continue
                    out_len = cnt * 512
                    f.seek(data_fork_off + part_data_off + coff)
                    comp = f.read(clen)
                    try:
                        if etype == UDIF_RAW:
                            buf = comp
                        elif etype == UDIF_ZLIB:
                            buf = zlib.decompress(comp)
                        elif etype == UDIF_BZIP2:
                            buf = bz2.decompress(comp)
                        elif etype == UDIF_LZMA:
                            buf = lzma.decompress(comp)
                        elif etype == UDIF_ADC:
                            buf = _adc_decompress(comp, out_len)
                        else:
                            unsupported[hex(etype)] = unsupported.get(hex(etype), 0) + 1
                            continue
                    except (zlib.error, OSError, lzma.LZMAError, ValueError) as e:
                        unsupported[f"{hex(etype)} ({e})"] = unsupported.get(hex(etype), 0) + 1
                        continue
                    out.seek((part_sector + sec) * 512)
                    out.write(buf[:out_len])
        for kind, n in unsupported.items():
            label = "LZFSE" if kind == hex(UDIF_LZFSE) else kind
            notes.append(f"{n} DMG chunk(s) with unsupported compression {label} left as zeros; install 7-Zip")
    return notes


MACHO_CPUS = {7, 12, 18, 0x01000007, 0x0100000C, 0x01000012}
MACHO_MAGIC = re.compile(rb"\xcf\xfa\xed\xfe|\xce\xfa\xed\xfe|\xca\xfe\xba\xbe")


def _macho_extent(mm, off: int) -> int | None:
    """Return the byte length of a Mach-O (thin or fat) starting at off, or None if it doesn't validate."""
    try:
        magic = mm[off:off + 4]
        if magic == b"\xca\xfe\xba\xbe":
            nfat = struct.unpack(">I", mm[off + 4:off + 8])[0]
            if not 1 <= nfat <= 8:  # also rejects Java class files, which share this magic
                return None
            end = 0
            for k in range(nfat):
                cpu, _, a_off, a_size, _ = struct.unpack(">iIIII", mm[off + 8 + 20 * k:off + 28 + 20 * k])
                if cpu not in MACHO_CPUS:
                    return None
                end = max(end, a_off + a_size)
            return end
        is64 = magic == b"\xcf\xfa\xed\xfe"
        cpu, _, filetype, ncmds, sizeofcmds, _ = struct.unpack("<iiIIII", mm[off + 4:off + 28])
        if cpu not in MACHO_CPUS or not 1 <= filetype <= 12 or not 0 < ncmds < 1000 or sizeofcmds > 1 << 20:
            return None
        hdr = 32 if is64 else 28
        end, p = hdr + sizeofcmds, off + hdr
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack("<II", mm[p:p + 8])
            if cmdsize < 8:
                return None
            if cmd == 0x19:    # LC_SEGMENT_64
                fo, fs = struct.unpack("<QQ", mm[p + 40:p + 56])
                end = max(end, fo + fs)
            elif cmd == 0x1:   # LC_SEGMENT
                fo, fs = struct.unpack("<II", mm[p + 32:p + 40])
                end = max(end, fo + fs)
            elif cmd == 0x1D:  # LC_CODE_SIGNATURE
                do, ds = struct.unpack("<II", mm[p + 8:p + 16])
                end = max(end, do + ds)
            p += cmdsize
        return end
    except struct.error:
        return None


def carve_macho(raw_path: Path, dest: Path, budget: Budget) -> tuple[list[tuple[Path, str]], list[str]]:
    out, notes = [], []
    dest.mkdir(parents=True, exist_ok=True)
    covered_until = 0
    with raw_path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        for m in MACHO_MAGIC.finditer(mm):
            off = m.start()
            # Files start on filesystem block boundaries; skip slices already inside a carved fat binary.
            if off % 512 or off < covered_until:
                continue
            size = _macho_extent(mm, off)
            if not size or size > config.UNPACK_MAX_FILE_BYTES or off + size > len(mm):
                continue
            budget.charge(nbytes=size, files=1)
            target = dest / f"carved_{off:#x}.macho"
            target.write_bytes(mm[off:off + size])
            out.append((target, f"<carved Mach-O @ {off:#x}, {size} bytes>"))
            covered_until = off + size
    notes.append("DMG decoded without 7-Zip: Mach-O binaries were carved from the raw image; "
                 "filenames, Info.plist and non-Mach-O files are not recovered. HFS+-compressed files are missed.")
    return out, notes


def extract_dmg(path: Path, dest: Path, budget: Budget) -> tuple[list[tuple[Path, str]], list[str], str]:
    if seven_zip():
        files, notes = extract_7z(path, dest, budget)
        return files, notes, "7z"
    dest.mkdir(parents=True, exist_ok=True)
    raw = dest / "_image.raw"
    try:
        notes = udif_to_raw(path, raw, budget)
        files, carve_notes = carve_macho(raw, dest / "carved", budget)
        return files, notes + carve_notes, "udif+carve"
    finally:
        raw.unlink(missing_ok=True)


# ---------------------------------------------------------------- recursion

def unpack_tree(sample: Path, out_dir: Path) -> list[dict]:
    budget = Budget()
    nodes: list[Node] = []
    by_hash: dict[str, str] = {}

    def add(path: Path, name: str, depth: int, parent: str | None) -> Node:
        node = Node(id=f"n{len(nodes)}", path=str(path), name=name, type=sniff_type(path),
                    size=path.stat().st_size, sha256=_sha256(path), depth=depth, parent=parent)
        if node.sha256 in by_hash:
            node.duplicate_of = by_hash[node.sha256]
        else:
            by_hash[node.sha256] = node.id
        nodes.append(node)
        if parent is not None:
            nodes[int(parent[1:])].children.append(node.id)
        return node

    def visit(node: Node) -> None:
        if node.type not in CONTAINER_TYPES or node.duplicate_of:
            return
        if node.depth >= config.UNPACK_MAX_DEPTH:
            node.notes.append(f"not unpacked: depth limit {config.UNPACK_MAX_DEPTH}")
            return
        dest = out_dir / node.id
        try:
            if node.type == "zip":
                files, notes = extract_zip(Path(node.path), dest, budget)
                method = "zipfile"
            elif node.type == "dmg":
                files, notes, method = extract_dmg(Path(node.path), dest, budget)
            else:
                files, notes = extract_7z(Path(node.path), dest, budget)
                method = "7z"
        except (UnpackError, zipfile.BadZipFile, OSError, KeyError, plistlib.InvalidFileException) as e:
            node.notes.append(f"unpack failed: {e}")
            return
        node.method = method
        node.notes += notes
        for fpath, name in files:
            try:
                child = add(fpath, name, node.depth + 1, node.id)
            except OSError:
                continue
            visit(child)

    visit(add(sample, sample.name, 0, None))
    return [asdict(n) for n in nodes]


TARGET_PRIORITY = {"pe": 0, "macho": 1, "macho-fat": 1, "elf": 2, "script": 3, "ole": 4, "pdf": 5}


def pick_primary(nodes: list[dict], child_triage: dict[str, dict]) -> dict:
    """Choose which node gets full static analysis first: most analyzable and most suspicious."""
    root = nodes[0]
    if root["type"] not in CONTAINER_TYPES:
        return root
    candidates = [n for n in nodes if n["type"] in TARGET_PRIORITY and not n["duplicate_of"]]
    if not candidates:
        return root

    def score(n):
        t = child_triage.get(n["id"], {})
        return (TARGET_PRIORITY[n["type"]], -len(t.get("yara", [])), -t.get("entropy", 0), n["depth"])

    return min(candidates, key=score)

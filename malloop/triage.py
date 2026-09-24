"""Stage 1: deterministic triage. Pure Python, never executes the sample."""
import hashlib
import math
import re
from pathlib import Path

MAGIC = [
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xca\xfe\xba\xbe", "macho-fat"),
    (b"PK\x03\x04", "zip"),
    (b"%PDF", "pdf"),
    (b"\xd0\xcf\x11\xe0", "ole"),
    (b"7z\xbc\xaf", "7z"),
    (b"Rar!", "rar"),
]


def detect_type(data: bytes, path: Path) -> str:
    for sig, kind in MAGIC:
        if data.startswith(sig):
            return kind
    # DMG files carry a 'koly' trailer in the last 512 bytes
    if len(data) > 512 and data[-512:-508] == b"koly":
        return "dmg"
    ext = path.suffix.lower()
    if ext in {".ps1", ".vbs", ".js", ".bat", ".cmd", ".sh", ".py", ".hta"}:
        return "script"
    return "unknown"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def strings(data: bytes, min_len: int = 6, limit: int = 4000) -> list[str]:
    ascii_ = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    utf16 = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)
    out = [s.decode() for s in ascii_] + [s.decode("utf-16le") for s in utf16]
    return out[:limit]


IOC_PATTERNS = {
    "url": r"https?://[^\s\"'<>]{4,}",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b[a-z0-9-]{2,63}\.(?:com|net|org|io|ru|cn|xyz|top|info|biz|onion)\b",
    "registry": r"(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s\"']+",
    "wallet_btc": r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b",
}


def extract_iocs(strs: list[str]) -> dict[str, list[str]]:
    blob = "\n".join(strs)
    return {k: sorted(set(re.findall(p, blob, re.I)))[:100] for k, p in IOC_PATTERNS.items()}


def pe_info(path: Path) -> dict:
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed"}
    pe = pefile.PE(str(path), fast_load=False)
    imports = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        imports[entry.dll.decode(errors="replace")] = [
            (i.name or b"").decode(errors="replace") for i in entry.imports
        ]
    return {
        "imphash": pe.get_imphash(),
        "is_dll": pe.is_dll(),
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "entrypoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "sections": [
            {
                "name": s.Name.rstrip(b"\x00").decode(errors="replace"),
                "vsize": s.Misc_VirtualSize,
                "rawsize": s.SizeOfRawData,
                "entropy": round(s.get_entropy(), 2),
            }
            for s in pe.sections
        ],
        "imports": imports,
        "signed": bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size),
    }


def yara_scan(path: Path, rules_dir: Path) -> list[str]:
    try:
        import yara
    except ImportError:
        return ["yara-python not installed"]
    files = {p.stem: str(p) for p in rules_dir.glob("*.yar")}
    if not files:
        return []
    rules = yara.compile(filepaths=files)
    return [f"{m.namespace}:{m.rule}" for m in rules.match(str(path))]


def triage(path: Path, rules_dir: Path) -> dict:
    data = path.read_bytes()
    kind = detect_type(data, path)
    strs = strings(data)
    report = {
        "file": path.name,
        "size": len(data),
        "type": kind,
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": round(entropy(data), 3),
        "string_count": len(strs),
        "iocs": extract_iocs(strs),
        "yara": yara_scan(path, rules_dir),
    }
    if kind == "pe":
        report["pe"] = pe_info(path)
    return report, strs

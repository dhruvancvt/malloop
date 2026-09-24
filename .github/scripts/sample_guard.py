"""Fail if any git-tracked file looks like an executable, disk image or archive.

malloop is a public repository: live malware, and binaries in general, must never be committed.
Test fixtures are synthesized in code at test time.
"""
import subprocess
import sys
from pathlib import Path

MAGICS = {
    b"MZ": "PE/DOS executable",
    b"\x7fELF": "ELF executable",
    b"\xcf\xfa\xed\xfe": "Mach-O",
    b"\xce\xfa\xed\xfe": "Mach-O",
    b"\xca\xfe\xba\xbe": "Mach-O fat / Java class",
    b"PK\x03\x04": "ZIP archive",
    b"7z\xbc\xaf": "7z archive",
    b"Rar!": "RAR archive",
    b"\xd0\xcf\x11\xe0": "OLE document",
    b"\x1f\x8b": "gzip",
    b"xar!": "XAR/PKG",
}
BLOCKED_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".dmg", ".iso", ".pkg", ".msi", ".apk", ".jar",
                    ".zip", ".7z", ".rar", ".gz", ".xz", ".bin", ".dmp", ".pcap", ".pcapng"}


def main() -> int:
    files = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout.split(b"\0")
    bad = []
    for raw in filter(None, files):
        path = Path(raw.decode())
        if not path.is_file():
            continue
        if path.suffix.lower() in BLOCKED_SUFFIXES:
            bad.append(f"{path}: blocked extension {path.suffix}")
            continue
        head = path.open("rb").read(8)
        for magic, kind in MAGICS.items():
            if head.startswith(magic):
                bad.append(f"{path}: looks like {kind}")
                break
        else:
            if path.stat().st_size >= 512:
                with path.open("rb") as f:
                    f.seek(-512, 2)
                    if f.read(4) == b"koly":
                        bad.append(f"{path}: looks like a DMG")
    if bad:
        print("Binary/sample-like files are not allowed in this repository:\n  " + "\n  ".join(bad))
        print("Generate fixtures in code (see tests/) and never commit real samples.")
        return 1
    print(f"sample-guard: {len([f for f in files if f])} tracked files OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

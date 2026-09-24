"""Central configuration. Override any value with an environment variable of the same name."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


RUNS_DIR = Path(_env("MALLOOP_RUNS_DIR", str(ROOT / "runs")))

# Agent
MODEL = _env("MALLOOP_MODEL", "claude-opus-5-5")
MAX_ITERATIONS = int(_env("MALLOOP_MAX_ITERATIONS", "12"))
MAX_DYNAMIC_SECONDS_TOTAL = int(_env("MALLOOP_MAX_DYNAMIC_SECONDS", "600"))
MAX_TOOL_OUTPUT_CHARS = int(_env("MALLOOP_MAX_TOOL_OUTPUT_CHARS", "12000"))
MAX_INITIAL_EVIDENCE_CHARS = int(_env("MALLOOP_MAX_INITIAL_EVIDENCE_CHARS", "60000"))

# Static tooling (leave blank to skip that tool)
GHIDRA_HEADLESS = _env("GHIDRA_HEADLESS", "")  # e.g. C:\ghidra\support\analyzeHeadless.bat
CAPA_BIN = _env("CAPA_BIN", "capa")
FLOSS_BIN = _env("FLOSS_BIN", "floss")
YARA_RULES_DIR = Path(_env("MALLOOP_YARA_DIR", str(ROOT / "rules")))
GHIDRA_SCRIPTS_DIR = ROOT / "ghidra_scripts"
SEVEN_ZIP = _env("SEVEN_ZIP", "")  # optional; auto-detected on PATH / Program Files

# Recursive unpacking limits (zip-bomb and resource guards)
UNPACK_MAX_DEPTH = int(_env("MALLOOP_UNPACK_MAX_DEPTH", "4"))
UNPACK_MAX_FILES = int(_env("MALLOOP_UNPACK_MAX_FILES", "1000"))
UNPACK_MAX_TOTAL_BYTES = int(_env("MALLOOP_UNPACK_MAX_TOTAL_BYTES", str(2 * 1024**3)))
UNPACK_MAX_FILE_BYTES = int(_env("MALLOOP_UNPACK_MAX_FILE_BYTES", str(512 * 1024**2)))
UNPACK_MAX_RATIO = int(_env("MALLOOP_UNPACK_MAX_RATIO", "250"))

# Sandbox
SANDBOX_BACKEND = _env("MALLOOP_SANDBOX", "virtualbox")  # virtualbox | hyperv | none
VM_NAME = _env("MALLOOP_VM_NAME", "malloop-win10")
VM_SNAPSHOT = _env("MALLOOP_VM_SNAPSHOT", "clean")
# The guest agent listens on a host-only network. Never bridge this VM to your LAN.
GUEST_URL = _env("MALLOOP_GUEST_URL", "http://192.168.56.10:8765")
GUEST_TOKEN = _env("MALLOOP_GUEST_TOKEN", "change-me")
VBOXMANAGE = _env("VBOXMANAGE", r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")

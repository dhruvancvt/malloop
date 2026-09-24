"""Stage 2: deterministic static analysis wrappers (Ghidra headless, capa, FLOSS).

Each wrapper degrades gracefully: if a tool isn't configured it returns {"skipped": reason}.
"""
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import config


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")


def _parse_capa(raw: dict) -> dict:
    caps = []
    for name, rule in (raw.get("rules") or {}).items():
        meta = rule.get("meta", {})
        caps.append({
            "capability": name,
            "namespace": meta.get("namespace"),
            "attack": [a.get("id") for a in meta.get("attack", [])],
        })
    return {"capabilities": caps}


def _parse_floss(raw: dict) -> dict:
    strings = raw.get("strings", {})
    return {k: [s.get("string") for s in strings.get(k, [])][:300]
            for k in ("decoded_strings", "stack_strings", "tight_strings")}


def capa(path: Path) -> dict:
    if not shutil.which(config.CAPA_BIN):
        return {"skipped": "capa not found"}
    proc = _run([config.CAPA_BIN, "-j", str(path)], timeout=600)
    if proc.returncode != 0:
        return {"error": proc.stderr[-2000:]}
    return _parse_capa(json.loads(proc.stdout))


def floss(path: Path) -> dict:
    if not shutil.which(config.FLOSS_BIN):
        return {"skipped": "floss not found"}
    proc = _run([config.FLOSS_BIN, "-j", "-q", str(path)], timeout=900)
    if proc.returncode != 0:
        return {"error": proc.stderr[-2000:]}
    return _parse_floss(json.loads(proc.stdout))


# Maps a tool name to the host-side parser for its raw JSON, when the worker ran it.
_WORKER_PARSERS = {"capa": _parse_capa, "floss": _parse_floss}


def static_from_worker(path: Path, worker) -> dict:
    """Ask the worker to run capa+FLOSS on `path`; parse each tool's raw JSON here on the host."""
    out = {}
    for name, res in worker.analyze(path, tuple(_WORKER_PARSERS)).items():
        if isinstance(res, dict) and res.get("ok"):
            out[name] = _WORKER_PARSERS[name](res.get("result") or {})
        else:
            out[name] = res  # {"skipped"|"error": ...} passes straight through
    return out


class Ghidra:
    """Runs Ghidra headless once to build a project, then serves follow-up queries from it."""

    def __init__(self, sample: Path, workdir: Path):
        self.sample = sample
        self.project_dir = workdir
        self.project_dir.mkdir(parents=True, exist_ok=True)
        self.imported = False

    @property
    def available(self) -> bool:
        return bool(config.GHIDRA_HEADLESS) and Path(config.GHIDRA_HEADLESS).exists()

    def _headless(self, script: str, args: list[str], import_: bool) -> dict:
        if not self.available:
            return {"skipped": "GHIDRA_HEADLESS not configured"}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out:
            out_path = out.name
        cmd = [config.GHIDRA_HEADLESS, str(self.project_dir), "malloop"]
        if import_:
            cmd += ["-import", str(self.sample), "-overwrite"]
        else:
            cmd += ["-process", self.sample.name, "-noanalysis", "-readOnly"]
        cmd += ["-scriptPath", str(config.GHIDRA_SCRIPTS_DIR),
                "-postScript", script, out_path, *args]
        proc = _run(cmd, timeout=1800)
        try:
            return json.loads(Path(out_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"error": proc.stdout[-1500:] + proc.stderr[-1500:]}
        finally:
            Path(out_path).unlink(missing_ok=True)

    def overview(self) -> dict:
        result = self._headless("export_overview.py", [], import_=not self.imported)
        self.imported = "skipped" not in result and "error" not in result
        return result

    def decompile(self, target: str) -> dict:
        return self._headless("decompile.py", [target], import_=False)

    def xrefs(self, target: str) -> dict:
        return self._headless("xrefs.py", [target], import_=False)


def run_static(path: Path, ghidra: Ghidra, worker="auto") -> dict:
    """capa + FLOSS + Ghidra. capa/FLOSS run in the static worker when one is configured, else locally.

    `worker`: "auto" resolves it from config; None forces local tools; or pass a StaticWorker (tests).
    """
    if worker == "auto":
        from .static_worker import get_static_worker
        worker = get_static_worker()
    if worker is not None:
        report = static_from_worker(path, worker)
        report["worker"] = worker.url
    else:
        report = {"capa": capa(path), "floss": floss(path)}
    report["ghidra"] = ghidra.overview()
    return report

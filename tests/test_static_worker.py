"""Static-worker tests: real worker_agent HTTP server on localhost, driven by the real StaticWorker
client and run_static. Only the capa/FLOSS subprocess call is stubbed (neither is installed here)."""
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
import requests

from malloop import config
from malloop.static_analysis import run_static
from malloop.static_worker import StaticWorker, get_static_worker
from malloop.worker import worker_agent

TOKEN = "worker-token-xyz"
CAPA_RAW = {"rules": {"encrypt data using AES": {"meta": {"namespace": "data-manipulation/encryption",
                                                          "attack": [{"id": "T1486"}]}},
                      "create TCP socket": {"meta": {"namespace": "communication/socket", "attack": []}}}}
FLOSS_RAW = {"strings": {"decoded_strings": [{"string": "http://evil.example.xyz/gate"}],
                         "stack_strings": [{"string": "AKIA-stackstr"}], "tight_strings": []}}


class NoGhidra:
    def overview(self):
        return {"skipped": "no ghidra"}


@pytest.fixture
def worker(monkeypatch):
    monkeypatch.setattr(worker_agent, "TOKEN", TOKEN)
    seen = {}

    def fake_run_tool(name, path):
        seen.setdefault("tools", []).append(name)
        seen["bytes"] = Path(path).read_bytes()
        if name == "capa":
            return {"ok": True, "result": CAPA_RAW}
        if name == "floss":
            return {"ok": True, "result": FLOSS_RAW}
        return {"error": f"unknown {name}"}

    monkeypatch.setattr(worker_agent, "run_tool", fake_run_tool)
    server = ThreadingHTTPServer(("127.0.0.1", 0), worker_agent.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    yield {"url": url, "seen": seen}
    server.shutdown()
    server.server_close()


def test_run_static_through_worker(worker, tmp_path):
    sample = tmp_path / "dropper.exe"
    sample.write_bytes(b"MZ\x90\x90 payload bytes " * 40)
    client = StaticWorker(worker["url"], TOKEN, timeout=30)

    report = run_static(sample, NoGhidra(), worker=client)

    assert worker["seen"]["tools"] == ["capa", "floss"]      # both tools ran in the worker
    assert worker["seen"]["bytes"] == sample.read_bytes()    # byte-exact upload
    caps = {c["capability"]: c["attack"] for c in report["capa"]["capabilities"]}
    assert caps["encrypt data using AES"] == ["T1486"]
    assert report["floss"]["decoded_strings"] == ["http://evil.example.xyz/gate"]
    assert report["worker"] == worker["url"]
    assert report["ghidra"] == {"skipped": "no ghidra"}


def test_worker_missing_tool_passes_through(worker, tmp_path, monkeypatch):
    def only_capa(name, path):
        return {"ok": True, "result": CAPA_RAW} if name == "capa" else {"skipped": "floss not installed in worker"}

    monkeypatch.setattr(worker_agent, "run_tool", only_capa)
    sample = tmp_path / "x.bin"
    sample.write_bytes(b"data")
    report = run_static(sample, NoGhidra(), worker=StaticWorker(worker["url"], TOKEN, 30))
    assert report["capa"]["capabilities"]
    assert report["floss"] == {"skipped": "floss not installed in worker"}


def test_unreachable_worker_degrades(tmp_path):
    sample = tmp_path / "x.bin"
    sample.write_bytes(b"data")
    dead = StaticWorker("http://127.0.0.1:1", TOKEN, timeout=2)   # nothing listening
    report = run_static(sample, NoGhidra(), worker=dead)
    assert "unreachable" in report["capa"]["error"] and "unreachable" in report["floss"]["error"]
    assert report["ghidra"] == {"skipped": "no ghidra"}          # Ghidra still ran locally


def test_worker_rejects_bad_token(worker):
    r = requests.get(worker["url"] + "/health", headers={"X-Malloop-Token": "nope"}, timeout=5)
    assert r.status_code == 403
    r = requests.post(worker["url"] + "/analyze", headers={"X-Malloop-Token": "nope"},
                      files={"file": ("s", b"MZ")}, timeout=5)
    assert r.status_code == 403
    assert worker["seen"] == {}                                   # nothing ran


def test_health_reports_tool_availability(worker):
    assert StaticWorker(worker["url"], TOKEN, 10).health()["ok"] is True


def test_get_static_worker_config(monkeypatch):
    monkeypatch.setattr(config, "STATIC_WORKER_URL", "")
    assert get_static_worker() is None
    monkeypatch.setattr(config, "STATIC_WORKER_URL", "http://192.168.56.20:8766")
    monkeypatch.setattr(config, "STATIC_WORKER_TOKEN", "t")
    w = get_static_worker()
    assert w is not None and w.url == "http://192.168.56.20:8766"


def test_run_static_local_when_no_worker(tmp_path, monkeypatch):
    # worker=None forces the local path; capa/floss aren't installed here, so both skip cleanly.
    monkeypatch.setattr(config, "CAPA_BIN", "definitely-not-capa")
    monkeypatch.setattr(config, "FLOSS_BIN", "definitely-not-floss")
    report = run_static(tmp_path / "x", NoGhidra(), worker=None)
    (tmp_path / "x").write_bytes(b"MZ")
    assert report["capa"] == {"skipped": "capa not found"}
    assert report["floss"] == {"skipped": "floss not found"}
    assert "worker" not in report

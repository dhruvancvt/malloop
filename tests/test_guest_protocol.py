"""Host <-> guest protocol tests.

Runs the real guest agent HTTP server on localhost and drives it with the real Sandbox.detonate().
Only the VM lifecycle (restore/poweroff) and the actual sample execution (run_sample) are stubbed,
so nothing is ever executed.
"""
import http.client
import threading
from http.server import ThreadingHTTPServer

import pytest
import requests

from malloop import config
from malloop.guest import guest_agent
from malloop.sandbox.base import Sandbox

TOKEN = "test-token-123"
# Bytes that would trip naive multipart parsing: CRLFs, blank lines, and a fake boundary marker.
SAMPLE_BYTES = b"MZ\r\n\r\n--not-the-boundary\r\n\x00\xff" * 50 + b"\r\n"


class RecordingVM(Sandbox):
    def __init__(self):
        self.events = []

    def restore(self):
        self.events.append("restore")

    def poweroff(self):
        self.events.append("poweroff")


@pytest.fixture
def guest(tmp_path, monkeypatch):
    work = tmp_path / "guest"
    monkeypatch.setattr(guest_agent, "TOKEN", TOKEN)
    monkeypatch.setattr(guest_agent, "SAMPLE_DIR", work / "sample")
    monkeypatch.setattr(guest_agent, "OUT_DIR", work / "out")
    monkeypatch.setitem(guest_agent.state, "sample", None)
    seen = {}

    def fake_run_sample(duration, args, network, dump=False):
        sample = guest_agent.state["sample"]
        seen.update(sample=sample, data=sample.read_bytes(), duration=duration, args=args, network=network, dump=dump)
        guest_agent.OUT_DIR.mkdir(parents=True, exist_ok=True)
        (guest_agent.OUT_DIR / "sysmon.json").write_text('[{"id": 22, "QueryName": "evil.example.xyz"}]')
        (guest_agent.OUT_DIR / "screen.png").write_bytes(b"\x89PNG fake")
        return {"launch": {"pid": 1}, "sysmon_events": [{"id": 22, "QueryName": "evil.example.xyz"}],
                "artifacts": ["sysmon.json", "screen.png"]}

    monkeypatch.setattr(guest_agent, "run_sample", fake_run_sample)
    server = ThreadingHTTPServer(("127.0.0.1", 0), guest_agent.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    monkeypatch.setattr(config, "GUEST_URL", url)
    monkeypatch.setattr(config, "GUEST_TOKEN", TOKEN)
    yield {"url": url, "port": server.server_address[1], "seen": seen, "work": work}
    server.shutdown()
    server.server_close()


def test_detonate_roundtrip(guest, tmp_path):
    sample = tmp_path / "dropper.exe"
    sample.write_bytes(SAMPLE_BYTES)
    out = tmp_path / "collected"
    out.mkdir()
    vm = RecordingVM()

    report = vm.detonate(sample, 45, ["--install"], "simulated", out, dump=True)

    assert vm.events == ["restore", "poweroff"]
    seen = guest["seen"]
    assert seen["data"] == SAMPLE_BYTES                      # multipart upload is byte-exact
    assert seen["sample"].name == "dropper.exe"
    assert (seen["duration"], seen["args"], seen["network"], seen["dump"]) == (45, ["--install"], "simulated", True)
    assert report["sysmon_events"][0]["QueryName"] == "evil.example.xyz"
    assert (out / "sysmon.json").read_text().startswith("[{")
    assert (out / "screen.png").read_bytes() == b"\x89PNG fake"


def test_vm_powered_off_even_when_guest_fails(guest, tmp_path, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("guest crashed mid-run")

    monkeypatch.setattr(guest_agent, "run_sample", boom)
    sample = tmp_path / "x.exe"
    sample.write_bytes(b"MZ")
    vm = RecordingVM()
    with pytest.raises(requests.RequestException):
        vm.detonate(sample, 15, [], "none", tmp_path)
    assert vm.events == ["restore", "poweroff"]


def test_rejects_bad_token(guest):
    for token in ("wrong", ""):
        r = requests.get(guest["url"] + "/health", headers={"X-Malloop-Token": token}, timeout=5)
        assert r.status_code == 403
    r = requests.post(guest["url"] + "/run", json={"duration": 1}, headers={"X-Malloop-Token": "wrong"}, timeout=5)
    assert r.status_code == 403
    # A rejected multipart upload must still get a clean 403, not a connection reset.
    r = requests.post(guest["url"] + "/sample", files={"file": ("x.exe", b"MZ" * 5000)},
                      headers={"X-Malloop-Token": "wrong"}, timeout=5)
    assert r.status_code == 403
    assert guest["seen"] == {}                               # nothing ran


def test_upload_filename_cannot_escape_sample_dir(guest):
    files = {"file": ("../../evil.exe", b"MZ")}
    r = requests.post(guest["url"] + "/sample", files=files, headers={"X-Malloop-Token": TOKEN}, timeout=5)
    assert r.ok
    stored = guest_agent.state["sample"]
    assert stored.resolve().parent == (guest["work"] / "sample").resolve()
    assert not (guest["work"].parent / "evil.exe").exists()


def test_artifact_download_cannot_traverse(guest):
    (guest["work"]).mkdir(parents=True, exist_ok=True)
    (guest["work"] / "out").mkdir(exist_ok=True)
    (guest["work"] / "secret.txt").write_text("host secret")
    # Send raw paths so no client-side URL normalization hides the attempt.
    for path in ("/artifact/../secret.txt", "/artifact/..%2Fsecret.txt", "/artifact/%2e%2e/secret.txt"):
        conn = http.client.HTTPConnection("127.0.0.1", guest["port"], timeout=5)
        conn.request("GET", path, headers={"X-Malloop-Token": TOKEN})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        assert resp.status == 404, path
        assert b"host secret" not in body

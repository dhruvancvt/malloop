"""Read-only web viewer tests: run listing, report rendering, and the safety properties that matter
because everything rendered here is derived from an analyzed (and possibly hostile) sample.
"""
import http.client
import json
import threading
from http.server import ThreadingHTTPServer

import pytest
import requests

from malloop import config, viewer


def _write_run(runs_dir, run_id, *, unpack=None, triage=None, static=None, final=None, trace_lines=None,
               status=None):
    run_dir = runs_dir / run_id
    (run_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    if unpack is not None:
        (run_dir / "unpack.json").write_text(json.dumps(unpack))
    if triage is not None:
        (run_dir / "triage.json").write_text(json.dumps(triage))
    if static is not None:
        (run_dir / "static.json").write_text(json.dumps(static))
    if final is not None:
        (run_dir / "final.json").write_text(json.dumps(final))
    if trace_lines is not None:
        (run_dir / "trace.jsonl").write_text("\n".join(trace_lines) + "\n")
    if status is not None:
        (run_dir / "status.json").write_text(json.dumps(status))
    return run_dir


@pytest.fixture
def viewer_server(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), viewer.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield {"url": f"http://127.0.0.1:{server.server_address[1]}", "runs_dir": tmp_path}
    server.shutdown()
    server.server_close()


def test_index_with_no_runs(viewer_server):
    r = requests.get(viewer_server["url"] + "/", timeout=5)
    assert r.status_code == 200
    assert "No runs yet" in r.text


def test_index_lists_completed_run(viewer_server):
    _write_run(
        viewer_server["runs_dir"], "20260924-100156-5fc8a2bfd30e",
        unpack=[{"id": "n0", "name": "sample.exe", "depth": 0, "type": "pe", "size": 100}],
        triage={"file": "sample.exe", "type": "pe", "size": 100, "entropy": 6.1,
                "sha256": "5fc8a2bfd30e" * 5},
        final={"verdict": "malicious", "confidence": 0.9, "family": "TestFamily",
               "summary": "test summary", "evidence": [], "attack_techniques": [], "iocs": {}},
    )
    r = requests.get(viewer_server["url"] + "/", timeout=5)
    assert r.status_code == 200
    assert "20260924-100156-5fc8a2bfd30e" in r.text
    assert "sample.exe" in r.text
    assert "malicious" in r.text
    assert "TestFamily" in r.text


def test_run_detail_renders_verdict_and_capa(viewer_server):
    run_id = "20260924-100156-5fc8a2bfd30e"
    _write_run(
        viewer_server["runs_dir"], run_id,
        unpack=[{"id": "n0", "name": "sample.exe", "depth": 0, "type": "pe", "size": 100}],
        triage={"file": "sample.exe", "type": "pe", "size": 100, "entropy": 6.1, "sha256": "aa" * 32},
        static={"capa": {"capabilities": [{"capability": "connect socket",
                                            "namespace": "communication/socket", "attack": ["T1071"]}]},
                "floss": {"decoded_strings": ["hello"]}, "worker": None, "ghidra": {"skipped": "n/a"}},
        final={"verdict": "malicious", "confidence": 0.9, "family": "TestFamily", "summary": "bad file",
               "evidence": ["ev1"], "attack_techniques": ["T1071"], "iocs": {"ips": ["1.2.3.4"]}},
        trace_lines=[json.dumps({"n": 1, "ts": 1, "tool": "search_strings", "params": {"pattern": "x"},
                                  "result": {"matches": ["x"]}})],
    )
    r = requests.get(viewer_server["url"] + f"/runs/{run_id}", timeout=5)
    assert r.status_code == 200
    assert "connect socket" in r.text
    assert "T1071" in r.text
    assert "1.2.3.4" in r.text
    assert "search_strings" in r.text
    assert "bad file" in r.text


def test_incomplete_run_does_not_crash(viewer_server):
    run_id = "20260924-100156-aaaaaaaaaaaa"
    _write_run(viewer_server["runs_dir"], run_id,
               unpack=[{"id": "n0", "name": "still-unpacking.bin", "depth": 0, "type": "unknown", "size": 1}])
    detail = requests.get(viewer_server["url"] + f"/runs/{run_id}", timeout=5)
    assert detail.status_code == 200
    assert "incomplete" in detail.text
    index = requests.get(viewer_server["url"] + "/", timeout=5)
    assert "incomplete" in index.text


def test_truncated_trace_line_is_tolerated(viewer_server):
    run_id = "20260924-100156-bbbbbbbbbbbb"
    run_dir = _write_run(viewer_server["runs_dir"], run_id, triage={"file": "x", "sha256": "b" * 64})
    (run_dir / "trace.jsonl").write_text(
        json.dumps({"n": 1, "ts": 1, "tool": "read_file", "params": {}, "result": {"ok": True}}) + "\n"
        '{"n": 2, "ts": 2, "tool": "read_fi'  # simulates a write in progress, no trailing newline
    )
    r = requests.get(viewer_server["url"] + f"/runs/{run_id}", timeout=5)
    assert r.status_code == 200
    assert "read_file" in r.text


def test_sample_derived_strings_are_html_escaped(viewer_server):
    run_id = "20260924-100156-cccccccccccc"
    payload = "<script>alert('xss')</script>"
    _write_run(
        viewer_server["runs_dir"], run_id,
        unpack=[{"id": "n0", "name": payload, "depth": 0, "type": "pe", "size": 1}],
        triage={"file": payload, "type": "pe", "size": 1, "entropy": 1, "sha256": "c" * 64},
        final={"verdict": "malicious", "confidence": 0.5, "family": payload, "summary": payload,
               "evidence": [payload], "attack_techniques": [], "iocs": {"notes": [payload]}},
    )
    for path in ("/", f"/runs/{run_id}"):
        r = requests.get(viewer_server["url"] + path, timeout=5)
        assert "<script>alert" not in r.text
        assert "&lt;script&gt;" in r.text


def test_unknown_run_is_404(viewer_server):
    r = requests.get(viewer_server["url"] + "/runs/20260924-100156-deadbeef0000", timeout=5)
    assert r.status_code == 404


@pytest.mark.parametrize("path", [
    "/runs/../secret.txt", "/runs/..%2Fsecret.txt", "/runs/%2e%2e/secret.txt",
    "/runs/not-a-run-id", "/runs/..",
])
def test_run_id_cannot_traverse_out_of_runs_dir(viewer_server, path):
    # Sent as a raw request line (not via `requests`, which would normalize ".." itself) so this
    # actually exercises the server's own path handling, not the client's.
    (viewer_server["runs_dir"].parent / "secret.txt").write_text("host secret", encoding="utf-8")
    host, port = "127.0.0.1", int(viewer_server["url"].rsplit(":", 1)[1])
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    assert resp.status == 404, path
    assert b"host secret" not in body


# ---------------------------------------------------------------- phase 2: live status/trace polling

def test_status_endpoint_reflects_status_json(viewer_server):
    run_id = "20260927-100156-1111aaaa1111"
    _write_run(viewer_server["runs_dir"], run_id, triage={"file": "x", "sha256": "a" * 64},
               status={"stage": "agent", "iteration": 3, "max_iterations": 12, "ts": 1.0})
    r = requests.get(viewer_server["url"] + f"/runs/{run_id}/status", timeout=5)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["stage"] == "agent" and body["iteration"] == 3 and body["max_iterations"] == 12


def test_status_endpoint_falls_back_when_no_status_json(viewer_server):
    # Runs recorded before status.json existed: a final.json means done, otherwise infer from what's there.
    done_id = "20260927-100156-2222aaaa2222"
    _write_run(viewer_server["runs_dir"], done_id, triage={"file": "x", "sha256": "b" * 64},
               final={"verdict": "benign", "confidence": 0.5, "summary": "", "evidence": []})
    r = requests.get(viewer_server["url"] + f"/runs/{done_id}/status", timeout=5)
    assert r.json()["stage"] == "done"

    partial_id = "20260927-100156-3333aaaa3333"
    _write_run(viewer_server["runs_dir"], partial_id,
               unpack=[{"id": "n0", "name": "x.exe", "depth": 0, "type": "pe", "size": 1}])
    r = requests.get(viewer_server["url"] + f"/runs/{partial_id}/status", timeout=5)
    assert "incomplete" in r.json()["stage"]


def test_trace_endpoint_filters_by_since(viewer_server):
    run_id = "20260927-100156-4444aaaa4444"
    lines = [json.dumps({"n": i, "ts": i, "type": "tool_call", "tool": "search_strings",
                          "params": {}, "result": {}}) for i in (1, 2, 3)]
    _write_run(viewer_server["runs_dir"], run_id, triage={"file": "x", "sha256": "c" * 64}, trace_lines=lines)
    r = requests.get(viewer_server["url"] + f"/runs/{run_id}/trace?since=1", timeout=5)
    assert r.status_code == 200
    entries = r.json()
    assert [e["n"] for e in entries] == [2, 3]

    r_all = requests.get(viewer_server["url"] + f"/runs/{run_id}/trace", timeout=5)
    assert [e["n"] for e in r_all.json()] == [1, 2, 3]


def test_in_progress_run_page_embeds_live_poll_script(viewer_server):
    run_id = "20260927-100156-5555aaaa5555"
    _write_run(viewer_server["runs_dir"], run_id, triage={"file": "x", "sha256": "d" * 64},
               status={"stage": "agent", "iteration": 2, "max_iterations": 12, "ts": 1.0})
    r = requests.get(viewer_server["url"] + f"/runs/{run_id}", timeout=5)
    assert "id='trace-list'" in r.text
    assert f"var runId = \"{run_id}\";" in r.text
    assert "stage: agent (iteration 2/12)" in r.text


def test_completed_run_page_has_no_poll_script(viewer_server):
    run_id = "20260927-100156-6666aaaa6666"
    _write_run(viewer_server["runs_dir"], run_id, triage={"file": "x", "sha256": "e" * 64},
               final={"verdict": "benign", "confidence": 0.5, "summary": "", "evidence": []},
               status={"stage": "done", "ts": 1.0})
    r = requests.get(viewer_server["url"] + f"/runs/{run_id}", timeout=5)
    assert "id='live-stage'" not in r.text
    assert "var runId" not in r.text


@pytest.mark.parametrize("path", [
    "/runs/../secret/status", "/runs/%2e%2e/status", "/runs/not-a-run-id/status",
    "/runs/../secret/trace", "/runs/not-a-run-id/trace",
])
def test_status_and_trace_endpoints_cannot_traverse(viewer_server, path):
    (viewer_server["runs_dir"].parent / "secret.txt").write_text("host secret", encoding="utf-8")
    host, port = "127.0.0.1", int(viewer_server["url"].rsplit(":", 1)[1])
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    assert resp.status == 404, path
    assert b"host secret" not in body

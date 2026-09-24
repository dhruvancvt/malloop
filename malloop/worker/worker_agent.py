"""Runs INSIDE the REMnux (or any Linux) static-analysis VM. Stdlib only, Python 3.8+.

Runs capa and FLOSS on an uploaded file and returns their JSON. It never executes the sample; capa
and FLOSS only parse it. Put this VM on a host-only network with no internet, like the detonation guest.

Start at boot:  python3 worker_agent.py --token <MALLOOP_STATIC_WORKER_TOKEN> --host 0.0.0.0 --port 8766
"""
import argparse
import json
import os
import shutil
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN = ""
CAPA_BIN = os.environ.get("MALLOOP_WORKER_CAPA", "capa")
FLOSS_BIN = os.environ.get("MALLOOP_WORKER_FLOSS", "floss")


def run_tool(name: str, path: Path) -> dict:
    """Run one static tool on `path` and return {"ok", "result"} or {"skipped"|"error"}."""
    binary = {"capa": CAPA_BIN, "floss": FLOSS_BIN}.get(name)
    if binary is None:
        return {"error": f"unknown tool {name}"}
    if not shutil.which(binary):
        return {"skipped": f"{name} not installed in worker"}
    argv = {
        "capa": [binary, "-j", str(path)],
        "floss": [binary, "-j", "-q", str(path)],
    }[name]
    timeout = 900 if name == "floss" else 600
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired:
        return {"error": f"{name} timed out after {timeout}s"}
    if proc.returncode != 0:
        return {"error": proc.stderr[-2000:] or f"{name} exit {proc.returncode}"}
    try:
        return {"ok": True, "result": json.loads(proc.stdout)}
    except json.JSONDecodeError:
        return {"error": f"{name} produced non-JSON output"}


def analyze(data: bytes, tools: list) -> dict:
    with tempfile.TemporaryDirectory() as td:
        sample = Path(td) / "sample"
        sample.write_bytes(data)
        return {name: run_tool(name, sample) for name in tools}


def _parse_file_upload(body: bytes, content_type: str) -> bytes:
    boundary = content_type.split("boundary=", 1)[1].encode()
    part = body.split(b"--" + boundary)[1]
    return part.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n", 1)[0]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _auth(self) -> bool:
        if self.headers.get("X-Malloop-Token") != TOKEN:
            self.send_error(403)
            return False
        return True

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._auth():
            return
        if self.path == "/health":
            return self._json({"ok": True, "capa": bool(shutil.which(CAPA_BIN)),
                               "floss": bool(shutil.which(FLOSS_BIN))})
        self.send_error(404)

    def do_POST(self):
        # Drain the request body first so a rejected upload still gets a clean response (no socket reset).
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if not self._auth():
            return
        if self.path != "/analyze":
            return self.send_error(404)
        try:
            data = _parse_file_upload(body, self.headers.get("Content-Type", ""))
        except (IndexError, ValueError):
            return self._json({"error": "malformed upload"}, code=400)
        tools = (self.headers.get("X-Malloop-Tools") or "capa,floss").split(",")
        self._json(analyze(data, [t.strip() for t in tools if t.strip()]))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8766)
    a = ap.parse_args()
    TOKEN = a.token
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()

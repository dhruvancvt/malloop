"""Runs INSIDE the Windows analysis VM (stdlib only, Python 3.10+). Bake it into the clean snapshot.

Telemetry sources (install in the guest before snapshotting):
  - Sysmon with a verbose config (e.g. SwiftOnSecurity or olafhartong/sysmon-modular)
  - Optional: Procmon (procmon.exe on PATH) for file/registry detail
  - Optional: FakeNet-NG for simulated network services

Start at boot:  python guest_agent.py --token <MALLOOP_GUEST_TOKEN> --host 0.0.0.0 --port 8765
"""
import argparse
import json
import os
import shutil
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WORK = Path(os.environ.get("MALLOOP_GUEST_WORK", r"C:\malloop"))
SAMPLE_DIR = WORK / "sample"
OUT_DIR = WORK / "out"
TOKEN = ""
state = {"sample": None}


def ps(script: str, timeout: int = 120) -> str:
    return subprocess.run(["powershell", "-NoProfile", "-Command", script],
                          capture_output=True, text=True, timeout=timeout, errors="replace").stdout


def snapshot_processes() -> dict:
    out = ps("Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json")
    try:
        return {p["ProcessId"]: p for p in json.loads(out or "[]")}
    except json.JSONDecodeError:
        return {}


def sysmon_events(since_iso: str) -> list[dict]:
    script = (
        "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; "
        f"StartTime=[datetime]'{since_iso}'}} -ErrorAction SilentlyContinue | "
        "Select-Object -First 3000 Id,TimeCreated,Message | ConvertTo-Json -Depth 2"
    )
    try:
        events = json.loads(ps(script, timeout=180) or "[]")
    except json.JSONDecodeError:
        return []
    events = events if isinstance(events, list) else [events]
    parsed = []
    for e in events:
        fields = {}
        for line in (e.get("Message") or "").splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                fields[k.strip()] = v.strip()
        parsed.append({"id": e.get("Id"), **{k: fields[k] for k in (
            "Image", "CommandLine", "ParentImage", "TargetFilename", "TargetObject", "Details",
            "DestinationIp", "DestinationPort", "DestinationHostname", "QueryName", "TargetImage",
            "ImageLoaded") if k in fields}})
    return parsed


def run_sample(duration: int, args: list[str], network: str, dump: bool = False) -> dict:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sample = state["sample"]
    if not sample:
        return {"error": "no sample uploaded"}

    fakenet = None
    if network == "simulated" and shutil.which("fakenet"):
        fakenet = subprocess.Popen(["fakenet", "-l", str(OUT_DIR / "fakenet.log")], cwd=str(OUT_DIR))
        time.sleep(5)

    procmon = shutil.which("procmon")
    pml = OUT_DIR / "procmon.pml"
    if procmon:
        subprocess.Popen([procmon, "/AcceptEula", "/Quiet", "/Minimized", "/BackingFile", str(pml)])
        time.sleep(3)

    before = snapshot_processes()
    start_iso = time.strftime("%Y-%m-%dT%H:%M:%S")
    ext = sample.suffix.lower()
    launcher = {
        ".dll": ["rundll32.exe", f"{sample},DllMain"],
        ".ps1": ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(sample)],
        ".js": ["wscript.exe", str(sample)], ".vbs": ["wscript.exe", str(sample)],
        ".msi": ["msiexec", "/i", str(sample), "/qn"],
    }.get(ext, [str(sample)])
    try:
        proc = subprocess.Popen(launcher + list(args), cwd=str(SAMPLE_DIR))
        launch = {"pid": proc.pid, "cmd": launcher + list(args)}
    except OSError as e:
        launch = {"error": str(e)}

    time.sleep(duration)
    after = snapshot_processes()
    if dump:
        for pid in [pid for pid in after if pid not in before][:5]:
            dump_process(pid)

    if procmon:
        subprocess.run([procmon, "/Terminate"], timeout=60)
    if fakenet:
        fakenet.terminate()

    screenshot = OUT_DIR / "screen.png"
    ps("Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
       "$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;"
       "$bmp=New-Object Drawing.Bitmap $b.Width,$b.Height;"
       "[Drawing.Graphics]::FromImage($bmp).CopyFromScreen($b.Location,[Drawing.Point]::Empty,$b.Size);"
       f"$bmp.Save('{screenshot}')")

    events = sysmon_events(start_iso)
    (OUT_DIR / "sysmon.json").write_text(json.dumps(events), encoding="utf-8")
    new_procs = [p for pid, p in after.items() if pid not in before]
    artifacts = [p.name for p in OUT_DIR.iterdir() if p.is_file()]
    return {"launch": launch, "duration": duration, "network": network,
            "new_processes": new_procs, "sysmon_event_count": len(events),
            "sysmon_events": events, "artifacts": artifacts}


def dump_process(pid: int) -> dict:
    procdump = shutil.which("procdump") or shutil.which("procdump64")
    if not procdump:
        return {"error": "procdump not installed in guest"}
    out = OUT_DIR / f"pid{pid}.dmp"
    subprocess.run([procdump, "-accepteula", "-ma", str(pid), str(out)], timeout=180)
    return {"artifacts": [out.name]} if out.exists() else {"error": "dump failed"}


class Handler(BaseHTTPRequestHandler):
    def _auth(self) -> bool:
        if self.headers.get("X-Malloop-Token") != TOKEN:
            self.send_error(403)
            return False
        return True

    def _json(self, obj, code=200):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._auth():
            return
        if self.path == "/health":
            return self._json({"ok": True})
        if self.path.startswith("/artifact/"):
            f = OUT_DIR / Path(self.path.split("/artifact/", 1)[1]).name
            if not f.exists():
                return self.send_error(404)
            data = f.read_bytes()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_error(404)

    def do_POST(self):
        if not self._auth():
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        if self.path == "/sample":
            # Minimal multipart parsing: single file field
            boundary = self.headers["Content-Type"].split("boundary=")[1].encode()
            part = body.split(b"--" + boundary)[1]
            header, content = part.split(b"\r\n\r\n", 1)
            name = header.split(b'filename="')[1].split(b'"')[0].decode()
            SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
            dest = SAMPLE_DIR / Path(name).name
            dest.write_bytes(content.rsplit(b"\r\n", 1)[0])
            state["sample"] = dest
            return self._json({"stored": str(dest)})
        req = json.loads(body or b"{}")
        if self.path == "/run":
            return self._json(run_sample(int(req["duration"]), req.get("args", []), req.get("network", "none"),
                                             bool(req.get("dump", False))))
        self.send_error(404)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()
    TOKEN = a.token
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()

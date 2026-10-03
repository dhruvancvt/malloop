"""Read-only local web viewer for run reports (malloop/cli.py's runs/<id>/ output).

Serves HTML only, from config.RUNS_DIR, over plain HTTP on 127.0.0.1 by default. Every value that
originates from the analyzed sample (strings, filenames, decompiled snippets, IOCs, agent tool
params/results) is untrusted the same way it is for the LLM in agent.py's <untrusted> wrapper, and is
HTML-escaped before it reaches a template. Never bind this to a non-loopback address without also
putting auth in front of it: run reports contain real IOCs (C2 hosts, ransom notes, etc).
"""
import html
import json
import re
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import config

RUN_ID_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6,64}$")

# Polls /runs/<id>/status and /runs/<id>/trace every 2s while a run is in progress, appending new trace
# entries via textContent (never innerHTML) so sample-derived text can't inject markup client-side either.
POLL_JS = """
(function () {
  var runId = "__RUN_ID__";
  var since = __SINCE__;
  function appendEntry(e) {
    var list = document.getElementById('trace-list');
    if (!list) return;
    if (e.type === 'text') {
      var div = document.createElement('div');
      div.className = 'trace-text';
      div.textContent = '#' + e.n + ' [agent] ' + (e.text || '');
      list.appendChild(div);
    } else {
      var det = document.createElement('details');
      var sum = document.createElement('summary');
      sum.textContent = '#' + e.n + ' ' + e.tool;
      var p1 = document.createElement('pre');
      p1.textContent = 'input: ' + JSON.stringify(e.params, null, 2);
      var p2 = document.createElement('pre');
      p2.textContent = (e.output_label || 'output') + ': ' + JSON.stringify(e.result, null, 2);
      det.appendChild(sum); det.appendChild(p1); det.appendChild(p2);
      list.appendChild(det);
    }
  }
  function tick() {
    fetch('/runs/' + runId + '/trace?since=' + since).then(function (r) { return r.json(); })
      .then(function (entries) { entries.forEach(function (e) { appendEntry(e); since = e.n; }); })
      .catch(function () {});
    fetch('/runs/' + runId + '/status').then(function (r) { return r.json(); })
      .then(function (s) {
        var el = document.getElementById('live-stage');
        if (el) {
          var extra = (s.iteration != null && s.max_iterations != null)
            ? ' (iteration ' + s.iteration + '/' + s.max_iterations + ')' : '';
          el.textContent = 'stage: ' + s.stage + extra;
        }
        if (s.stage === 'done' || s.stage === 'failed') { location.reload(); } else { setTimeout(tick, 2000); }
      })
      .catch(function () { setTimeout(tick, 2000); });
  }
  tick();
})();
"""

CSS = """
body { font: 14px/1.5 -apple-system, Segoe UI, sans-serif; margin: 0; padding: 2rem; background: #0f1115;
       color: #d8dbe2; }
a { color: #7aa2f7; }
h1, h2, h3 { color: #f2f4f8; }
table { border-collapse: collapse; width: 100%; margin: 0.5rem 0 1.5rem; }
th, td { text-align: left; padding: 0.35rem 0.6rem; border-bottom: 1px solid #262a35; vertical-align: top; }
th { color: #9aa4b2; font-weight: 600; }
tr:hover td { background: #171a22; }
.badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 0.3rem; font-weight: 600; }
.malicious { background: #3a1620; color: #ff8a9a; }
.suspicious { background: #3a2f16; color: #ffcf80; }
.benign { background: #16321f; color: #7fe0a0; }
.inconclusive, .unknown { background: #23262f; color: #9aa4b2; }
pre { background: #171a22; padding: 0.75rem; border-radius: 0.4rem; overflow-x: auto; white-space: pre-wrap;
      word-break: break-word; }
code { font-family: Consolas, monospace; }
details { margin: 0.4rem 0; }
summary { cursor: pointer; color: #9aa4b2; }
.section { margin: 1.5rem 0; }
.muted { color: #6b7280; }
.trace-text { margin: 0.3rem 0; color: #9aa4b2; }
.trace-text em { color: #7aa2f7; font-style: normal; }
"""


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _parse_since(query: str) -> int:
    try:
        return int(urllib.parse.parse_qs(query).get("since", ["0"])[0])
    except (ValueError, IndexError):
        return 0


def _load_trace(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue  # tolerate a truncated last line from a run still in progress
        if e.get("type") != "text":
            e["output_label"] = _output_label(e.get("result"))
        entries.append(e)
    return entries


def _output_label(result) -> str:
    """Says how much of a tool result got past `_clip` in agent.py to the model."""
    # ponytail: uses this process's MAX_TOOL_OUTPUT_CHARS, which is the run's unless the env var changed between them
    n, limit = len(json.dumps(result, default=str)), config.MAX_TOOL_OUTPUT_CHARS
    return f"output (the agent saw only the first {limit:,} of {n:,} chars)" if n > limit else "output"


def _pretty(value, cap: int = 60000) -> str:
    text = json.dumps(value, indent=2, default=str)
    return _esc(text[:cap] + (f"\n... [{len(text) - cap:,} more chars]" if len(text) > cap else ""))


def _page(title: str, body: str) -> bytes:
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>{_esc(title)}</title><style>{CSS}</style></head>"
            f"<body>{body}</body></html>").encode("utf-8")


def _badge(verdict: str | None) -> str:
    cls = (verdict or "unknown").lower()
    if cls not in ("malicious", "suspicious", "benign", "inconclusive"):
        cls = "unknown"
    return f"<span class='badge {cls}'>{_esc(verdict or 'unknown')}</span>"


def _run_timestamp(run_id: str) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.strptime(run_id[:15], "%Y%m%d-%H%M%S"))
    except ValueError:
        return run_id


def _status_for(run_dir: Path) -> dict:
    """The live pipeline stage for a run. Authoritative source is status.json; older runs (recorded
    before the viewer could show live progress) fall back to inferring it from what's on disk."""
    status = _load_json(run_dir / "status.json")
    if status:
        return status
    if (run_dir / "final.json").exists():
        return {"stage": "done"}
    return {"stage": _run_summary(run_dir)["status"]}


def _describe_status(status: dict) -> str:
    stage = status.get("stage", "unknown")
    if stage == "failed":
        return f"failed: {status.get('error', 'unknown error')}"
    if stage == "agent" and status.get("iteration") is not None:
        return f"stage: agent (iteration {status['iteration']}/{status.get('max_iterations', '?')})"
    return f"stage: {stage}"


def _run_summary(run_dir: Path) -> dict:
    unpack = _load_json(run_dir / "unpack.json") or []
    triage = _load_json(run_dir / "triage.json")
    final = _load_json(run_dir / "final.json")
    sample_name = (unpack[0]["name"] if unpack else (triage or {}).get("file")) or "?"
    if final:
        status = final.get("verdict", "unknown")
    elif (_load_json(run_dir / "status.json") or {}).get("stage") == "failed":
        status = "failed"
    elif (run_dir / "static.json").exists():
        status = "no verdict (static-only or incomplete)"
    elif triage:
        status = "incomplete (triage only)"
    elif unpack:
        status = "incomplete (unpack only)"
    else:
        status = "starting"
    return {
        "id": run_dir.name,
        "sample_name": sample_name,
        "status": status,
        "confidence": (final or {}).get("confidence"),
        "family": (final or {}).get("family"),
        "timestamp": _run_timestamp(run_dir.name),
    }


def _iter_run_dirs():
    if not config.RUNS_DIR.is_dir():
        return
    for child in sorted(config.RUNS_DIR.iterdir(), reverse=True):
        if child.is_dir() and RUN_ID_RE.match(child.name):
            yield child


def render_index() -> bytes:
    rows = []
    for run_dir in _iter_run_dirs():
        s = _run_summary(run_dir)
        conf = f" ({s['confidence']})" if s["confidence"] is not None else ""
        rows.append(
            f"<tr><td>{s['timestamp']}</td>"
            f"<td><a href='/runs/{_esc(s['id'])}'>{_esc(s['id'])}</a></td>"
            f"<td>{_esc(s['sample_name'])}</td>"
            f"<td>{_badge(s['status'])}{_esc(conf)}</td>"
            f"<td>{_esc(s['family'] or '')}</td></tr>"
        )
    body = (
        "<h1>malloop runs</h1>"
        + ("<p class='muted'>No runs yet — analyze a sample to populate this list.</p>" if not rows else
           "<table><tr><th>Started</th><th>Run</th><th>Sample</th><th>Verdict</th><th>Family</th></tr>"
           + "".join(rows) + "</table>")
    )
    return _page("malloop runs", body)


def _render_capa(capa) -> str:
    if not isinstance(capa, dict) or not capa.get("capabilities"):
        note = capa.get("skipped") if isinstance(capa, dict) else None
        return f"<p class='muted'>capa: {_esc(note or 'no capabilities found')}</p>"
    rows = "".join(
        f"<tr><td>{_esc(c.get('capability'))}</td><td>{_esc(c.get('namespace') or '')}</td>"
        f"<td>{_esc(', '.join(c.get('attack') or []))}</td></tr>"
        for c in capa["capabilities"]
    )
    return ("<table><tr><th>Capability</th><th>Namespace</th><th>ATT&amp;CK</th></tr>" + rows + "</table>")


def _render_floss(floss) -> str:
    if not isinstance(floss, dict) or not floss:
        return "<p class='muted'>floss: no output</p>"
    parts = []
    for kind, values in floss.items():
        if not isinstance(values, list):
            continue
        shown = "\n".join(_esc(v) for v in values[:50])
        more = f"\n... [{len(values) - 50} more]" if len(values) > 50 else ""
        parts.append(f"<details><summary>{_esc(kind)} ({len(values)})</summary><pre>{shown}{more}</pre></details>")
    return "".join(parts) or "<p class='muted'>floss: no strings recovered</p>"


def _render_trace_entry(a: dict) -> str:
    # "type" is missing on entries written before this field existed; treat those as tool calls.
    if a.get("type") == "text":
        return f"<div class='trace-text'>#{a.get('n')} <em>[agent]</em> {_esc(a.get('text', ''))}</div>"
    return (f"<details><summary>#{a.get('n')} <code>{_esc(a.get('tool'))}</code></summary>"
            f"<pre>input: {_pretty(a.get('params'))}</pre>"
            f"<pre>{_esc(a.get('output_label', 'output'))}: {_pretty(a.get('result'))}</pre></details>")


def _render_trace(actions: list[dict]) -> str:
    if not actions:
        return "<p class='muted'>No agent actions recorded (static-only run, or the agent stage hasn't started).</p>"
    return "".join(_render_trace_entry(a) for a in actions)


def _resolve_run_dir(run_id: str) -> Path | None:
    if not RUN_ID_RE.match(run_id):
        return None
    run_dir = (config.RUNS_DIR / run_id).resolve()
    if not run_dir.is_relative_to(config.RUNS_DIR.resolve()) or not run_dir.is_dir():
        return None
    return run_dir


def render_run(run_id: str) -> bytes | None:
    run_dir = _resolve_run_dir(run_id)
    if run_dir is None:
        return None

    unpack = _load_json(run_dir / "unpack.json") or []
    triage = _load_json(run_dir / "triage.json")
    static = _load_json(run_dir / "static.json")
    final = _load_json(run_dir / "final.json")
    actions = _load_trace(run_dir / "trace.jsonl")
    summary = _run_summary(run_dir)
    status = _status_for(run_dir)
    live = status.get("stage") not in ("done", "failed")

    confidence_text = f"(confidence {final.get('confidence')})" if final else ""
    sections = ["<p><a href='/'>&laquo; all runs</a></p>",
                f"<h1>{_esc(summary['sample_name'])}</h1>",
                f"<p>{_badge(summary['status'])} {_esc(confidence_text)} "
                f"&middot; started {summary['timestamp']} &middot; <code>{_esc(run_id)}</code></p>"]
    if status.get("stage") != "done":
        sections.append(f"<p id='live-stage' class='muted'>{_esc(_describe_status(status))}</p>")

    if final:
        sections.append("<div class='section'><h2>Verdict</h2>"
                         f"<p><b>Family:</b> {_esc(final.get('family') or 'unknown')}</p>"
                         f"<p>{_esc(final.get('summary') or '')}</p>"
                         "<h3>Evidence</h3><ul>"
                         + "".join(f"<li>{_esc(e)}</li>" for e in final.get("evidence") or [])
                         + "</ul><h3>ATT&amp;CK</h3><ul>"
                         + "".join(f"<li>{_esc(t)}</li>" for t in final.get("attack_techniques") or [])
                         + "</ul><h3>IOCs</h3>"
                         + "".join(f"<h4>{_esc(k)}</h4><ul>" + "".join(f"<li><code>{_esc(v)}</code></li>" for v in vs)
                                   + "</ul>" for k, vs in (final.get("iocs") or {}).items())
                         + "</div>")

    if triage:
        sections.append("<div class='section'><h2>Triage</h2>"
                         f"<p><b>File:</b> {_esc(triage.get('file'))} &middot; "
                         f"<b>Type:</b> {_esc(triage.get('type'))} &middot; "
                         f"<b>Size:</b> {_esc(triage.get('size'))} bytes &middot; "
                         f"<b>Entropy:</b> {_esc(triage.get('entropy'))}</p>"
                         f"<p><b>SHA256:</b> <code>{_esc(triage.get('sha256'))}</code></p></div>")

    if len(unpack) > 1:
        rows = "".join(
            f"<tr><td>{_esc(n.get('id'))}</td><td>{_esc(n.get('depth'))}</td><td>{_esc(n.get('name'))}</td>"
            f"<td>{_esc(n.get('type'))}</td><td>{_esc(n.get('size'))}</td></tr>" for n in unpack)
        sections.append("<div class='section'><h2>Container contents</h2>"
                         "<table><tr><th>id</th><th>depth</th><th>name</th><th>type</th><th>size</th></tr>"
                         + rows + "</table></div>")

    if static:
        sections.append("<div class='section'><h2>Static analysis</h2>"
                         f"<p class='muted'>worker: {_esc(static.get('worker') or 'local')}</p>"
                         "<h3>capa</h3>" + _render_capa(static.get("capa"))
                         + "<h3>FLOSS</h3>" + _render_floss(static.get("floss"))
                         + "<details><summary>Ghidra (raw)</summary><pre>"
                         + _esc(json.dumps(static.get("ghidra"), indent=2, default=str))[:8000] + "</pre></details>"
                         "</div>")

    brief = _load_json(run_dir / "brief.json")
    brief_html = ("<details><summary>#0 <code>initial brief</code> (the evidence the agent started from)</summary>"
                  f"<pre>{_pretty(brief)}</pre></details>") if brief else ""
    sections.append("<div class='section'><h2>Agent trace</h2>" + brief_html + "<div id='trace-list'>"
                     + _render_trace(actions) + "</div></div>")
    if live:
        since0 = max((a.get("n", 0) for a in actions), default=0)
        js = POLL_JS.replace("__RUN_ID__", run_id).replace("__SINCE__", str(since0))
        sections.append(f"<script>{js}</script>")
    return _page(summary["sample_name"], "".join(sections))


class Handler(BaseHTTPRequestHandler):
    def _send_html(self, body: bytes, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj, code: int = 200) -> None:
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self):
        return self._send_html(_page("not found", "<p>No such run.</p>"), 404)

    def do_GET(self):
        if self.path == "/":
            return self._send_html(render_index())
        if not self.path.startswith("/runs/"):
            return self._not_found()

        rest = self.path[len("/runs/"):]
        path_no_query, _, query = rest.partition("?")
        run_id, _, sub = path_no_query.partition("/")
        run_dir = _resolve_run_dir(run_id)
        if run_dir is None:
            return self._not_found()

        if sub == "":
            page = render_run(run_id)
            return self._send_html(page) if page else self._not_found()
        if sub == "status":
            return self._send_json(_status_for(run_dir))
        if sub == "trace":
            since = _parse_since(query)
            entries = [e for e in _load_trace(run_dir / "trace.jsonl") if e.get("n", 0) > since]
            return self._send_json(entries)
        return self._not_found()

    def log_message(self, fmt, *args):
        pass  # keep stdout quiet; this is a local read-only viewer, not a service to audit


def serve(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"[*] malloop viewer: http://{host}:{port}  (runs dir: {config.RUNS_DIR})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

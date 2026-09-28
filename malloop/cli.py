"""Entry point: python -m malloop analyze <file> [--static-only]"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

from . import config
from .evidence import Run
from .sandbox import get_sandbox
from .static_analysis import Ghidra, run_static
from .tools import ToolExecutor, compact_tree
from .triage import triage
from .unpack import pick_primary, unpack_tree


def write_report(run: Run, triage_report: dict, final: dict, tree: list[dict]) -> Path:
    lines = [
        f"# malloop report: {tree[0]['name']}",
        "",
        f"- **Submitted SHA256:** `{tree[0]['sha256']}`",
        f"- **Primary target:** `{triage_report['file']}` (`{triage_report['sha256']}`)",
        f"- **Type:** {triage_report['type']}, {triage_report['size']} bytes, entropy {triage_report['entropy']}",
        f"- **Verdict:** **{final.get('verdict')}** (confidence {final.get('confidence')})",
        f"- **Family:** {final.get('family') or 'unknown'}",
        "",
        "## Summary",
        final.get("summary", ""),
        "",
        "## Evidence",
        *[f"- {e}" for e in final.get("evidence", [])],
        "",
        "## ATT&CK",
        *[f"- {t}" for t in final.get("attack_techniques", [])],
        "",
        "## IOCs",
    ]
    for kind, vals in (final.get("iocs") or {}).items():
        lines += [f"### {kind}", *[f"- `{v}`" for v in vals]]
    if len(tree) > 1:
        lines += ["", "## Container contents", "", "| id | depth | name | type | size | sha256 |", "|---|---|---|---|---|---|"]
        lines += [f"| {n['id']} | {n['depth']} | `{n['name']}` | {n['type']} | {n['size']} | `{n['sha256'][:16]}` |"
                  for n in tree]
    lines += ["", "## Action trace"]
    for a in run.actions:
        if a.get("type") == "text":
            lines.append(f"{a['n']}. [agent] {a['text']}")
        else:
            lines.append(f"{a['n']}. `{a['tool']}` {json.dumps(a['params'])}")
    path = run.run_dir / "report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def analyze(sample: Path, static_only: bool, client=None, sandbox=None) -> Path | None:
    """Run the full pipeline and return the report path. `client`/`sandbox` are injectable for tests."""
    sha256 = hashlib.sha256(sample.read_bytes()).hexdigest()
    run = Run.create(config.RUNS_DIR, sample, sha256)
    print(f"[*] run dir: {run.run_dir}")
    try:
        return _pipeline(run, sample, static_only, client, sandbox)
    except BaseException as e:  # includes Ctrl+C: otherwise the viewer shows a dead run as still in progress
        run.set_status("failed", error=f"{type(e).__name__}: {e}")
        raise


def _pipeline(run: Run, sample: Path, static_only: bool, client, sandbox) -> Path | None:
    run.set_status("unpack")
    print("[*] stage 0: recursive unpack")
    nodes = unpack_tree(sample, run.run_dir / "extracted")
    run.save("unpack", nodes)

    run.set_status("triage")
    print(f"[*] stage 1: triage ({len(nodes)} file(s))")
    node_triage, node_strings = {}, {}
    for n in nodes:
        if not n["duplicate_of"]:
            node_triage[n["id"]], node_strings[n["id"]] = triage(Path(n["path"]), config.YARA_RULES_DIR)
    tree = compact_tree(nodes, node_triage)
    for n in tree:
        print(f"    {'  ' * n['depth']}{n['id']:<4} {n['type']:<9} {n['size']:>10}  {n['name']}")
        for note in n.get("notes", []):
            print(f"    {'  ' * n['depth']}     ! {note}")
    primary = pick_primary(nodes, node_triage)
    target = Path(primary["path"])
    triage_report, strs = node_triage[primary["id"]], node_strings[primary["id"]]
    run.save("triage", triage_report)
    run.sample = target
    print(f"[*] primary target: {primary['id']} {primary['name']}")

    run.set_status("static")
    print("[*] stage 2: static analysis")
    ghidra = Ghidra(target, run.run_dir / "ghidra" / primary["id"])
    static_report = run_static(target, ghidra)
    run.save("static", static_report)
    floss_strs = [s for v in static_report["floss"].values() if isinstance(v, list) for s in v if s]
    all_strings = strs + floss_strs

    if static_only:
        run.set_status("done", static_only=True)
        print(json.dumps({"primary": primary["id"], "triage": triage_report, "static": static_report},
                         indent=2, default=str)[:5000])
        return None

    run.set_status("agent", iteration=0, max_iterations=config.MAX_ITERATIONS)
    print("[*] stage 3: agent loop")
    from .agent import run_agent  # imported lazily so --static-only works without an API key

    executor = ToolExecutor(run, ghidra, sandbox or get_sandbox(), all_strings, nodes, node_triage, primary)
    evidence = {"container_tree": tree if len(tree) > 1 else None, "primary_target": primary["id"],
                "triage": triage_report, "static": static_report, "sample_strings_head": all_strings[:300]}
    final = run_agent(evidence, executor, client=client)
    run.save("final", final)
    report = write_report(run, triage_report, final, tree)
    run.set_status("done")
    print(f"[+] verdict: {final.get('verdict')} ({final.get('confidence')})")
    print(f"[+] report: {report}")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(prog="malloop")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze a sample")
    a.add_argument("sample", type=Path)
    a.add_argument("--static-only", action="store_true", help="skip the agent and dynamic analysis")
    v = sub.add_parser("viewer", help="serve a read-only web viewer for runs/<id>/ reports")
    v.add_argument("--host", default=config.VIEWER_HOST)
    v.add_argument("--port", type=int, default=config.VIEWER_PORT)
    args = ap.parse_args()
    if args.cmd == "viewer":
        from .viewer import serve
        return serve(args.host, args.port)
    if not args.sample.is_file():
        sys.exit(f"not a file: {args.sample}")
    analyze(args.sample.resolve(), args.static_only)


if __name__ == "__main__":
    main()

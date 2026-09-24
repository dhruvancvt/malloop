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
    lines += [f"{a['n']}. `{a['tool']}` {json.dumps(a['params'])}" for a in run.actions]
    path = run.run_dir / "report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def analyze(sample: Path, static_only: bool) -> None:
    sha256 = hashlib.sha256(sample.read_bytes()).hexdigest()
    run = Run.create(config.RUNS_DIR, sample, sha256)
    print(f"[*] run dir: {run.run_dir}")

    print("[*] stage 0: recursive unpack")
    nodes = unpack_tree(sample, run.run_dir / "extracted")
    run.save("unpack", nodes)

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

    print("[*] stage 2: static analysis")
    ghidra = Ghidra(target, run.run_dir / "ghidra" / primary["id"])
    static_report = run_static(target, ghidra)
    run.save("static", static_report)
    floss_strs = [s for v in static_report["floss"].values() if isinstance(v, list) for s in v if s]
    all_strings = strs + floss_strs

    if static_only:
        print(json.dumps({"primary": primary["id"], "triage": triage_report, "static": static_report},
                         indent=2, default=str)[:5000])
        return

    print("[*] stage 3: agent loop")
    from .agent import run_agent  # imported lazily so --static-only works without an API key

    executor = ToolExecutor(run, ghidra, get_sandbox(), all_strings, nodes, node_triage, primary)
    evidence = {"container_tree": tree if len(tree) > 1 else None, "primary_target": primary["id"],
                "triage": triage_report, "static": static_report, "sample_strings_head": all_strings[:300]}
    final = run_agent(evidence, executor)
    run.save("final", final)
    report = write_report(run, triage_report, final, tree)
    print(f"[+] verdict: {final.get('verdict')} ({final.get('confidence')})")
    print(f"[+] report: {report}")


def main() -> None:
    ap = argparse.ArgumentParser(prog="malloop")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze a sample")
    a.add_argument("sample", type=Path)
    a.add_argument("--static-only", action="store_true", help="skip the agent and dynamic analysis")
    args = ap.parse_args()
    if not args.sample.is_file():
        sys.exit(f"not a file: {args.sample}")
    analyze(args.sample.resolve(), args.static_only)


if __name__ == "__main__":
    main()

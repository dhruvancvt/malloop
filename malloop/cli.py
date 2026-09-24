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
from .tools import ToolExecutor
from .triage import triage


def write_report(run: Run, triage_report: dict, final: dict) -> Path:
    lines = [
        f"# malloop report: {triage_report['file']}",
        "",
        f"- **SHA256:** `{triage_report['sha256']}`",
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
    lines += ["", "## Action trace"]
    lines += [f"{a['n']}. `{a['tool']}` {json.dumps(a['params'])}" for a in run.actions]
    path = run.run_dir / "report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def analyze(sample: Path, static_only: bool) -> None:
    sha256 = hashlib.sha256(sample.read_bytes()).hexdigest()
    run = Run.create(config.RUNS_DIR, sample, sha256)
    print(f"[*] run dir: {run.run_dir}")

    print("[*] stage 1: triage")
    triage_report, strs = triage(sample, config.YARA_RULES_DIR)
    run.save("triage", triage_report)

    print("[*] stage 2: static analysis")
    ghidra = Ghidra(sample, run.run_dir)
    static_report = run_static(sample, ghidra)
    run.save("static", static_report)
    floss_strs = [s for v in static_report["floss"].values() if isinstance(v, list) for s in v if s]
    all_strings = strs + floss_strs

    if static_only:
        print(json.dumps({"triage": triage_report, "static": static_report}, indent=2, default=str)[:5000])
        return

    print("[*] stage 3: agent loop")
    from .agent import run_agent  # imported lazily so --static-only works without an API key

    executor = ToolExecutor(run, ghidra, get_sandbox(), all_strings)
    evidence = {"triage": triage_report, "static": static_report,
                "sample_strings_head": all_strings[:300]}
    final = run_agent(evidence, executor)
    run.save("final", final)
    report = write_report(run, triage_report, final)
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

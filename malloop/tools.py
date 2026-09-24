"""The fixed action catalog. The agent can ONLY request these; each is validated and executed deterministically."""
import json
import re
from collections import Counter

from . import config
from .evidence import Run
from .sandbox import Sandbox
from .static_analysis import Ghidra, run_static
from .triage import triage

# Types the Windows analysis guest can meaningfully execute.
WINDOWS_RUNNABLE = {"pe", "script", "ole", "pdf", "zip", "unknown"}

TOOLS = [
    {
        "name": "decompile_function",
        "description": "Decompile one function with Ghidra. Target is a hex address (e.g. 0x401000) or a function name from the static report.",
        "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
    },
    {
        "name": "xrefs",
        "description": "Get callers/callees of a function (address or name), or find which functions reference a string.",
        "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
    },
    {
        "name": "search_strings",
        "description": "Regex search over all extracted strings (static + FLOSS-decoded). Returns up to 100 matches.",
        "input_schema": {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]},
    },
    {
        "name": "list_extracted",
        "description": "List every file recursively unpacked from the submitted container (zip/dmg/...), with type, size, entropy, YARA hits and unpack notes. Node ids are used by switch_target.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "switch_target",
        "description": "Make a different extracted file the current analysis target: runs triage + full static analysis on it and points decompile/xrefs/search_strings/run_dynamic at it.",
        "input_schema": {"type": "object", "properties": {"node_id": {"type": "string"}}, "required": ["node_id"]},
    },
    {
        "name": "run_dynamic",
        "description": (
            "Detonate the sample in a fresh snapshot of the isolated analysis VM and collect Sysmon, process, file, "
            "registry and network telemetry. Expensive: consumes the dynamic time budget. network='none' blocks all "
            "traffic; 'simulated' answers DNS/HTTP with fake services (FakeNet). Real internet is never available."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "duration_seconds": {"type": "integer", "minimum": 15, "maximum": 300},
                "args": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
                "network": {"type": "string", "enum": ["none", "simulated"]},
                "dump_new_processes": {"type": "boolean", "description": "Full memory dump of up to 5 spawned processes (for unpacked payloads)."},
                "hypothesis": {"type": "string", "description": "What you expect to observe and why."},
            },
            "required": ["duration_seconds", "network", "hypothesis"],
        },
    },
    {
        "name": "query_dynamic_events",
        "description": "Filter the full Sysmon event log from a previous run_dynamic call (by run number). Event IDs: 1 proc create, 3 net conn, 7 image load, 8 remote thread, 10 proc access, 11 file create, 13 reg set, 22 DNS.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dynamic_run": {"type": "integer", "minimum": 1},
                "event_ids": {"type": "array", "items": {"type": "integer"}},
                "contains": {"type": "string"},
            },
            "required": ["dynamic_run"],
        },
    },
    {
        "name": "finish",
        "description": "End the analysis with a final verdict and report.",
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign", "inconclusive"]},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "family": {"type": "string"},
                "summary": {"type": "string"},
                "attack_techniques": {"type": "array", "items": {"type": "string"}},
                "iocs": {"type": "object", "additionalProperties": {"type": "array", "items": {"type": "string"}}},
                "evidence": {"type": "array", "items": {"type": "string"}, "description": "Key observations backing the verdict."},
            },
            "required": ["verdict", "confidence", "summary", "evidence"],
        },
    },
]

TOOL_NAMES = {t["name"] for t in TOOLS}


def summarize_dynamic(report: dict) -> dict:
    """Compress raw guest telemetry into something an LLM can reason over."""
    if "skipped" in report or "error" in report:
        return report
    ev = report.get("sysmon_events", [])
    by_id = Counter(e["id"] for e in ev)

    def uniq(ids, key, n=40):
        return sorted({e[key] for e in ev if e["id"] in ids and key in e})[:n]

    return {
        "launch": report.get("launch"),
        "event_counts_by_id": dict(by_id),
        "processes_created": [f'{e.get("ParentImage")} -> {e.get("CommandLine")}' for e in ev if e["id"] == 1][:40],
        "files_created": uniq({11}, "TargetFilename"),
        "registry_set": [f'{e.get("TargetObject")} = {e.get("Details")}' for e in ev if e["id"] == 13][:40],
        "dns_queries": uniq({22}, "QueryName"),
        "network": sorted({f'{e.get("DestinationIp")}:{e.get("DestinationPort")}' for e in ev if e["id"] == 3})[:40],
        "remote_threads_or_access": [f'{e.get("Image")} -> {e.get("TargetImage")}' for e in ev if e["id"] in (8, 10)][:30],
        "artifacts": report.get("artifacts", []),
    }


def compact_tree(nodes: list[dict], node_triage: dict[str, dict]) -> list[dict]:
    out = []
    for n in nodes:
        t = node_triage.get(n["id"], {})
        out.append({k: v for k, v in {
            "id": n["id"], "name": n["name"], "type": n["type"], "size": n["size"], "depth": n["depth"],
            "parent": n["parent"], "sha256": n["sha256"], "entropy": t.get("entropy"), "yara": t.get("yara") or None,
            "duplicate_of": n["duplicate_of"], "unpacked_via": n["method"], "notes": n["notes"] or None,
        }.items() if v is not None})
    return out


class ToolExecutor:
    def __init__(self, run: Run, ghidra: Ghidra, sandbox: Sandbox, all_strings: list[str],
                 nodes: list[dict], node_triage: dict[str, dict], target: dict):
        self.run = run
        self.ghidra = ghidra
        self.sandbox = sandbox
        self.all_strings = all_strings
        self.nodes = {n["id"]: n for n in nodes}
        self.node_triage = node_triage
        self.target = target
        self.dynamic_reports: list[dict] = []
        self.final: dict | None = None

    def execute(self, name: str, params: dict) -> dict:
        if name not in TOOL_NAMES:
            return {"error": f"unknown tool {name}"}
        try:
            result = getattr(self, f"_{name}")(**params)
        except TypeError as e:
            result = {"error": f"bad parameters: {e}"}
        except Exception as e:  # tool failures are reported back to the agent, not raised
            result = {"error": f"{type(e).__name__}: {e}"}
        self.run.log_action(name, params, result)
        return result

    def _list_extracted(self) -> dict:
        return {"current_target": self.target["id"],
                "nodes": compact_tree(list(self.nodes.values()), self.node_triage)}

    def _switch_target(self, node_id: str) -> dict:
        node = self.nodes.get(node_id)
        if node is None:
            return {"error": f"unknown node {node_id}"}
        if node["duplicate_of"]:
            return {"error": f"{node_id} is identical to {node['duplicate_of']}; switch to that instead"}
        path = Path(node["path"])
        triage_report, strs = triage(path, config.YARA_RULES_DIR)
        self.ghidra = Ghidra(path, self.run.run_dir / "ghidra" / node_id)
        static_report = run_static(path, self.ghidra)
        floss = [x for v in static_report["floss"].values() if isinstance(v, list) for x in v if x]
        self.all_strings = strs + floss
        self.run.sample = path
        self.target = node
        self.run.save(f"triage_{node_id}", triage_report)
        self.run.save(f"static_{node_id}", static_report)
        return {"target": node_id, "name": node["name"], "triage": triage_report, "static": static_report}

    def _decompile_function(self, target: str) -> dict:
        return self.ghidra.decompile(target)

    def _xrefs(self, target: str) -> dict:
        return self.ghidra.xrefs(target)

    def _search_strings(self, pattern: str) -> dict:
        rx = re.compile(pattern, re.I)
        return {"matches": [s for s in self.all_strings if rx.search(s)][:100]}

    def _run_dynamic(self, duration_seconds: int, network: str, hypothesis: str,
                     args: list[str] | None = None, dump_new_processes: bool = False) -> dict:
        duration_seconds = max(15, min(300, int(duration_seconds)))
        if network not in ("none", "simulated"):
            return {"error": "network must be 'none' or 'simulated'"}
        if self.target["type"] not in WINDOWS_RUNNABLE:
            return {"error": f"current target is type '{self.target['type']}'; the sandbox only has a Windows "
                             "guest. Analyze it statically, or switch_target to a Windows-runnable file."}
        remaining = config.MAX_DYNAMIC_SECONDS_TOTAL - self.run.dynamic_seconds_used
        if duration_seconds > remaining:
            return {"error": f"dynamic budget exhausted ({remaining}s left)"}
        self.run.dynamic_seconds_used += duration_seconds
        n = len(self.dynamic_reports) + 1
        out_dir = self.run.run_dir / "artifacts" / f"dynamic{n}"
        out_dir.mkdir(parents=True, exist_ok=True)
        raw = self.sandbox.detonate(self.run.sample, duration_seconds, args or [], network, out_dir,
                                    dump=dump_new_processes)
        self.dynamic_reports.append(raw)
        self.run.save(f"dynamic{n}_raw", raw)
        return {"dynamic_run": n, **summarize_dynamic(raw)}

    def _query_dynamic_events(self, dynamic_run: int, event_ids: list[int] | None = None,
                              contains: str | None = None) -> dict:
        if not 1 <= dynamic_run <= len(self.dynamic_reports):
            return {"error": "no such dynamic run"}
        ev = self.dynamic_reports[dynamic_run - 1].get("sysmon_events", [])
        if event_ids:
            ev = [e for e in ev if e["id"] in event_ids]
        if contains:
            ev = [e for e in ev if contains.lower() in json.dumps(e).lower()]
        return {"count": len(ev), "events": ev[:80]}

    def _finish(self, **report) -> dict:
        self.final = report
        return {"ok": True}

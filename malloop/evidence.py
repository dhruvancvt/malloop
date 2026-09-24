"""Per-run evidence store: every action and result is written to disk so runs are auditable and replayable."""
import json
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Run:
    run_dir: Path
    sample: Path
    sha256: str
    actions: list = field(default_factory=list)
    dynamic_seconds_used: int = 0

    @classmethod
    def create(cls, runs_dir: Path, sample: Path, sha256: str) -> "Run":
        run_dir = runs_dir / f"{time.strftime('%Y%m%d-%H%M%S')}-{sha256[:12]}"
        (run_dir / "artifacts").mkdir(parents=True, exist_ok=True)
        return cls(run_dir=run_dir, sample=sample, sha256=sha256)

    def save(self, name: str, data) -> Path:
        path = self.run_dir / f"{name}.json"
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return path

    def log_action(self, tool: str, params: dict, result: dict) -> None:
        entry = {"n": len(self.actions) + 1, "ts": time.time(), "tool": tool, "params": params, "result": result}
        self.actions.append(entry)
        with (self.run_dir / "trace.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

"""Sandbox backend interface. A backend controls the VM lifecycle; the guest agent does the in-VM work."""
import time
from abc import ABC, abstractmethod
from pathlib import Path

import requests

from .. import config


class Sandbox(ABC):
    @property
    def available(self) -> bool:
        """Whether this backend can actually detonate. When False, dynamic tools are hidden from the agent."""
        return True

    @abstractmethod
    def restore(self) -> None:
        """Revert the VM to the clean snapshot and power it on."""

    @abstractmethod
    def poweroff(self) -> None:
        """Hard power-off. Always called after a detonation, even on errors."""

    # --- guest agent protocol (shared by all backends) ---

    def _guest(self, method: str, path: str, **kw):
        headers = {"X-Malloop-Token": config.GUEST_TOKEN}
        return requests.request(method, config.GUEST_URL + path, headers=headers, timeout=kw.pop("timeout", 30), **kw)

    def wait_for_guest(self, timeout: int = 180) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if self._guest("GET", "/health", timeout=5).ok:
                    return
            except requests.RequestException:
                pass
            time.sleep(3)
        raise TimeoutError("guest agent did not come up")

    def detonate(self, sample: Path, duration: int, args: list[str], network: str, out_dir: Path,
                 dump: bool = False) -> dict:
        """Restore -> upload -> run -> collect -> power off. Returns the guest's telemetry report."""
        self.restore()
        try:
            self.wait_for_guest()
            with sample.open("rb") as f:
                self._guest("POST", "/sample", files={"file": (sample.name, f)}).raise_for_status()
            resp = self._guest("POST", "/run", json={"duration": duration, "args": args, "network": network, "dump": dump},
                               timeout=duration + 120)
            resp.raise_for_status()
            report = resp.json()
            for name in report.get("artifacts", []):
                blob = self._guest("GET", f"/artifact/{name}", timeout=120)
                if blob.ok:
                    (out_dir / Path(name).name).write_bytes(blob.content)
            return report
        finally:
            self.poweroff()


class NoSandbox(Sandbox):
    """Used when no VM is configured: dynamic actions return a clear refusal instead of running anything."""

    @property
    def available(self) -> bool:
        return False

    def restore(self) -> None:
        raise RuntimeError("no sandbox configured (set MALLOOP_SANDBOX)")

    def poweroff(self) -> None:
        pass

    def detonate(self, *a, **kw) -> dict:
        return {"skipped": "no sandbox backend configured; dynamic analysis unavailable"}


def get_sandbox() -> Sandbox:
    if config.SANDBOX_BACKEND == "virtualbox":
        from .virtualbox import VirtualBoxSandbox
        return VirtualBoxSandbox()
    if config.SANDBOX_BACKEND == "hyperv":
        from .hyperv import HyperVSandbox
        return HyperVSandbox()
    return NoSandbox()

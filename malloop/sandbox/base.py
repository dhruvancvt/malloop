"""Sandbox backend interface. A backend controls the VM lifecycle; the guest agent does the in-VM work."""
import contextlib
import time
from abc import ABC, abstractmethod
from pathlib import Path
from urllib.parse import urlsplit

import requests

from .. import config
from ..fakedns import FakeDNS
from ..pcap import summarize as summarize_pcap


def _guest_endpoint() -> tuple[str, int] | None:
    parts = urlsplit(config.GUEST_URL)
    return (parts.hostname, parts.port) if parts.hostname and parts.port else None


class Sandbox(ABC):
    @property
    def available(self) -> bool:
        """Whether this backend can actually detonate. When False, dynamic tools are hidden from the agent."""
        return True

    @abstractmethod
    def restore(self, capture: Path | None = None) -> None:
        """Revert the VM to the clean snapshot and power it on. If `capture` is given and the backend can,
        record the guest's network traffic to that pcap file until power-off."""

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
        """Restore -> upload -> run -> collect -> power off. Returns the guest's telemetry report, plus a
        summary of the captured traffic and, for `simulated` runs, of what the fake DNS was asked."""
        # Kept beside out_dir, not in it: artifact names come from the guest, so a sample could otherwise
        # drop a file with the same name and have it overwrite the host's own capture.
        pcap_path = out_dir.with_suffix(".pcap")
        dns = FakeDNS(config.FAKEDNS_BIND, config.FAKEDNS_PORT) if network == "simulated" else None
        self.restore(capture=pcap_path)
        try:
            self.wait_for_guest()
            with sample.open("rb") as f:
                self._guest("POST", "/sample", files={"file": (sample.name, f)}).raise_for_status()
            with dns or contextlib.nullcontext():
                resp = self._guest("POST", "/run", json={"duration": duration, "args": args, "network": network,
                                                         "dump": dump}, timeout=duration + 120)
            resp.raise_for_status()
            report = resp.json()
            for name in report.get("artifacts", []):
                blob = self._guest("GET", f"/artifact/{name}", timeout=120)
                if blob.ok:
                    (out_dir / Path(name).name).write_bytes(blob.content)
        finally:
            self.poweroff()
        if pcap_path.exists():
            report["pcap"] = summarize_pcap(pcap_path, _guest_endpoint(), config.PCAP_MAX_BYTES,
                                            config.PCAP_MAX_PACKETS)
        if dns is not None:
            report["fake_dns"] = dns.summary()
        return report


class NoSandbox(Sandbox):
    """Used when no VM is configured: dynamic actions return a clear refusal instead of running anything."""

    @property
    def available(self) -> bool:
        return False

    def restore(self, capture: Path | None = None) -> None:
        raise RuntimeError("no sandbox configured (set MALLOOP_SANDBOX)")

    def poweroff(self) -> None:
        pass


def get_sandbox() -> Sandbox:
    if config.SANDBOX_BACKEND == "virtualbox":
        from .virtualbox import VirtualBoxSandbox
        return VirtualBoxSandbox()
    if config.SANDBOX_BACKEND == "hyperv":
        from .hyperv import HyperVSandbox
        return HyperVSandbox()
    return NoSandbox()

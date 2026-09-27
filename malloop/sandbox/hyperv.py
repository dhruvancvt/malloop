"""Hyper-V backend. Requires Windows Pro/Enterprise and an elevated shell (or Hyper-V Administrators membership).

No traffic capture: Hyper-V has no per-VM pcap equivalent to VirtualBox's NIC trace, so `capture` is ignored."""
import functools
import subprocess
from pathlib import Path

from .. import config
from .base import Sandbox


class HyperVSandbox(Sandbox):
    def _ps(self, script: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(["powershell", "-NoProfile", "-Command", script],
                              capture_output=True, text=True, check=check)

    @functools.cached_property
    def available(self) -> bool:
        """Hyper-V is present and the configured VM has the configured snapshot."""
        proc = self._ps(f"Get-VMSnapshot -VMName '{config.VM_NAME}' -Name '{config.VM_SNAPSHOT}' "
                        "-ErrorAction Stop | Out-Null", check=False)
        return proc.returncode == 0
    def restore(self, capture: Path | None = None) -> None:
        self.poweroff()
        self._ps(f"Restore-VMSnapshot -VMName '{config.VM_NAME}' -Name '{config.VM_SNAPSHOT}' -Confirm:$false")
        self._ps(f"Start-VM -Name '{config.VM_NAME}'")

    def poweroff(self) -> None:
        self._ps(f"Stop-VM -Name '{config.VM_NAME}' -TurnOff -Force -ErrorAction SilentlyContinue", check=False)

"""Hyper-V backend. Requires Windows Pro/Enterprise and an elevated shell (or Hyper-V Administrators membership)."""
import subprocess

from .. import config
from .base import Sandbox


class HyperVSandbox(Sandbox):
    def _ps(self, script: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(["powershell", "-NoProfile", "-Command", script],
                              capture_output=True, text=True, check=check)

    def restore(self) -> None:
        self.poweroff()
        self._ps(f"Restore-VMSnapshot -VMName '{config.VM_NAME}' -Name '{config.VM_SNAPSHOT}' -Confirm:$false")
        self._ps(f"Start-VM -Name '{config.VM_NAME}'")

    def poweroff(self) -> None:
        self._ps(f"Stop-VM -Name '{config.VM_NAME}' -TurnOff -Force -ErrorAction SilentlyContinue", check=False)

import functools
import subprocess
import time
from pathlib import Path

from .. import config
from .base import Sandbox


class VirtualBoxSandbox(Sandbox):
    def _vbox(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run([config.VBOXMANAGE, *args], capture_output=True, text=True, check=check)

    @functools.cached_property
    def available(self) -> bool:
        """VBoxManage exists and the configured VM has the configured snapshot."""
        if not Path(config.VBOXMANAGE).exists():
            return False
        proc = self._vbox("snapshot", config.VM_NAME, "list", "--machinereadable", check=False)
        return proc.returncode == 0 and f'="{config.VM_SNAPSHOT}"' in proc.stdout

    def restore(self, capture: Path | None = None) -> None:
        self.poweroff()
        self._vbox("snapshot", config.VM_NAME, "restore", config.VM_SNAPSHOT)
        if capture is not None:
            # Enabled while the restored VM is still in its saved state. Toggling the trace on a running VM
            # re-plumbs the NIC, which drops the guest's link for a few seconds and breaks agent requests.
            self._vbox("modifyvm", config.VM_NAME, "--nic-trace1", "on", "--nic-trace-file1", str(capture.resolve()))
        self._vbox("startvm", config.VM_NAME, "--type", "headless")

    def poweroff(self) -> None:
        state = self._vbox("showvminfo", config.VM_NAME, "--machinereadable", check=False).stdout
        if 'VMState="running"' in state or 'VMState="paused"' in state:
            self._vbox("controlvm", config.VM_NAME, "poweroff", check=False)
            time.sleep(2)
        # So a later manual boot can't write over the finished run's capture.
        self._vbox("modifyvm", config.VM_NAME, "--nic-trace1", "off", check=False)

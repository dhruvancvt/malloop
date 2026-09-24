import subprocess
import time

from .. import config
from .base import Sandbox


class VirtualBoxSandbox(Sandbox):
    def _vbox(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run([config.VBOXMANAGE, *args], capture_output=True, text=True, check=check)

    def restore(self) -> None:
        self.poweroff()
        self._vbox("snapshot", config.VM_NAME, "restore", config.VM_SNAPSHOT)
        self._vbox("startvm", config.VM_NAME, "--type", "headless")

    def poweroff(self) -> None:
        state = self._vbox("showvminfo", config.VM_NAME, "--machinereadable", check=False).stdout
        if 'VMState="running"' in state or 'VMState="paused"' in state:
            self._vbox("controlvm", config.VM_NAME, "poweroff", check=False)
            time.sleep(2)

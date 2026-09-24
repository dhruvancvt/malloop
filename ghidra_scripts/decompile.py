# Ghidra headless post-script: decompile one function by address or name.
# Args: <out_json> <addr_or_name>
# @runtime Jython
import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

out_path, target = getScriptArgs()[0], getScriptArgs()[1]
fm = currentProgram.getFunctionManager()

func = None
try:
    func = fm.getFunctionContaining(toAddr(target))
except Exception:
    pass
if func is None:
    for f in fm.getFunctions(True):
        if f.getName() == target:
            func = f
            break

if func is None:
    result = {"error": "function not found: " + target}
else:
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    res = decomp.decompileFunction(func, 120, ConsoleTaskMonitor())
    result = {
        "name": func.getName(),
        "addr": str(func.getEntryPoint()),
        "c": res.getDecompiledFunction().getC() if res.decompileCompleted() else res.getErrorMessage(),
    }

with open(out_path, "w") as fh:
    fh.write(json.dumps(result))

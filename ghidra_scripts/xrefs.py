# Ghidra headless post-script: callers/callees of a function, or references to a string/symbol.
# Args: <out_json> <addr_or_name_or_string>
# @runtime Jython
import json

from ghidra.util.task import ConsoleTaskMonitor

out_path, target = getScriptArgs()[0], getScriptArgs()[1]
prog = currentProgram
fm = prog.getFunctionManager()
refman = prog.getReferenceManager()
monitor = ConsoleTaskMonitor()


def fn_at(addr):
    f = fm.getFunctionContaining(addr)
    return {"name": f.getName(), "addr": str(f.getEntryPoint())} if f else {"addr": str(addr)}


result = {"target": target}
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

if func is not None:
    result["callers"] = [{"name": f.getName(), "addr": str(f.getEntryPoint())} for f in func.getCallingFunctions(monitor)]
    result["callees"] = [{"name": f.getName(), "addr": str(f.getEntryPoint())} for f in func.getCalledFunctions(monitor)]
else:
    # Treat target as a string: find defined strings containing it, then who references them
    hits = []
    for data in prog.getListing().getDefinedData(True):
        v = data.getValue()
        if isinstance(v, (str, unicode)) and target in v:
            refs = [fn_at(r.getFromAddress()) for r in refman.getReferencesTo(data.getAddress())]
            hits.append({"string": v[:200], "addr": str(data.getAddress()), "referenced_from": refs})
            if len(hits) >= 25:
                break
    result["string_refs"] = hits

with open(out_path, "w") as fh:
    fh.write(json.dumps(result))

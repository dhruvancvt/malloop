# Ghidra headless post-script: exports a compact overview of the program as JSON.
# Args: <out_json>
# @runtime Jython
import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

SUSPICIOUS_APIS = set("""
VirtualAlloc VirtualAllocEx VirtualProtect WriteProcessMemory CreateRemoteThread NtCreateThreadEx
QueueUserAPC SetThreadContext ResumeThread NtUnmapViewOfSection LoadLibraryA LoadLibraryW GetProcAddress
CryptEncrypt CryptDecrypt BCryptEncrypt InternetOpenA InternetOpenW InternetConnectA HttpSendRequestA
URLDownloadToFileA URLDownloadToFileW WinHttpOpen WSAStartup connect send recv
RegSetValueExA RegSetValueExW CreateServiceA CreateServiceW ShellExecuteA ShellExecuteW WinExec CreateProcessA CreateProcessW
IsDebuggerPresent CheckRemoteDebuggerPresent NtQueryInformationProcess GetTickCount
SetWindowsHookExA SetWindowsHookExW GetAsyncKeyState OpenProcess AdjustTokenPrivileges
""".split())

out_path = getScriptArgs()[0]
prog = currentProgram
fm = prog.getFunctionManager()
monitor = ConsoleTaskMonitor()

imports = []
for sym in prog.getSymbolTable().getExternalSymbols():
    imports.append(sym.getName())

functions = []
for f in fm.getFunctions(True):
    called = [c.getName() for c in f.getCalledFunctions(monitor)]
    hits = [c for c in called if c in SUSPICIOUS_APIS]
    functions.append({
        "name": f.getName(),
        "addr": str(f.getEntryPoint()),
        "size": f.getBody().getNumAddresses(),
        "calls_suspicious": hits,
        "is_thunk": f.isThunk(),
    })

ranked = sorted([f for f in functions if not f["is_thunk"]],
                key=lambda f: (len(f["calls_suspicious"]), f["size"]), reverse=True)

decomp = DecompInterface()
decomp.openProgram(prog)
top = []
for f in ranked[:5]:
    func = fm.getFunctionAt(toAddr(f["addr"]))
    res = decomp.decompileFunction(func, 60, monitor)
    code = res.getDecompiledFunction().getC() if res.decompileCompleted() else ""
    top.append({"addr": f["addr"], "name": f["name"], "c": code[:4000]})

result = {
    "language": str(prog.getLanguageID()),
    "compiler": str(prog.getCompilerSpec().getCompilerSpecID()),
    "function_count": len(functions),
    "imports": sorted(set(imports))[:500],
    "suspicious_functions": [f for f in ranked if f["calls_suspicious"]][:40],
    "top_decompiled": top,
}
with open(out_path, "w") as fh:
    fh.write(json.dumps(result))

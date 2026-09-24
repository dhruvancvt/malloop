"""Builds the initial evidence brief for the agent.

Raw triage + static output can be hundreds of KB (full import tables, every string, decompiled code).
Blindly truncating the JSON drops whole sections, usually the most useful ones at the end. Instead,
each section is compacted with its own budget, in priority order, and only the least important
material (the raw string sample, then decompiled bodies) shrinks to fit the overall limit.
"""
import json

# Imports worth surfacing individually; everything else is summarized as per-DLL counts.
SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory",
    "ReadProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "QueueUserAPC",
    "SetThreadContext", "GetThreadContext", "ResumeThread", "SuspendThread", "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection", "OpenProcess", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll", "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "CryptAcquireContextW",
    "BCryptEncrypt", "BCryptDecrypt", "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
    "InternetConnectA", "InternetConnectW", "HttpSendRequestA", "HttpSendRequestW", "URLDownloadToFileA",
    "URLDownloadToFileW", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "WSAStartup", "connect",
    "send", "recv", "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW", "CreateServiceA",
    "CreateServiceW", "StartServiceA", "StartServiceW", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExW",
    "WinExec", "CreateProcessA", "CreateProcessW", "CreateProcessAsUserW", "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA", "SetWindowsHookExA",
    "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState", "AdjustTokenPrivileges", "LookupPrivilegeValueA",
    "LookupPrivilegeValueW", "OpenProcessToken", "DeleteFileA", "DeleteFileW", "MoveFileExA", "MoveFileExW",
    "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "Process32FirstW", "Process32NextW",
    "CryptStringToBinaryA", "CryptStringToBinaryW", "FindResourceA", "FindResourceW", "LoadResource",
    "SizeofResource", "NetUserAdd", "WNetAddConnection2A", "WNetAddConnection2W", "DnsQuery_A", "DnsQuery_W",
}


def _truncate(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n] + f" ...[+{len(text) - n} chars]"


def _compact_triage(t: dict) -> dict:
    out = {k: v for k, v in t.items() if k not in ("pe", "iocs")}
    out["iocs"] = {k: v[:25] for k, v in (t.get("iocs") or {}).items() if v}
    pe = t.get("pe")
    if isinstance(pe, dict) and "imports" in pe:
        imports = pe.get("imports") or {}
        out["pe"] = {k: v for k, v in pe.items() if k != "imports"}
        out["pe"]["import_counts"] = {dll: len(fns) for dll, fns in imports.items()}
        out["pe"]["suspicious_imports"] = sorted({f for fns in imports.values() for f in fns if f in SUSPICIOUS_APIS})
    elif pe is not None:
        out["pe"] = pe
    return out


def _compact_static(s: dict, decompiled_chars: int) -> dict:
    out = {}
    capa = s.get("capa") or {}
    if "capabilities" in capa:
        out["capa"] = [
            c["capability"] + (f" [{', '.join(a for a in c.get('attack') or [] if a)}]" if c.get("attack") else "")
            for c in capa["capabilities"][:150]
        ]
    else:
        out["capa"] = capa
    floss = s.get("floss") or {}
    out["floss"] = {k: [_truncate(x, 200) for x in v[:100]] if isinstance(v, list) else v for k, v in floss.items()}
    g = s.get("ghidra") or {}
    if "function_count" in g:
        out["ghidra"] = {
            "language": g.get("language"),
            "compiler": g.get("compiler"),
            "function_count": g.get("function_count"),
            "suspicious_functions": g.get("suspicious_functions", [])[:40],
            "top_decompiled": [{**f, "c": _truncate(f.get("c", ""), decompiled_chars)}
                               for f in g.get("top_decompiled", [])[:5]],
        }
    else:
        out["ghidra"] = g
    return out


def build_brief(evidence: dict, limit: int) -> dict:
    """Compact `evidence` (triage, static, container_tree, sample_strings_head, ...) to fit `limit` chars of JSON."""
    strings = [_truncate(s, 160) for s in evidence.get("sample_strings_head", [])]
    decompiled_chars = 3000
    tree = evidence.get("container_tree")

    def assemble() -> dict:
        brief = {k: v for k, v in evidence.items()
                 if k not in ("triage", "static", "container_tree", "sample_strings_head")}
        if tree:
            brief["container_tree"] = tree[:200]
            if len(tree) > 200:
                brief["container_tree_omitted"] = len(tree) - 200
        if "triage" in evidence:
            brief["triage"] = _compact_triage(evidence["triage"])
        if "static" in evidence:
            brief["static"] = _compact_static(evidence["static"], decompiled_chars)
        brief["sample_strings_head"] = strings
        return brief

    brief = assemble()
    # Shrink the least valuable material first: raw strings, then decompiled bodies.
    while len(json.dumps(brief, default=str)) > limit:
        if len(strings) > 20:
            strings = strings[: len(strings) // 2]
        elif decompiled_chars > 500:
            decompiled_chars //= 2
        elif strings:
            strings = []
        else:
            break
        brief = assemble()
    return brief

# malloop

Deterministic + agentic malware analysis loop.

```
sample ─▶ recursive unpack (zip, dmg, 7z/rar with 7-Zip)
       ─▶ triage (hashes, type, entropy, IOCs, YARA, PE)      ┐ deterministic,
       ─▶ static (Ghidra headless, capa, FLOSS)               ┘ always runs
       ─▶ Claude agent ◀──▶ fixed tool catalog ◀──▶ sandbox VM (snapshot per run)
       ─▶ report.md + full action trace
```

The agent never gets a shell. It can only call the actions in `malloop/tools.py`
(decompile, xrefs, string search, list/switch extracted files, detonate, query telemetry, finish). Each call is validated,
budgeted and logged to `runs/<id>/trace.jsonl`.

## Layout

| Path | Role |
|---|---|
| `malloop/unpack.py` | Stage 0: bounded recursive unpacking of zip/dmg (+ 7-Zip formats) |
| `malloop/triage.py` | Stage 1: pure-Python triage, never executes the sample |
| `malloop/static_analysis.py` | Stage 2: capa / FLOSS / Ghidra headless wrappers |
| `ghidra_scripts/` | Ghidra post-scripts: overview, decompile, xrefs |
| `malloop/tools.py` | Agent tool catalog + deterministic executor |
| `malloop/agent.py` | Claude tool-use loop with iteration and dynamic-time budgets |
| `malloop/sandbox/` | VM lifecycle backends (VirtualBox, Hyper-V) |
| `malloop/guest/guest_agent.py` | Runs inside the analysis VM: receives the sample, detonates it, returns Sysmon telemetry |

## Quick start (static only)

```bash
python -m venv .venv && .venv/Scripts/activate
pip install -r requirements.txt
python -m malloop analyze path/to/file --static-only
```

Add capa, FLOSS and Ghidra (`set GHIDRA_HEADLESS=C:\ghidra\support\analyzeHeadless.bat`) to get the full static stage.
Missing tools are skipped, not fatal.

## Full loop

```bash
set ANTHROPIC_API_KEY=...
python -m malloop analyze path/to/sample.exe
```

## Recursive unpacking

Containers are unpacked recursively before triage. Every extracted file becomes a node in a tree
(`runs/<id>/unpack.json`). Each node is triaged, and the most analyzable, most suspicious file is picked as
the primary target: PE first, then Mach-O and ELF, then scripts and documents. The agent sees the whole tree
and can `switch_target` to any other node.

| Format | Handler |
|---|---|
| ZIP | `zipfile` / `pyzipper` (AES). Tries `infected`, `malware`, `virus` as passwords. |
| DMG | 7-Zip if installed (full HFS+/APFS with filenames). Otherwise a built-in UDIF decoder (zlib, bzip2, ADC, LZMA, raw) rebuilds the disk image and carves Mach-O binaries (thin and fat) from it. |
| 7z, RAR, HFS, APFS | 7-Zip only |

Guards: max depth, file count, total bytes, per-file size, and compression ratio (zip bombs). Output bytes
are counted as they're written, not taken from headers. Path traversal and drive-letter names are stripped,
symlinks are never extracted, and identical files are analyzed once (`duplicate_of`).
All limits are `MALLOOP_UNPACK_*` env vars.

Without 7-Zip, DMGs lose filenames and non-Mach-O files, and LZFSE-compressed DMGs can't be decoded
(this is reported in the node notes). Installing 7-Zip is recommended:

```bash
winget install 7zip.7zip
```

## Tests

```bash
pip install pytest
python -m pytest tests
```

The fixtures (encrypted and nested zips, a zip bomb, zip-slip, a synthetic UDIF DMG with thin and fat Mach-O) are generated in code.
No real malware is included.

## Building the sandbox VM

**Windows 10 Home has no Hyper-V**, so use VirtualBox (`MALLOOP_SANDBOX=virtualbox`, the default).
Use `hyperv` only on Pro/Enterprise.

1. Create a Windows 10/11 VM named `malloop-win10`.
2. **Networking:** one adapter, **Host-only** (`192.168.56.0/24`), with the guest at `192.168.56.10`.
   No NAT and no bridged adapter. The VM must not be able to reach your LAN or the internet.
3. In the guest:
   - Disable Defender real-time protection and auto-updates (otherwise it deletes samples).
   - Install Python 3.11+, [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) with a verbose config,
     and optionally Procmon, ProcDump and FakeNet-NG (all on PATH).
   - Copy `malloop/guest/guest_agent.py` to `C:\malloop\` and add a startup task:
     `python C:\malloop\guest_agent.py --token <secret>`
   - Allow inbound TCP 8765 on the host-only interface in the guest firewall.
   - Disable shared folders, clipboard and drag-and-drop.
4. Shut down cleanly, then take a snapshot named `clean`.
5. On the host, set `MALLOOP_GUEST_TOKEN=<secret>`.

Every `run_dynamic` call restores `clean`, detonates, collects data and hard powers off the VM.

## Configuration (env vars)

`MALLOOP_MODEL`, `MALLOOP_MAX_ITERATIONS`, `MALLOOP_MAX_DYNAMIC_SECONDS`, `MALLOOP_SANDBOX`,
`MALLOOP_VM_NAME`, `MALLOOP_VM_SNAPSHOT`, `MALLOOP_GUEST_URL`, `MALLOOP_GUEST_TOKEN`,
`GHIDRA_HEADLESS`, `CAPA_BIN`, `FLOSS_BIN`, `SEVEN_ZIP`, `VBOXMANAGE`, `MALLOOP_UNPACK_*`. See `malloop/config.py`.

## Safety notes

- Keep live samples in `samples/` (git-ignored), ideally zipped with the password `infected`, and don't open them on the host.
- Sample-derived content goes to the model wrapped in `<untrusted>` tags. The agent is told to treat it as data only.
- Real internet during detonation is not offered to the agent. Add it only as a manual, human-gated option.

## Roadmap

- More unpackers: MSI, PKG (xar), installers (NSIS/Inno), UPX
- macOS and Linux guests (ESF / eBPF telemetry)
- PCAP capture on the host-only adapter
- Config extractors (e.g. CAPE's) exposed as an `extract_config` tool
- Replay mode: re-run a `trace.jsonl` without the model

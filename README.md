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
| `malloop/static_worker.py` | Host client for the REMnux static worker (capa/FLOSS over host-only net) |
| `malloop/worker/worker_agent.py` | Runs inside the REMnux VM: receives a file, runs capa/FLOSS, returns JSON |
| `malloop/tools.py` | Agent tool catalog + deterministic executor |
| `malloop/agent.py` | Claude tool-use loop with iteration and dynamic-time budgets |
| `malloop/sandbox/` | VM lifecycle backends (VirtualBox, Hyper-V) |
| `malloop/guest/guest_agent.py` | Runs inside the analysis VM: receives the sample, detonates it, returns Sysmon telemetry |
| `malloop/evidence.py` | Per-run evidence store: `trace.jsonl`, `status.json`, saved stage reports |
| `malloop/viewer.py` | Read-only web UI for `runs/<id>/`, with live progress on runs still in flight |

## Quick start (static only)

```bash
python -m venv .venv && .venv/Scripts/activate
pip install -r requirements.txt
python -m malloop analyze path/to/file --static-only
```

Add capa, FLOSS and Ghidra to get the full static stage — see [Installing Ghidra](#installing-ghidra) below,
Ghidra needs more than just the env var. Missing tools are skipped, not fatal. Instead of installing capa and
FLOSS on the host, you can run them in an isolated Linux VM — see [Static worker](#static-worker-capa--floss-in-remnux).

## Full loop

```bash
set ANTHROPIC_API_KEY=...
python -m malloop analyze path/to/sample.exe
```

## Web viewer

A read-only local web UI for `runs/<id>/` reports, including live progress on a run still in flight:

```bash
python -m malloop viewer
```

Serves on `http://127.0.0.1:8787` by default (`MALLOOP_VIEWER_HOST`/`MALLOOP_VIEWER_PORT`). The index
lists past runs; a run's page shows the verdict, evidence, triage, static analysis and the full agent
trace, and — while a run is still in progress — polls for new trace entries and the current
stage/iteration until it finishes. Everything rendered is sample-derived and untrusted, so it's all
HTML-escaped the same way the `<untrusted>` wrapper protects the model; don't bind it beyond
loopback without adding auth in front of it.

## Network capture

On VirtualBox, every detonation records the guest NIC to `runs/<id>/artifacts/dynamicN.pcap` (VirtualBox's
NIC trace, enabled while the restored VM is still in its saved state). After power-off the host parses it
with a bounded stdlib reader (`malloop/pcap.py`) into a `pcap` summary for the agent: DNS names asked,
which resolvers were asked, and TCP/UDP connection attempts. The guest agent's own traffic is filtered out.
The capture is independent of Sysmon, which misses a lot of network activity.

With `network="simulated"`, the host also runs a fake DNS (`malloop/fakedns.py`) on `192.168.56.1:53`
for the length of the run. It answers every A query with a per-domain sinkhole address in `192.0.2.0/24`
(TEST-NET-1), so the sample goes on to connect and its C2 ports show up in the capture. Hyper-V has no
equivalent trace, so it doesn't capture.

The guest's default gateway is the host, so **isolation depends on the host not forwarding**. Never enable
IP routing or Internet Connection Sharing on the host-only adapter. Check with
`Get-NetIPInterface -AddressFamily IPv4 | Where-Object Forwarding -eq Enabled`, which should print nothing.

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

## Installing Ghidra

Ghidra needs two things that a bare `GHIDRA_HEADLESS` env var doesn't fix by itself, and getting
them wrong doesn't raise a clear error — it either silently records `{"skipped": ...}` for the
`ghidra` section of every static report, or (if `GHIDRA_HEADLESS` points at a real
`analyzeHeadless.bat` but the second thing below is missing) fails per-file with a real but
easy-to-miss error:

1. **A JDK 21 on `JAVA_HOME` or `PATH`.** Ghidra 11+ requires exactly this; older/newer JDKs won't
   do. [Temurin](https://adoptium.net/temurin/releases/?version=21) is a good source.
2. **The Jython extension, installed separately.** As of Ghidra 12.x, Jython was split out of the
   base distribution — `ghidra_scripts/` in this repo are Jython 2.7 (see `AGENTS.md`), so without
   this step every `analyzeHeadless` call fails with:
   `JythonStubException: ... you must install the Jython Ghidra Extension`.
   The extension ships *inside* the Ghidra download itself, so no separate download is needed:
   extract `<ghidra_install_dir>/Extensions/Ghidra/ghidra_<version>_Jython.zip` into
   `<ghidra_install_dir>/Ghidra/Extensions/`, so you end up with a
   `<ghidra_install_dir>/Ghidra/Extensions/Jython/` folder.

Steps:

```bash
# 1. JDK 21 (or use your OS's package manager)
# download + extract a Temurin 21 build, then:
setx JAVA_HOME "C:\tools\jdk-21.x.x.x+x"

# 2. Ghidra itself — verify the SHA-256 on the release page before extracting
# https://github.com/NationalSecurityAgency/ghidra/releases
# extract to e.g. C:\tools\ghidra_<version>_PUBLIC

# 3. the Jython extension bundled inside the Ghidra download (see above)
# extract Extensions/Ghidra/ghidra_<version>_Jython.zip into Ghidra/Extensions/

setx GHIDRA_HEADLESS "C:\tools\ghidra_<version>_PUBLIC\support\analyzeHeadless.bat"
```

Verify with a static-only run against a benign binary:

```bash
python -m malloop analyze C:\Windows\System32\notepad.exe --static-only
```

The printed `ghidra` section should have `language`/`compiler`/`function_count`/`imports`/
`suspicious_functions`/`top_decompiled` keys — not `{"skipped": ...}` and not a Jython error.

## Tests

```bash
pip install pytest
python -m pytest tests
```

The fixtures (encrypted and nested zips, a zip bomb, zip-slip, a synthetic UDIF DMG with thin and fat Mach-O) are generated in code.
No real malware is included.

The whole loop is tested without an API key or a VM:

- `tests/test_agent_loop.py` drives the real CLI (unpack, triage, evidence brief, tool executor, budgets, report) with a
  scripted stand-in for the Claude client and a fake sandbox. It also checks that sample text never appears outside `<untrusted>` tags.
- `tests/test_guest_protocol.py` runs the real guest agent HTTP server on localhost against the real `Sandbox.detonate()`,
  covering byte-exact upload, artifact collection, power-off on failure, token auth and path traversal. Only the sample execution is stubbed.

The agent's first message is a structured brief (`malloop/brief.py`). Each section has its own budget, so large
Ghidra and capa output is compacted instead of cut off (`MALLOOP_MAX_INITIAL_EVIDENCE_CHARS`, default 60000).

## Building the sandbox VM

**Windows 10 Home has no Hyper-V**, so use VirtualBox (`MALLOOP_SANDBOX=virtualbox`, the default).
Use `hyperv` only on Pro/Enterprise.

You can click through a normal Windows install, or drive it unattended with an `autounattend.xml`.
The unattended route is what actually built and proved out the current `malloop-win10` VM, and it
surfaced most of the gotchas below, so it's documented in full.

### Getting a Windows image

- **Enterprise evaluation editions require signing into a Microsoft account during setup.** That
  rules them out for an unattended, account-less build — skip straight to Server editions.
- **Windows Server evaluation editions** (Standard or Datacenter) use a local Administrator password
  instead, but **must reach the internet to activate within 10 days of install**, which is in direct
  tension with keeping the guest permanently offline. The fix used here: do every internet-dependent
  step (installing Python, Sysmon, the guest agent) *while the VM still has NAT*, and only switch to
  the isolated host-only network as the very last step, after everything the guest needs is already
  on disk — the same order the REMnux worker VM was hardened in.
- Pick the **Desktop Experience** image index, not Server Core — `guest_agent.py`'s screenshot
  capture needs an interactive desktop session to exist.

### Unattended install

1. Create the VM with **EFI firmware** and **NAT** networking for now (switched to host-only in step 4):
   ```bash
   VBoxManage createvm --name malloop-win10 --ostype Windows2025_64 --register
   VBoxManage modifyvm malloop-win10 --memory 4096 --cpus 2 --firmware efi --nic1 nat
   ```
   **UEFI needs the standard multi-partition layout (EFI System Partition + MSR + primary), not a
   single NTFS partition spanning the disk.** An `autounattend.xml` `DiskConfiguration` that only
   defines one partition fails partway through setup with *"There is an error selecting this
   partition for install. Please select a different partition or refresh selections."* — even though
   the partition it created matches the answer file exactly. Point the disk config at unallocated
   space and let Setup create the standard four-partition scheme itself, rather than defining a
   single partition by hand.
2. Attach the Windows ISO, plus a second small ISO containing `autounattend.xml`,
   `malloop/guest/guest_agent.py`, and a `bootstrap.ps1` first-logon script. Windows Setup scans the
   root of *every* attached optical drive for `autounattend.xml`, not just floppy/USB media, so a
   second virtual DVD works fine. Building that small ISO with PowerShell's built-in `IMAPI2FS` COM
   object is unreliable — neither `IStream.Read` nor `ADODB.Stream.LoadFromStream` marshal correctly
   called this way from PowerShell. [`pycdlib`](https://pypi.org/project/pycdlib/) (`pip install
   pycdlib`, pure Python, no native deps) builds the same ISO in a few lines and just works.
3. `bootstrap.ps1`, invoked via `autounattend.xml`'s `FirstLogonCommands`, does all the
   internet-dependent setup while NAT is still attached: install Python 3.11+, install
   [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) with a verbose config (e.g.
   SwiftOnSecurity's), copy `guest_agent.py` to `C:\malloop\`, register it as a SYSTEM-level scheduled
   task triggered `AtStartup`, and open the firewall for inbound TCP 8765. **As its last action**, it
   also sets the guest's own static IP (`192.168.56.10/24`, DHCP disabled) — this has to happen here,
   before the network is switched, because **the host-only adapter has DHCP disabled**, and without
   Guest Additions already installed there is no way to configure a static IP from the host side
   afterward. Confirm it worked (`bootstrap_done.txt` exists, `Get-NetIPAddress` shows the static
   address in `Preferred` state) before moving on.

   It also needs these guest settings, which the first build missed:
   ```powershell
   # VirtualBox passes the host laptop's battery into the guest. Task Scheduler's defaults then refuse to
   # start the agent (it sits "Queued") or stop it, and every restore fails its health check on battery.
   Set-ScheduledTask MalloopGuestAgent -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
       -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -RestartCount 3 `
       -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable)
   foreach ($t in "monitor", "standby", "hibernate") { powercfg -change "-$t-timeout-ac" 0; powercfg -change "-$t-timeout-dc" 0 }
   # Gateway and DNS -> the host, so off-subnet traffic reaches the wire (and the capture and fake DNS).
   $if = (Get-NetIPAddress -IPAddress 192.168.56.10).InterfaceIndex
   New-NetRoute -InterfaceIndex $if -DestinationPrefix 0.0.0.0/0 -NextHop 192.168.56.1
   Set-DnsClientServerAddress -InterfaceIndex $if -ServerAddresses 192.168.56.1
   # Quiet the idle guest: connectivity probes and NTP were ~55 DNS queries per 100s of capture noise.
   New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator -Force |
       Set-ItemProperty -Name NoActiveProbe -Type DWord -Value 1
   Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet EnableActiveProbing 0
   Set-Service W32Time -StartupType Disabled   # Guest Additions keep the clock in sync
   # Defender quarantines samples before they run. On Server it's a removable feature; reboot afterwards.
   Uninstall-WindowsFeature Windows-Defender
   ```
4. Shut the guest down cleanly, then from the host switch the network:
   ```bash
   VBoxManage controlvm malloop-win10 poweroff
   VBoxManage modifyvm malloop-win10 --nic1 hostonly --hostonlyadapter1 "VirtualBox Host-Only Ethernet Adapter"
   VBoxManage startvm malloop-win10 --type headless
   ```
   Then confirm the guest agent answers on the isolated network:
   `curl -H "X-Malloop-Token: <secret>" http://192.168.56.10:8765/health`.
5. Install **VirtualBox Guest Additions** (`Devices > Insert Guest Additions CD image`, then run
   `D:\VBoxWindowsAdditions.exe /S` as Administrator inside the guest, then reboot). **Without this,
   mouse clicks into the VM's console window land at the wrong coordinates** — keyboard input reaches
   the guest fine, but absolute-position mouse clicks don't map correctly until Guest Additions
   provides real pointer integration. Do this before you need to click anything by hand.
6. Disable the shared clipboard and drag-and-drop, then snapshot. Restoring a snapshot also restores
   these settings, so they have to be off when `clean` is taken:
   ```bash
   VBoxManage controlvm malloop-win10 clipboard mode disabled
   VBoxManage controlvm malloop-win10 draganddrop disabled
   VBoxManage snapshot malloop-win10 take clean
   ```
   Keep NIC trace off in the snapshot; malloop turns it on per run.
7. On the host, set `MALLOOP_GUEST_TOKEN=<secret>` to match what `bootstrap.ps1` used.

Every `run_dynamic` call restores `clean`, detonates, collects data and hard powers off the VM.

### A dangerous VirtualBox input gotcha

If you ever drive the VM's console window directly instead of over the guest agent's HTTP API:
**VirtualBox's keyboard/mouse capture silently drops** every time you click one of VirtualBox's own
menus (`Devices`, `Machine`, ...), and after every guest reboot. If a system-level key combo like
`Win+R` is sent while capture is inactive, **it goes to your real host desktop, not the guest** — this
is exactly how a stray `Win+R` opened a Run dialog on the host machine mid-build here. Always click
"Capture" on VirtualBox's own re-capture prompt (safe to click — it's host-native chrome, not guest
content) immediately before sending the next round of guest-bound input, and assume every reboot has
reset the capture state.

A smaller side effect of the same root cause: Windows Server's Start-menu shutdown flow shows a
"Shutdown Event Tracker" reason dialog that needs an extra click to confirm before the VM actually
powers off — scripting a clean shutdown from the host (`shutdown /s /t 0` inside the guest, or ACPI)
skips it.

## Static worker: capa + FLOSS in REMnux

capa and FLOSS are the heavy reverse-engineering tools in stage 2. Rather than installing them on your host,
run them inside an isolated Linux VM (e.g. [REMnux](https://remnux.org/), which ships both). The host uploads
each file to a worker over the host-only network; the worker runs the tools and returns JSON. Ghidra and YARA
still run on the host. If no worker is configured, capa/FLOSS run locally (or are skipped if absent) as before.

The worker only parses samples with capa/FLOSS; it never executes them. Still, isolate the VM exactly like the
detonation guest: host-only networking, no shared folders, no internet.

1. In the REMnux VM (host-only network, e.g. guest `192.168.56.20`, host `192.168.56.1`):
   - Confirm capa and FLOSS are on `PATH` (`capa -h`, `floss -h`). They are preinstalled on REMnux.
   - Copy `malloop/worker/worker_agent.py` into the VM (over the host-only network, e.g. `scp`).
   - Start it at boot: `python3 worker_agent.py --token <secret> --host 0.0.0.0 --port 8766`
   - Allow inbound TCP 8766 on the host-only interface.
2. On the host:
   ```bash
   set MALLOOP_STATIC_WORKER_URL=http://192.168.56.20:8766
   set MALLOOP_STATIC_WORKER_TOKEN=<secret>
   ```

The worker is stateless: each request writes the upload to a temp file, runs the tools, and deletes it.

## Configuration (env vars)

`MALLOOP_MODEL`, `MALLOOP_MAX_ITERATIONS`, `MALLOOP_MAX_DYNAMIC_SECONDS`, `MALLOOP_MAX_INITIAL_EVIDENCE_CHARS`,
`MALLOOP_SANDBOX`, `MALLOOP_VM_NAME`, `MALLOOP_VM_SNAPSHOT`, `MALLOOP_GUEST_URL`, `MALLOOP_GUEST_TOKEN`,
`MALLOOP_STATIC_WORKER_URL`, `MALLOOP_STATIC_WORKER_TOKEN`, `MALLOOP_STATIC_WORKER_TIMEOUT`,
`MALLOOP_VIEWER_HOST`, `MALLOOP_VIEWER_PORT`, `MALLOOP_PCAP_MAX_BYTES`, `MALLOOP_PCAP_MAX_PACKETS`,
`MALLOOP_FAKEDNS_BIND`, `MALLOOP_FAKEDNS_PORT`,
`GHIDRA_HEADLESS`, `CAPA_BIN`, `FLOSS_BIN`, `SEVEN_ZIP`, `VBOXMANAGE`, `MALLOOP_UNPACK_*`. See `malloop/config.py`.

## Safety notes

- Keep live samples in `samples/` (git-ignored), ideally zipped with the password `infected`, and don't open them on the host.
- Sample-derived content goes to the model wrapped in `<untrusted>` tags. The agent is told to treat it as data only.
- Real internet during detonation is not offered to the agent. Add it only as a manual, human-gated option.

## Roadmap

- More unpackers: MSI, PKG (xar), installers (NSIS/Inno), UPX
- macOS and Linux guests (ESF / eBPF telemetry)
- Config extractors (e.g. CAPE's) exposed as an `extract_config` tool
- Replay mode: re-run a `trace.jsonl` without the model

## License

[MIT](LICENSE)

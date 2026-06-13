# Memory Forensics

**Image:** `/mnt/windows_ram/windows_ram.raw` (12 GB)  
**Tool:** Volatility 3 Framework v2.28.1  
**Acquisition:** go-winpmem `amd64_1.0-rc2_signed` at 14:10:01 UTC  
**Target:** Windows 10 20H2 Build 19041 (DESKTOP-N46SBV9)

Memory forensics was required to reconstruct what happened during the engagement. Standard detections (Defender, Wazuh, YARA) generated no alerts for the loader execution, SSPI bypass, token manipulation, or credential dump. The only way to confirm these events occurred was from the memory image.

---

## System Information

```bash
vol.py -f windows_ram.raw windows.info
```

| Field | Value |
|---|---|
| Kernel Base | `0xf80729c00000` |
| NtMajorVersion | 10 |
| Build | 19041 (Windows 10 20H2) |
| Architecture | x64 |
| Capture Time | 2026-06-01 14:10:02 UTC |

---

## Process Discovery

```bash
vol.py -f windows_ram.raw windows.pslist | grep -i loader
```

Two distinct `loader.exe` instances found:

| PID | PPID | Session | Created | Context |
|---|---|---|---|---|
| **9788** | 4992 | 1 | 14:07:35 UTC | Interactive user — spawned from `explorer.exe` |
| **3352** | 7096 | 0 | 14:09:42 UTC | SYSTEM — parent PID 7096 **not in process list** |

PID 3352 has an orphaned parent. PID 7096 exited before the memory capture — the hallmark of a short-lived intermediary process used in UAC bypass. Session 0 placement confirms this is the privilege-escalated beacon.

---

## Process Tree Context

```
explorer.exe (4992)
  └── loader.exe (9788)          ← initial DNS beacon, user context
        └── conhost.exe (9800)

loader.exe (3352)                ← SYSTEM beacon, orphaned PPID 7096
  └── conhost.exe (5604)
```

Notable co-processes at capture time:

| PID | Process | Significance |
|---|---|---|
| 2608 | MsMpEng.exe | Defender AV engine — active |
| 3012 | Sysmon64.exe | Sysmon — logging active |
| 2368 | wazuh-agent.exe | Wazuh agent — active |
| 8548 | rustinel.exe | Rust EDR — active |
| 8588 | go-winpmem | Memory acquisition tool — blue team initiated capture |

---

## Token Privileges: User vs SYSTEM

```bash
vol.py -f windows_ram.raw windows.privileges --pid 9788 3352
```

### PID 9788 — Initial Beacon (High Integrity Admin)

Standard admin user token elevated via UAC to High Integrity. `SeDebugPrivilege` absent from the enabled set — cannot open arbitrary process handles at this privilege level.

### PID 3352 — SYSTEM Beacon

| Privilege | State | Significance |
|---|---|---|
| **SeTcbPrivilege** | Present, Enabled, Default | **Definitive SYSTEM token indicator** — act as part of OS |
| **SeDebugPrivilege** | Present, Enabled, Default | Open any process including lsass |
| **SeImpersonatePrivilege** | Present, Enabled, Default | Impersonate any logged-on user |
| SeLockMemoryPrivilege | Present, Enabled, Default | Lock pages in RAM |
| SeAuditPrivilege | Present, Enabled, Default | Generate security audit events |
| SeBackupPrivilege | Present | Read any file bypassing ACL |
| SeRestorePrivilege | Present | Write any file bypassing ACL |
| SeLoadDriverPrivilege | Present | Load/unload kernel drivers |

`SeTcbPrivilege` enabled by default is the definitive indicator of `NT AUTHORITY\SYSTEM`. No normal admin account can hold this privilege.

---

## Loaded DLLs — Reflective Load Evidence

```bash
vol.py -f windows_ram.raw windows.dlllist --pid 9788
```

Two critical anomalies:

**1. `WS2_32.dll` present but absent from loader.exe IAT**

`WS2_32.dll` appears in PID 9788's loaded module list but does not appear in `loader_evade.exe`'s on-disk import table. It was loaded at runtime by the reflective loader's IAT fixup routine when it resolved imports for the embedded dns_agent PE. This is a runtime-only dependency — visible in memory, invisible in static analysis.

**2. NTLM/SSPI DLL cluster at 14:09:42**

All loaded at the exact timestamp of PID 3352's creation:

| DLL | Load Time | Significance |
|---|---|---|
| `SspiCli.dll` | 14:09:42 | SSPI client interface |
| `SECUR32.dll` | 14:09:42 | SSPI/NTLM |
| `msv1_0.DLL` | 14:09:42 | NTLM authentication provider |
| `NtlmShared.dll` | 14:09:42 | NTLM shared code |
| `cryptdll.dll` | 14:09:42 | Kerberos/NTLM crypto |

This timestamp cluster — five NTLM-related DLLs loading simultaneously at the moment the SYSTEM beacon appeared — is the memory-based confirmation that PID 9788 initiated the SSPI UAC bypass at 14:09:42 to forge an authentication context and spawn PID 3352.

---

## VAD Analysis — Reflective PE Mapping

```bash
vol.py -f windows_ram.raw windows.vadinfo --pid 9788
```

**Critical entry:**

```
PID   Start VPN       End VPN         Tag   Protection      PrivateMemory  File
9788  0x140000000     0x140045fff     VadS  PAGE_READWRITE  1              N/A
```

Breakdown of what this tells us:

| Attribute | Value | Meaning |
|---|---|---|
| `0x140000000` | PE preferred ImageBase for x64 MinGW binaries | Reflective loader allocated at the preferred base |
| Size `0x46000` | 286,720 bytes | Matches SizeOfImage of dns_agent_53.exe |
| `VadS` tag | Anonymous private allocation | **No file backing** — not a normal PE load |
| `PAGE_READWRITE` | Initial protection | Loader wrote the PE as RW, then applied per-section perms |
| File path | N/A | No associated file — the PE exists only in memory |

For comparison, the legitimate loader binary in memory:

```
0x7ff652880000  0x7ff6528d4fff  Vad  PAGE_EXECUTE_WRITECOPY  \Users\test_user\Downloads\loader.exe
```

This is backed by a file on disk (`Vad` tag, not `VadS`). The `VadS` at `0x140000000` with no file path is the canonical memory signature of in-process reflective PE loading.

---

## malfind — Why It Found Nothing

```bash
vol.py -f windows_ram.raw windows.malfind --pid 9788 3352
# Result: no output
```

`malfind` identifies regions with `MZ`/`PE` headers that carry `PAGE_EXECUTE_READWRITE` permissions. The reflective loader applied proper section-level protections after mapping:

- `.text` → `PAGE_EXECUTE_READ`
- `.data` / `.rdata` → `PAGE_READWRITE`

Since the code section is not writable, malfind's primary detection heuristic does not fire. The correct detection method is `vadinfo` anomaly hunting — anonymous private allocations at PE preferred bases with no file backing.

---

## UAC Bypass Registry Artifact

```bash
vol.py -f windows_ram.raw windows.registry.printkey \
  --key "Software\Classes\ms-settings\shell\open\command"
```

The key path exists in `UsrClass.dat` but carries **no data values**. The attacker's payload (`default` = cmd path, `DelegateExecute` = empty) was either cleaned up by the BOF's post-execution routine or deleted by Defender when it fired `Behavior:Win32/UACBypassExp.gen!G`. The empty key node is a residual artifact that timestamps the first (failed) UAC bypass attempt.

The SSPI bypass — which succeeded — left no equivalent registry artifact.

---

## Network Connections — Expected Absence

```bash
vol.py -f windows_ram.raw windows.netstat
vol.py -f windows_ram.raw windows.netscan
```

Both return empty results for loader.exe / dns_agent connections. Expected — the C2 channel uses raw UDP DNS on port 53. UDP is connectionless; between beacons the agent holds no open socket. The agent was likely in its jitter sleep when winpmem ran. DNS C2 traffic is only visible in pcap, not in a memory snapshot's socket table.

---

## Timeline Reconstruction

All timestamps UTC from `windows.pstree` and `windows.cmdline`:

```
14:05:04  System boot
14:05:19  explorer.exe (4992) — user logged in
14:06:24  powershell.exe (2212) — blue team activity begins
14:07:13  rustinel.exe (8548) — Rust EDR launched from PowerShell
14:07:35  loader.exe (9788) — initial DNS C2 beacon
           dns_agent_53.exe reflectively loaded at 0x140000000
           Winsock2 initialized at runtime, DNS C2 begins beaconing
14:07:xx  uacbybass regshellcmd BOF executed
           HKCU\ms-settings\shell\open\command written
           ComputerDefaults.exe invoked → Defender kills process
14:09:42  loader.exe (3352) — SYSTEM beacon in Session 0
           PPID 7096 (SSPI intermediary) already exited
           Five NTLM DLLs load in PID 9788 at this exact timestamp
14:10:01  go-winpmem (8588) — blue team begins memory acquisition
14:10:18  sc.exe (3792) — Wazuh/Sysmon service state query
```

---

## Indicators of Compromise (Memory-Based)

| Indicator | Type | Context |
|---|---|---|
| VadS at `0x140000000`, 0x46000 bytes, no file backing | Memory — VAD | Reflectively loaded dns_agent_53.exe |
| `WS2_32.dll` in module list, absent from loader.exe IAT | DLL anomaly | Runtime-resolved Winsock import |
| `SECUR32.dll`, `msv1_0.DLL`, `NtlmShared.dll` at 14:09:42 | DLL cluster | SSPI bypass execution timestamp |
| PID 3352 with orphaned PPID 7096 in Session 0 | Process anomaly | SSPI bypass child process |
| `SeTcbPrivilege` enabled on PID 3352 | Token | Definitive SYSTEM context |
| Empty `ms-settings\shell\open\command` key in UsrClass.dat | Registry artifact | Failed UAC bypass attempt |
| No UDP socket entries for loader.exe | Network absence | DNS C2 between-beacon sleep state |

---

## Full Forensics Report

See [loader-memory-forensics.md](loader-memory-forensics.md) for the complete Volatility investigation including all reproduction commands and full plugin output.

---

## Reproduction Commands

```bash
IMG=windows_ram.raw
VOL=/home/kali/volatility3/vol.py

# 1. Confirm OS
$VOL -f $IMG windows.info

# 2. Find loader.exe instances
$VOL -f $IMG windows.pslist | grep -i loader

# 3. Full process tree
$VOL -f $IMG windows.pstree > pstree.txt

# 4. Command lines
$VOL -f $IMG windows.cmdline | grep -A1 -B1 -iE "loader|9788|3352"

# 5. Token privileges
$VOL -f $IMG windows.privileges --pid 9788 3352

# 6. DLL list — find runtime-loaded suspicious DLLs
$VOL -f $IMG windows.dlllist --pid 9788

# 7. VAD map — anonymous executable private allocations
$VOL -f $IMG windows.vadinfo --pid 9788

# 8. malfind (will be empty — for documentation)
$VOL -f $IMG windows.malfind --pid 9788 3352

# 9. Open handles
$VOL -f $IMG windows.handles --pid 9788 | grep -E "File|Key|Process|Thread"

# 10. UAC bypass registry artifact
$VOL -f $IMG windows.registry.printkey \
  --key "Software\Classes\ms-settings\shell\open\command"

# 11. Network (UDP C2 will not appear)
$VOL -f $IMG windows.netstat
$VOL -f $IMG windows.netscan
```

# Memory Forensics — loader.exe Analysis
**Image:** `/mnt/windows_ram/windows_ram.raw` (12 GB)  
**Tool:** Volatility 3 Framework 2.28.1 (`/home/kali/volatility3/vol.py`)  


---

## 1. System Information

```bash
vol.py -f /mnt/windows_ram/windows_ram.raw windows.info
```

| Field | Value |
|-------|-------|
| Kernel Base | `0xf80729c00000` |
| NtMajorVersion | 10 |
| NtMinorVersion | 0 |
| Build | **19041** (Windows 10 20H2) |
| Architecture | x64 (64-bit) |
| System Time (capture) | 2026-06-01 14:10:02 UTC |
| NtSystemRoot | `C:\Windows` |

---

## 2. Process Discovery

### 2.1 Locate loader.exe

```bash
vol.py -f /mnt/windows_ram/windows_ram.raw windows.pslist 2>/dev/null | grep -i loader
```

**Result:**

| PID | PPID | ImageFileName | SessionId | Created |
|-----|------|---------------|-----------|---------|
| **9788** | 4992 | loader.exe | 1 | 2026-06-01 14:07:35 UTC |
| **3352** | 7096 | loader.exe | 0 | 2026-06-01 14:09:42 UTC |

Two distinct instances running. Session 1 = interactive user desktop. Session 0 = services/SYSTEM session.

---

## 3. Process Tree and Parent Context

```bash
vol.py -f /mnt/windows_ram/windows_ram.raw windows.pstree
```

**Relevant extract:**

```
768   winlogon.exe
  * 4812  userinit.exe  [EXITED 14:05:56]
    ** 4992  explorer.exe  "C:\Windows\Explorer.EXE"
       *** 9788  loader.exe  "C:\Users\test_user\Downloads\loader.exe"
           **** 9800  conhost.exe

3352  loader.exe  c:\users\test_user\downloads\loader.exe
  * 5604  conhost.exe
```

**Analysis:**

- **PID 9788** — launched interactively by `explorer.exe` (PID 4992). This is the initial user-context beacon the attacker executed from the Downloads folder.
- **PID 3352** — PPID 7096 is **not present** in the process tree. The parent process exited before the memory capture. An orphaned parent is a hallmark of UAC bypass techniques: a short-lived intermediary process elevates and spawns loader.exe then terminates. The 2-minute gap between the two instances (14:07:35 vs 14:09:42) and Session 0 placement confirm this is the privilege-escalated beacon born from the SSPI UAC bypass.

**Notable co-processes identified in the full tree:**

| PID | Process | Note |
|-----|---------|------|
| 2608 | MsMpEng.exe | Microsoft Defender AV engine — active |
| 3012 | Sysmon64.exe | Sysmon event logging — active |
| 2368 | wazuh-agent.exe | Wazuh SIEM agent — active |
| 8548 | rustinel.exe | Rust-based tool, spawned from PowerShell (PID 2212) under explorer — additional red team artifact |
| 8588 | go-winpmem | `go-winpmem_amd64_1.0-rc2_signed.exe acquire C:\temp\windows_ram.raw` — confirms this image was captured by the blue team at 14:10:01 UTC, 2m19s after the SYSTEM beacon appeared |


---

## 4. Command Lines

```bash
vol.py -f /mnt/windows_ram/windows_ram.raw windows.cmdline 2>/dev/null | grep -A1 -B1 -i loader
```

**Result:**

```
9788  loader.exe  "C:\Users\test_user\Downloads\loader.exe"
3352  loader.exe  c:\users\test_user\downloads\loader.exe
```

Both instances run from the same binary in `Downloads`. No command-line arguments — the loader is self-contained. The lowercase path on PID 3352 indicates it was spawned programmatically (SSPI bypass intermediary passed the path without quoting).

---

## 5. Token Privileges

```bash
vol.py -f /mnt/windows_ram/windows_ram.raw windows.privileges --pid 9788 3352
```

### PID 9788 — Session 1 (Initial Beacon, High Integrity Admin)

Privileges marked **Present** or **Enabled**:

| Privilege | State |
|-----------|-------|
| SeShutdownPrivilege | Present |
| SeChangeNotifyPrivilege | Present, Enabled, Default |
| SeUndockPrivilege | Present |
| SeIncreaseWorkingSetPrivilege | Present |
| SeTimeZonePrivilege | Present |
| SeCreateGlobalPrivilege | Default |

All other privileges (SeDebugPrivilege, SeImpersonatePrivilege, SeTcbPrivilege) are **absent from the enabled set**. This token belongs to a standard admin user elevated via UAC to High Integrity — not SYSTEM.

### PID 3352 — Session 0 (SYSTEM Beacon)

Privileges marked **Present, Enabled, Default**:

| Privilege | State | Significance |
|-----------|-------|-------------|
| **SeTcbPrivilege** | Present, Enabled, Default | Act as part of OS — **definitive SYSTEM token indicator** |
| **SeDebugPrivilege** | Present, Enabled, Default | Open any process including lsass |
| **SeImpersonatePrivilege** | Present, Enabled, Default | Impersonate any logged-on user |
| SeLockMemoryPrivilege | Present, Enabled, Default | Lock pages — prevents paging to disk |
| SeSystemProfilePrivilege | Present, Enabled, Default | |
| SeProfileSingleProcessPrivilege | Present, Enabled, Default | |
| SeIncreaseBasePriorityPrivilege | Present, Enabled, Default | |
| SeCreatePagefilePrivilege | Present, Enabled, Default | |
| SeCreatePermanentPrivilege | Present, Enabled, Default | |
| SeAuditPrivilege | Present, Enabled, Default | Generate security audit events |
| SeCreateGlobalPrivilege | Present, Enabled, Default | |
| SeManageVolumePrivilege | Present | |
| SeBackupPrivilege | Present | Read any file bypassing ACL |
| SeRestorePrivilege | Present | Write any file bypassing ACL |
| SeSecurityPrivilege | Present | |
| SeTakeOwnershipPrivilege | Present | |
| SeLoadDriverPrivilege | Present | Load/unload kernel drivers |

The presence of `SeTcbPrivilege` (enabled by default) is the clearest memory-based indicator that PID 3352 runs under the `NT AUTHORITY\SYSTEM` account. A normal admin cannot hold this privilege.

---

## 6. Loaded DLLs — Reflective Loading Evidence

```bash
vol.py -f /mnt/windows_ram/windows_ram.raw windows.dlllist --pid 9788
```

**Result (PID 9788):**

| Base | Size | DLL | Load Time | Note |
|------|------|-----|-----------|------|
| 0x7ff652880000 | 0x55000 | loader.exe | 14:07:35 | Loader binary itself |
| 0x7ffe39530000 | 0x1f8000 | ntdll.dll | 14:07:35 | OS loader |
| 0x7ffe39300000 | 0xc2000 | KERNEL32.DLL | 14:07:35 | Static import |
| 0x7ffe36cf0000 | 0x2f6000 | KERNELBASE.dll | 14:07:35 | |
| 0x7ffe39430000 | 0x9e000 | msvcrt.dll | 14:07:35 | |
| 0x7ffe38ac0000 | 0xb1000 | ADVAPI32.dll | **14:07:35** | Runtime loaded |
| 0x7ffe389a0000 | 0x9f000 | sechost.dll | 14:07:35 | |
| 0x7ffe390b0000 | 0x120000 | RPCRT4.dll | 14:07:35 | |
| 0x7ffe37520000 | 0x27000 | bcrypt.dll | 14:07:35 | |
| **0x7ffe38a40000** | 0x6b000 | **WS2_32.dll** | **14:07:35** | Winsock — resolved by reflective loader IAT fixup |
| 0x7ffe36460000 | 0x18000 | CRYPTSP.dll | 14:07:35 | |
| 0x7ffe35b90000 | 0x38000 | rsaenh.dll | 14:07:35 | |
| 0x7ffe36480000 | 0xc000 | CRYPTBASE.dll | 14:07:35 | |
| 0x7ffe37110000 | 0x82000 | bcryptPrimitives.dll | 14:07:35 | |
| **0x7ffe36aa0000** | 0x32000 | **SspiCli.dll** | **14:09:42** | Loaded at time of second instance spawn — SSPI bypass artifact |
| 0x7ffe36270000 | 0x6a000 | mswsock.dll | 14:09:42 | |
| **0x7ffe2b570000** | 0xc000 | **SECUR32.dll** | **14:09:42** | SSPI/NTLM |
| **0x7ffe361e0000** | 0x8c000 | **msv1_0.DLL** | **14:09:42** | NTLM authentication provider |
| 0x7ffe371f0000 | 0x100000 | ucrtbase.dll | 14:09:42 | |
| **0x7ffe361c0000** | 0x17000 | **NtlmShared.dll** | **14:09:42** | NTLM shared code |
| **0x7ffe362e0000** | 0x15000 | **cryptdll.dll** | **14:09:42** | Kerberos/NTLM crypto |

**Key observations:**

1. `WS2_32.dll` is present in the process's loaded module list — but it does **not appear in `loader.exe`'s import table on disk**. It was loaded at runtime by the reflective loader's IAT fixup routine when it resolved imports for the embedded dns_agent PE.
2. The cluster of NTLM/SSPI DLLs (`SECUR32.dll`, `msv1_0.DLL`, `NtlmShared.dll`, `cryptdll.dll`) all loaded at **14:09:42** — the timestamp of PID 3352's creation. This timing confirms that PID 9788 initiated the SSPI UAC bypass at that moment, pulling in NTLM libraries to forge the authentication context.

---

## 7. Virtual Address Descriptor Analysis — Reflective PE Mapping

```bash
vol.py -f /mnt/windows_ram/windows_ram.raw windows.vadinfo --pid 9788
```

**Critical entry:**

```
PID   Start VPN      End VPN        Tag    Protection         PrivateMemory  File
9788  0x140000000    0x140045fff    VadS   PAGE_READWRITE     1              N/A
```

**Analysis:**

- **Address `0x140000000`** — This is the default `ImageBase` for x64 PE files compiled by MinGW (and the preferred base of `dns_agent_53.exe`). The reflective loader successfully allocated at the preferred base.
- **Size `0x46000` (286,720 bytes)** — Matches the SizeOfImage of the embedded dns_agent_53.exe PE (source file: 301,110 bytes on disk, rounded to section alignment gives ~280-288 KB mapped).
- **`VadS` tag** — Indicates an anonymous private allocation (no file backing). A legitimate PE loaded normally by the Windows loader would show a `Vad` tag backed by the PE file on disk. **A VadS at the PE preferred base with no file backing is the canonical signature of in-process reflective PE loading.**
- **`PAGE_READWRITE`** — Initial protection. The reflective loader allocated the region as RW, wrote the PE, then used `VirtualProtect` to apply per-section permissions (code → RX, data → RW). Volatility's vadinfo shows the VAD node's initial protection setting.

**Comparison — legitimate loader.exe mapping:**
```
0x7ff652880000  0x7ff6528d4fff  Vad  PAGE_EXECUTE_WRITECOPY  0  \Users\test_user\Downloads\loader.exe
```
This is backed by the loader.exe file on disk (normal PE load). The `VadS` at `0x140000000` with no file path is the anomaly.

---

## 8. malfind — Injected Code Search

```bash
vol.py -f /mnt/windows_ram/windows_ram.raw windows.malfind --pid 9788 3352
```

**Result: No output.**

**Why malfind found nothing:**

`malfind` identifies regions with `MZ`/`PE` headers that also carry `PAGE_EXECUTE_READWRITE` permissions. The reflective loader applied proper section-level permissions via `VirtualProtect` after mapping:
- `.text` section → `PAGE_EXECUTE_READ`
- `.data`/`.rdata` sections → `PAGE_READWRITE`

Since the code section is not writable (`PAGE_EXECUTE_READ`), malfind's primary detection heuristic does not fire. This demonstrates that applying correct section permissions during reflective loading successfully evades malfind-class detectors. The correct detection method is vadinfo anomaly hunting (Section 7).

---

## 9. Open Handles

```bash
vol.py -f /mnt/windows_ram/windows_ram.raw windows.handles --pid 9788 | grep -E "File|Key|Process|Thread"
```

**Result (PID 9788):**

| Type | Name | Significance |
|------|------|-------------|
| File | `\Device\HarddiskVolume3\Users\test_user\Downloads` | Working directory handle — confirms execution from Downloads folder |
| File | `\Device\ConDrv\Connect`, `Input`, `Output` | Console I/O pipes (conhost.exe connection) |
| File | `\Device\KsecDD` | Kernel Security Device — used by SSPI/crypto subsystem |
| File | `\Device\CNG` | Cryptography Next Generation — WSAStartup crypto path |
| Key | `MACHINE\SYSTEM\CONTROLSET001\SERVICES\WINSOCK2\PARAMETERS\PROTOCOL_CATALOG9` | Winsock catalog read — WSAStartup initialising at runtime |
| Key | `MACHINE\SYSTEM\CONTROLSET001\SERVICES\WINSOCK2\PARAMETERS\NAMESPACE_CATALOG5` | Winsock namespace — DNS resolver configuration read |
| Key | `MACHINE\SYSTEM\CONTROLSET001\CONTROL\SESSION MANAGER` | Normal process init |
| Key | `MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\IMAGE FILE EXECUTION OPTIONS` | IFEO check on startup |
| Thread | Tid 9792 Pid 9788 (×2) | Main thread handle (duplicated) |

The Winsock2 catalog registry keys are opened at runtime during `WSAStartup` — confirming the embedded dns_agent PE successfully initialised its network stack after reflective loading, without those keys appearing in the loader's static import table.

---

## 10. UAC Bypass Registry Artifact

```bash
vol.py -f /mnt/windows_ram/windows_ram.raw windows.registry.printkey \
  --key "Software\Classes\ms-settings\shell\open\command"
```

The key path `\??\C:\Users\test_user\ntuser.dat\Software\Classes\ms-settings\shell\open\command` and `\??\C:\Users\test_user\AppData\Local\Microsoft\Windows\UsrClass.dat\...` are present in the hive structure but carry **no data values**. The key node exists in the hive due to the hive tree structure, but the attacker's values (`default`, `DelegateExecute`) were either:
- Cleaned up by the `uacbybass regshellcmd` BOF's post-execution cleanup routine, or
- Deleted by Defender's remediation when it detected `Behavior:Win32/UACBypassExp.gen!G`

The empty key node itself is a residual artifact that locates the timing of the first bypass attempt. The successful SSPI bypass that subsequently spawned PID 3352 left no equivalent registry artifact.

---

## 11. Network Connections

```bash
vol.py -f /mnt/windows_ram/windows_ram.raw windows.netstat
vol.py -f /mnt/windows_ram/windows_ram.raw windows.netscan
```

Both plugins return empty results for loader.exe / dns_agent connections. This is expected: the C2 channel uses **raw UDP DNS queries** on port 53. UDP is a connectionless protocol — active UDP sockets only appear in netstat/netscan if they are in a `LISTEN` or bound state at the moment of capture. Between DNS queries (during the sleep interval), no socket is held open. The beacon had been running approximately 2.5 minutes before capture; the agent was likely in its jitter sleep when winpmem ran.

The DNS traffic is visible only in network capture (pcap), not in a memory snapshot's socket table.

---

## 12. Timeline Reconstruction

All timestamps UTC from windows.pstree and windows.cmdline output.

```
14:05:04  System boot
14:05:19  explorer.exe (4992) launched — user logged in
14:06:24  powershell.exe (2212) launched from explorer — blue team activity begins
14:07:13  rustinel.exe (8548) launched from powershell — secondary red team tool
14:07:35  loader.exe (9788) spawned directly from explorer.exe — initial DNS C2 beacon
          [dns_agent_53.exe reflectively loaded into process memory at 0x140000000]
          [Winsock2 initialized at runtime, DNS C2 begins beaconing to c2.lab:53]
14:07:xx  uacbybass regshellcmd executed via BOF
          HKCU\ms-settings\shell\open\command written → ComputerDefaults.exe runs
          Defender fires: Behavior:Win32/UACBypassExp.gen!G — process killed
14:09:42  loader.exe (3352) appears in Session 0 with SYSTEM token
          PPID 7096 (SSPI intermediary) already exited
          SSPI bypass loaded NTLM libraries into PID 9788 at 14:09:42 to forge elevation
14:10:01  go-winpmem (8588) starts — blue team begins memory acquisition
          "go-winpmem_amd64_1.0-rc2_signed.exe acquire C:\temp\windows_ram.raw"
14:10:18  sc.exe (3792) spawned by taskhostw — Wazuh/Sysmon service query
14:10:02  Memory capture timestamp (windows.info SystemTime)
```

---

## 13. Indicators of Compromise

| Indicator | Type | Context |
|-----------|------|---------|
| `C:\Users\test_user\Downloads\loader.exe` | File path | Both beacon instances |
| VadS at `0x140000000`, 0x46000 bytes, no file backing | Memory | Reflectively loaded dns_agent_53.exe PE |
| `WS2_32.dll` in module list, absent from loader.exe IAT | DLL anomaly | Runtime-resolved Winsock import |
| `SECUR32.dll`, `msv1_0.DLL`, `NtlmShared.dll` loaded at 14:09:42 | DLL cluster | SSPI UAC bypass execution |
| PID 3352 with orphaned PPID 7096 in Session 0 | Process anomaly | SSPI bypass child |
| `SeTcbPrivilege` enabled on PID 3352 | Token | Definitive SYSTEM context |
| Winsock2 catalog registry keys in PID 9788 handle table | Handle | Runtime DNS init |
| Empty `ms-settings\shell\open\command` key node in UsrClass.dat | Registry | Failed UAC bypass artifact |
| DNS queries to `c2.lab:53` (not visible in memory, visible in pcap) | Network | C2 transport |

---

## 14. Reproduction Commands (Full Investigation Sequence)

Copy-paste in order to reproduce this investigation from scratch:

```bash
IMG=/mnt/windows_ram/windows_ram.raw
VOL=/home/kali/volatility3/vol.py

# 1. Confirm OS and capture time
$VOL -f $IMG windows.info

# 2. Find loader.exe instances
$VOL -f $IMG windows.pslist | grep -i loader

# 3. Full process tree (identify parent chain and co-processes)
$VOL -f $IMG windows.pstree > pstree.txt

# 4. Command lines for both PIDs
$VOL -f $IMG windows.cmdline | grep -A1 -B1 -iE "loader|9788|3352"

# 5. Token privileges — distinguish admin from SYSTEM
$VOL -f $IMG windows.privileges --pid 9788 3352

# 6. DLL list — find runtime-loaded suspicious DLLs
$VOL -f $IMG windows.dlllist --pid 9788

# 7. VAD map — find anonymous executable/private allocations (reflective load)
$VOL -f $IMG windows.vadinfo --pid 9788

# 8. malfind — check for RWX injection (will be empty with proper section perms)
$VOL -f $IMG windows.malfind --pid 9788 3352

# 9. Open handles — network and registry activity
$VOL -f $IMG windows.handles --pid 9788 | grep -E "File|Key|Process|Thread"

# 10. Registry — UAC bypass artifact
$VOL -f $IMG windows.registry.printkey \
  --key "Software\Classes\ms-settings\shell\open\command"

# 11. Network connections (UDP C2 will not appear — expected)
$VOL -f $IMG windows.netstat
$VOL -f $IMG windows.netscan

# 12. Strings from loader.exe memory (look for C2 domain, DLL names)
$VOL -f $IMG windows.strings --pid 9788 | \
  grep -iE "c2\.lab|ws2_32|winsock|cmd\.exe|downloads"
```

---

## 15. Forensic Conclusions

| Question | Finding |
|----------|---------|
| What is loader.exe? | Reflective PE loader — decrypts and in-process maps dns_agent_53.exe |
| What did it load? | dns_agent_53.exe (DNS C2 implant, 301KB encrypted blob) at VA 0x140000000 |
| What network activity? | Raw UDP DNS to c2.lab:53 — not captured in socket table |
| What privilege level was PID 9788? | High Integrity (admin), not SYSTEM; SeDebugPrivilege not enabled |
| What privilege level was PID 3352? | NT AUTHORITY\SYSTEM — SeTcbPrivilege, SeDebugPrivilege, SeImpersonatePrivilege all enabled |
| How did PID 3352 reach SYSTEM? | SSPI Datagram Context UAC bypass (intermediary PID 7096) then getsystem token BOF |
| Was there prior UAC bypass attempt? | Yes — regshellcmd (ms-settings registry) — caught by Defender, empty key node remains |
| Did malfind detect the injection? | No — correct section permissions prevent RWX signature match |
| How was the memory image acquired? | go-winpmem by blue team at 14:10:01 UTC, ~2.5min after SYSTEM beacon appeared |

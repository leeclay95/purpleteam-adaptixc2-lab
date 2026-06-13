# dumpex Analysis — loader.exe Memory Dumps 
**Tool:** [dumpex](https://github.com/bitbug0x55AA/dumpex)  
**Dumps:** `/mnt/windows_ram/loader_service_5512.dmp`, `/mnt/windows_ram/loader_user_5188.dmp`

---

## Environment

dumpex depends on `minidump >= 0.0.24` for PEB parsing. The system package is 0.0.21 and lacks the `.peb` attribute. All commands below must be run inside `dfir_env`.

```bash
source /home/kali/dfir_env/bin/activate
cd /home/kali/dumpex
```

> To verify the library version: `pip show minidump`

---

## Subject Dumps

| Field | loader_user_5188.dmp | loader_service_5512.dmp |
|---|---|---|
| PID | 5188 (0x1444) | 5512 (0x1588) |
| Process start (UTC) | 2026-06-02 16:10:53 | 2026-06-02 16:13:39 |
| Image | `C:\Users\test_user\Downloads\loader.exe` | `c:\users\test_user\downloads\loader.exe` |
| Compiled (UTC) | 2026-05-31 22:04:02 | 2026-05-31 22:04:02 (same binary) |
| Username | test_user | DESKTOP-N46SBV9$ (SYSTEM) |
| Working directory | `C:\Users\test_user\Downloads\` | `C:\Windows\system32\` |
| Threads in dump | 1 | 2 |
| Modules in dump | 21 | 16 |
| Host | DESKTOP-N46SBV9 | DESKTOP-N46SBV9 |
| OS | Windows 10 22H2 (10.0.19045) AMD64 | Windows 10 22H2 (10.0.19045) AMD64 |

Both processes run the same binary compiled the day before capture. The service dump (5512) runs as the machine account (`DESKTOP-N46SBV9$`) three minutes after the user process launched — consistent with a successful local privilege escalation.

---

## Commands Run

Every command section below maps directly to the finding that follows it.

### 1. System info

```bash
python3 Dumpex.py /mnt/windows_ram/loader_user_5188.dmp --sysinfo
python3 Dumpex.py /mnt/windows_ram/loader_service_5512.dmp --sysinfo
```

### 2. PEB

```bash
python3 Dumpex.py /mnt/windows_ram/loader_user_5188.dmp --peb
python3 Dumpex.py /mnt/windows_ram/loader_service_5512.dmp --peb
```

### 3. Modules

```bash
python3 Dumpex.py /mnt/windows_ram/loader_user_5188.dmp --modules
python3 Dumpex.py /mnt/windows_ram/loader_service_5512.dmp --modules
```

### 4. Threads

```bash
python3 Dumpex.py /mnt/windows_ram/loader_user_5188.dmp --threads
python3 Dumpex.py /mnt/windows_ram/loader_service_5512.dmp --threads
```

### 5. Full TTP hunt (both dumps)

```bash
python3 Dumpex.py /mnt/windows_ram/loader_user_5188.dmp --hunt all --verbose --txt /tmp/dumpex_5188.txt
python3 Dumpex.py /mnt/windows_ram/loader_service_5512.dmp --hunt all --verbose --txt /tmp/dumpex_5512.txt
```

### 6. String extraction — unregistered PE at 0x140000000

```bash
python3 Dumpex.py /mnt/windows_ram/loader_user_5188.dmp   --strings 0x140000000
python3 Dumpex.py /mnt/windows_ram/loader_service_5512.dmp --strings 0x140000000
```

### 7. String extraction — mimikatz regions (5512 only)

```bash
python3 Dumpex.py /mnt/windows_ram/loader_service_5512.dmp --strings 0x197cc2c0000 --grep "lsadump|sekurlsa|mimikatz|logon|kerberos|sam|cache|dcsync"
python3 Dumpex.py /mnt/windows_ram/loader_service_5512.dmp --strings 0x197cc600000 --grep "lsadump|sekurlsa|mimikatz|logon|kerberos|sam|cache|dcsync"
```

### 8. String extraction — named pipe C2 region (5188 only)

```bash
python3 Dumpex.py /mnt/windows_ram/loader_user_5188.dmp --strings 0x183a4840000 --grep "ntsvcs|127\.0\.0\.1|pipe|connect"
```

### 9. Triage reports

```bash
# Anchored to the CreateSvcRpc/pipe region in the user process
python3 Dumpex.py /mnt/windows_ram/loader_user_5188.dmp --report --report-addr 0x183a4840000

# Anchored to the mimikatz string region in the service process
python3 Dumpex.py /mnt/windows_ram/loader_service_5512.dmp --report --report-addr 0x197cc2c0000

# Hunt by string across all regions (shows both lsadump regions)
python3 Dumpex.py /mnt/windows_ram/loader_service_5512.dmp --report --report-string "lsadump"
```

### 10. Raw PE extraction (unregistered PE, both dumps)

```bash
python3 Dumpex.py /mnt/windows_ram/loader_user_5188.dmp   --extract 0x140000000 -o /tmp/injected_pe_5188.bin
python3 Dumpex.py /mnt/windows_ram/loader_service_5512.dmp --extract 0x140000000 -o /tmp/injected_pe_5512.bin
```

---

## Findings

### Finding 1 — Unregistered PE in private memory (both processes)

**YARA rule hit:** `PE_In_Private_Memory` (T1055)

Both processes contain an MZ/PE header at virtual address `0x0000000140000000` in a `PAGE_READWRITE MEM_PRIVATE` region that has no corresponding entry in the loaded module list. The PE headers are identical across both dumps (same section layout), confirming the same payload was injected into both.

```
VA (process)   0x0000000140000000
File offset    0x850b              (loader_service_5512.dmp)
File offset    0x8de3              (loader_user_5188.dmp)
Region size    0x1000
Protection     PAGE_READWRITE
Type           MEM_PRIVATE
```

Section names extracted from the PE header:

```
.data   .rdata   .pdata   .xdata   .idata   .reloc
```

The region is read-write, not executable — the payload header stub is parked in RW memory while the actual executable sections are mapped elsewhere or will be resolved reflectively at runtime.

**Command to extract for further analysis:**
```bash
python3 Dumpex.py /mnt/windows_ram/loader_user_5188.dmp --extract 0x140000000 -o /tmp/injected_pe.bin
```

---

### Finding 2 — Privilege escalation via loopback NTLM relay (5188 — user process)

**Hunt verdict:** `LIKELY C2 PIPE` (2/4)  
**YARA rule hits:** `WMI_Lateral_Movement`, `Suspicious_VirtualAlloc_Sequence`, `Shellcode_Bootstrap_x64`, `Win32_API_Hashing`

Three private unbacked regions in the user process contain named pipe references alongside loopback connection strings:

| Region VA | Pipe name | C2 artifact |
|---|---|---|
| `0x4465fde000` | `\pipe\ntsvcs` | `\\127.0.0.1\pipe\ntsvcs` |
| `0x183a4840000` | `\pipe\ntsvcs RPC pipe` | `Connecting to \\127.0.0.1\pipe\ntsvcs RPC pipe` |
| `0x183a4b90000` | `\pipe\%s` | `\\127.0.0.1\pipe\%s`, `Connecting to \\127.0.0.1\pipe\ntsvcs RPC pipe` |

The hex dump in the triage report reveals the exact technique in plain text inside region `0x183a4840000`:

```
...w impersonating the forged token... Loopback network auth should be seen as
elevated now.
Invoking CreateSvcRpc (by @x86matthew).
Connecting to \\127.0.0.1\pipe\ntsvcs RPC pipe
Opening service manager....
Creating temporary service....
Executing 'c:\users\tes[t_user\downloads\loader.exe]...
```

This is the **CreateSvcRpc** local privilege escalation technique ([@x86matthew](https://github.com/x86matthew/CreateSvcRpc)). It works by:

1. Creating a local named pipe (`\pipe\ntsvcs`) and triggering a loopback NTLM authentication from a SYSTEM-level service
2. Relaying the NTLM token over the loopback to impersonate SYSTEM
3. Calling `CreateService` via RPC with the impersonated token to execute an arbitrary binary as SYSTEM

The module load list for PID 5188 confirms NTLM authentication libraries were loaded by the user process — consistent with the relay requiring local NTLM negotiation:

```
secur32.dll       msv1_0.dll       NtlmShared.dll       cryptdll.dll
```

These modules are **absent** from the 5512 (SYSTEM) process, which loaded only 16 modules — by that point the escalation was complete.

**Timeline:** User process 5188 started at 16:10:53. SYSTEM process 5512 appeared at 16:13:39 — **2 minutes 46 seconds** for the relay to complete and `loader.exe` to relaunch as SYSTEM.

---

### Finding 3 — Mimikatz credential dumping in SYSTEM process (5512)

**YARA rule hits:** `Mimikatz_Strings` (T1003.001), `LSASS_Dump_Keywords` (T1003.001)

Two private unbacked regions in the SYSTEM process contain Mimikatz output strings and internal function labels. These regions are absent from the user process dump.

**Region `0x197cc2c0000`** (124 KB, PAGE_READWRITE, MEM_PRIVATE):
```
=== lsadump::sam ===
=== lsadump::cache ===
```

**Region `0x197cc600000`** (60 KB, PAGE_READWRITE, MEM_PRIVATE):
```
=== lsadump::sam ===
[!] Failed to open SAM: %d
SAM\Domains\Account
[!] RegOpenKeyEx SAM\Domains\Account failed: %d
[*] SAM key AES: DataLen=%u
SAMKey: %s
SAM\Domains\Account\Users
[!] Unknown SAM key Revision: %u (expected 2 for AES)
[!] Failed to decrypt SAM key
    (Cached domain credentials key)
```

The presence of two separate regions containing `lsadump::sam` output markers (plus SAM registry path strings and AES key parsing labels) indicates Mimikatz was executed in-process — likely via BOF or reflective loading rather than as a standalone executable. The `lsadump::sam` module targets local account hashes; `lsadump::cache` targets cached domain credentials stored in the registry.

The SYSTEM process also contains `KERNELBASE.dll` with `lsass.exe`, `MiniDumpWriteDump`, and `comsvcs.dll` strings — standard LSASS dump capability strings present in KERNELBASE itself. No separate lsass dump file was found in the dump paths examined.

**YARA rule `LSASS_Dump_Keywords` hit location:**

```
Region  VA 0x00007ff9a9a52000  ← C:\Windows\System32\KERNELBASE.dll
  $s1  VA 0x00007ff9a9b3b320   lsass.exe
  $s2  VA 0x00007ff9a9b52c58   MiniDumpWriteDump
  $s4  VA 0x00007ff9a9b43ac0   comsvcs.dll
```

> This is a false-positive signal — these strings live in KERNELBASE.dll itself as export/import names, not in attacker-controlled memory. The meaningful hit is `Mimikatz_Strings` in private regions.

---

### Finding 4 — Additional thread in SYSTEM process

The SYSTEM process (5512) has two threads vs one in the user process:

| TID | Start address | Module | Created |
|---|---|---|---|
| 0x215c | `0x7ff632a21440` | `loader.exe` | 2026-06-02 16:13:39 |
| 0x20ac | `0x7ff9ac09d110` | `ntdll.dll` | 2026-06-02 16:18:39 |

TID 0x20ac started **5 minutes after** the main thread and is backed by `ntdll.dll` — consistent with a threadpool or timer-queue callback. This could be a cleanup, exfil, or C2 check-in thread.

---

### Finding 5 — Base64 payload in SYSTEM process (5512)

The obfuscation hunt flagged one private region in the SYSTEM process containing Base64-encoded data. This was not present in the user process.

```bash
# To identify the region and extract it:
python3 Dumpex.py /mnt/windows_ram/loader_service_5512.dmp --hunt obfuscation --verbose
```

---

## Attack Sequence

```
16:10:53  test_user double-clicks loader.exe
          └─ PID 5188 starts in Downloads, CWD = Downloads
          └─ Loads NTLM auth DLLs (secur32, msv1_0, NtlmShared, cryptdll)
          └─ Injects PE stub at 0x140000000 (PAGE_READWRITE, private)
          └─ CreateSvcRpc loopback relay:
               1. Opens \pipe\ntsvcs listener
               2. Coerces SYSTEM NTLM auth over loopback (127.0.0.1)
               3. Impersonates forged SYSTEM token
               4. Calls CreateService → executes loader.exe as SYSTEM

16:13:39  loader.exe re-executes as DESKTOP-N46SBV9$ (SYSTEM)
          └─ PID 5512 starts, CWD = C:\Windows\system32\
          └─ Injects same PE stub at 0x140000000
          └─ Reflectively loads Mimikatz (in-process, no disk drop)
          └─ Runs lsadump::sam   → dumps local SAM hashes
          └─ Runs lsadump::cache → dumps cached domain credentials
          └─ Spawns second thread (TID 0x20ac) from ntdll at 16:18:39
```

---

## MITRE ATT&CK Summary

| Technique | ID | Evidence |
|---|---|---|
| User Execution | T1204.002 | `loader.exe` run from Downloads by test_user |
| Process Injection | T1055 | Unregistered PE at `0x140000000` in both processes |
| Token Impersonation / Theft | T1134.001 | CreateSvcRpc NTLM loopback relay, `forged token` string |
| Inter-Process Comm: Named Pipes | T1559.001 | `\pipe\ntsvcs` + loopback C2 context |
| OS Credential Dumping: SAM | T1003.002 | `lsadump::sam`, SAM AES key parsing strings in SYSTEM process |
| OS Credential Dumping: Cached Credentials | T1003.005 | `lsadump::cache`, cached domain credentials key string |
| Obfuscated Files or Information | T1027 | Base64 payload region in SYSTEM process |
| Reflective Code Loading | T1620 | PE in private memory, Win32_API_Hashing YARA hit |

---

## IOCs

| Type | Value | Source |
|---|---|---|
| Binary | `loader.exe` | Both dumps — PEB ImagePath |
| Compile timestamp | `2026-05-31 22:04:02 UTC` | Module list |
| Checksum | `0x0004e9eb` | Module list |
| Image base | `0x00007ff632a20000` | Both dumps |
| Injected PE VA | `0x0000000140000000` | Both dumps — PE_In_Private_Memory |
| Pipe name | `\pipe\ntsvcs` | User process private regions |
| Endpoint | `\\127.0.0.1\pipe\ntsvcs` | User process — CreateSvcRpc relay target |
| Tool string | `CreateSvcRpc (by @x86matthew)` | Region `0x183a4840000` in PID 5188 |
| Tool string | `lsadump::sam` | Regions `0x197cc2c0000`, `0x197cc600000` in PID 5512 |
| Tool string | `lsadump::cache` | Region `0x197cc2c0000` in PID 5512 |
| Host | `DESKTOP-N46SBV9` | sysinfo |
| User | `test_user` | PEB env block |

---


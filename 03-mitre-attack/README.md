# MITRE ATT&CK Mapping

All techniques observed during this lab engagement on Windows 10 (DESKTOP-N46SBV9).

| Technique ID | Name | Implementation | Detected |
|---|---|---|---|
| T1071.004 | Application Layer Protocol: DNS | Raw UDP DNS C2 via dns_agent_53.exe | No |
| T1132.001 | Data Encoding: Standard Encoding | Base32 encoding of XOR-encrypted C2 data | No |
| T1027 | Obfuscated Files or Information | RC4-encrypted payload in `.rdata`, masked key | No |
| T1055 | Process Injection | Reflective PE loading (in-process, not remote) | No |
| T1620 | Reflective Code Loading | BOF in-process COFF execution without disk write | No |
| T1548.002 | Abuse Elevation Control: Bypass UAC | regshellcmd (caught) / SSPI datagram (clean) | Partial |
| T1134.001 | Token Manipulation: Token Impersonation | getsystem token BOF via SeDebugPrivilege | No |
| T1003 | OS Credential Dumping | Credential dump BOF | No |
| T1562.001 | Impair Defenses: Disable/Modify Tools | ETW `EtwEventWrite*` patched to `ret` | No |
| T1562.006 | Impair Defenses: Indicator Blocking | ETW telemetry severed pre-allocation | No |
| T1497 | Virtualization/Sandbox Evasion | Monte Carlo 3-min CPU prelude | No |
| T1497.003 | Virtualization/Sandbox Evasion: Time-Based | `GetTickCount` wall-clock check (not Sleep) | No |
| T1106 | Native API | SysWhispers3 direct NT syscalls | No |
| T1059.003 | Command and Scripting: Windows Command Shell | `shell` BOF task via `cmd.exe` | No |
| T1018 | Remote System Discovery | SAR BOF — port scan, NetBIOS scanner | No |
| T1069 | Permission Groups Discovery | AD BOF — LDAP group enumeration | No |
| T1087 | Account Discovery | AD BOF — LDAP user enumeration | No |
| T1046 | Network Service Discovery | Port scanner BOF | No |

---

## Technique Detail

### T1071.004 — DNS C2

The implant constructs raw DNS packets in userspace and fires them directly to the C2 server via UDP. No `DnsQuery` API, no Windows resolver involvement. C2 data rides in the subdomain labels (up) and TXT record RDATA (down). From a network sensor, traffic is valid DNS — no TCP connection state, no TLS fingerprint, no HTTP.

**Detection gap:** network-layer detection requires DNS query frequency analysis or entropy scoring on query names, not just protocol allowlisting.

### T1027 / RC4 Payload

The DNS agent binary is RC4-encrypted inside the loader's `.rdata` section. The key is XOR-masked at rest — no plaintext key in the binary. Ciphertext is unique on every build. No PE headers visible in the binary — entropy is uniformly high, consistent with encrypted data. Static scanners and PE-structure YARA rules cannot analyze the embedded payload.

### T1055 — Reflective PE Loading (In-Process)

`pe_load()` maps the decrypted dns_agent_53.exe into the loader's own process address space at the PE's preferred ImageBase (`0x140000000`). No `CreateRemoteThread`, no `WriteProcessMemory`, no second process involved. The mapped region shows as an anonymous private allocation (`VadS` tag in VAD tree) with no file backing — the canonical memory forensics signature of reflective loading.

**Detection gap:** `malfind` does not fire because the code section is `PAGE_EXECUTE_READ`, not `PAGE_EXECUTE_READWRITE`. Detection requires `vadinfo` anomaly hunting for `VadS` at PE preferred bases with no associated file path.

### T1548.002 — UAC Bypass (Two Techniques)

**Attempt 1 — regshellcmd (CAUGHT):** writes `HKCU\Software\Classes\ms-settings\shell\open\command` then invokes an auto-elevating binary (`ComputerDefaults.exe`). Defender fired `Behavior:Win32/UACBypassExp.gen!G` and killed the process. An empty key node remains in `UsrClass.dat` as a residual artifact.

**Attempt 2 — SSPI Datagram Context (CLEAN):** James Forshaw technique — manipulates NTLM authentication tokens locally within LSASS's SSPI processing path. No registry writes, no auto-elevating binary execution, no process creation. Spawned a SYSTEM-context `loader.exe` via a service control manager call over a loopback RPC pipe. Defender had no behavioral rule for this specific abuse at the installed intelligence version.

### T1134.001 — Token Impersonation

`getsystem token` BOF: enable `SeDebugPrivilege` on the current thread, open a handle to a SYSTEM process, duplicate the primary token, impersonate via `ImpersonateLoggedOnUser`. No alert generated. Confirmed via memory forensics: PID 3352 token showed `SeTcbPrivilege` enabled by default — definitive SYSTEM context indicator.

### T1562.001/006 — ETW Blinding

`blind_etw()` patches `EtwEventWrite`, `EtwEventWriteFull`, and `EtwEventWriteEx` to `0xC3` (`ret`) using `NtProtectVirtualMemory` via SW3 syscall stub. Executed before any allocation or decryption. Defender's ML behavioral telemetry pipeline receives no events from subsequent suspicious operations. Effective against user-mode ETW consumers; does not affect the `Microsoft-Windows-Threat-Intelligence` kernel ETW provider.

### T1497.003 — Sandbox Evasion via CPU Work

`mc_prelude()` runs 3 minutes of Monte Carlo π estimation. Sandboxes that fast-forward `Sleep` cannot speed up actual multiplications. A 2-minute sandbox timeout kills the process before decryption begins. The `GetTickCount` timeout pattern is indistinguishable from legitimate timing-bounded application code.

### T1106 — Indirect Syscalls

SysWhispers3 jumper method: syscall stubs jump to existing `syscall; ret` gadgets inside ntdll rather than executing `syscall` from within the loader binary. EDR hooks on ntdll user-mode wrappers (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtFreeVirtualMemory`) are bypassed — the call originates from inside ntdll's own `.text`, making it appear as a legitimate ntdll-originated syscall.

### T1620 — BOF In-Process Execution

All BOF commands (AD enumeration, credential dump, UAC bypass, token steal, process operations) run as in-process COFF objects. No staging file written to disk. The COFF loader allocates executable memory, applies relocations, resolves Beacon API symbols, and calls the BOF's `go` entry point. Output returns through the same DNS chunking mechanism as shell commands.

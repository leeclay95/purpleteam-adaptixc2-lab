# Purple Team Lab: DNS C2 with Adaptix and EDR Evasion Research

**Author:** leeha  
**Lab Date:** 2026-05-26 to 2026-06-04  
**Framework:** Adaptix C2 v1.2.0  
**Target:** Windows 10 x64 (DESKTOP-N46SBV9)  
**Classification:** Authorized red team research

---

## Overview

This repository documents end-to-end purple team research covering a custom DNS command-and-control stack built on Adaptix C2, multiple AV/EDR evasion techniques, privilege escalation via UAC bypass, and the memory forensics required to find what standard detections missed.

The lab ran on a single Windows 10 system with three concurrent defensive layers active:

| Defensive Layer | Tool | Role |
|---|---|---|
| AV/EDR | Microsoft Defender | Behavioral ML, static scanning |
| YARA EDR | Rustinel (custom Rust EDR) | YARA rule-based process scanning on ETW events |
| SIEM/Logging | Wazuh | Event collection, alert forwarding, log aggregation |

---

## What Was Built

### Offensive Stack

- **BeaconDNS** — Go Adaptix listener plugin running a raw UDP/TCP DNS server
- **dns_agent** — Go Adaptix agent handler plugin
- **dns_agent_53.exe** — Windows x64 C implant communicating via raw DNS TXT records, bypassing the Windows DNS resolver entirely
- **dns-bof-kit** — Collection of Cobalt Strike-compatible BOFs (AD enumeration, credential operations, UAC bypass, token manipulation, process control)
- **loader_evade.exe** — Intermediate reflective PE loader; SysWhispers3 indirect syscalls, ETW blinding, Monte Carlo prelude
- **loader2.exe** — Final payload: COFF BOF architecture (no PE surface), XOR runtime string obfuscation, custom indirect syscalls with Hell's Gate SSN harvesting, AMSI + ETW blinding, three-stage CPU prelude with cursor delta detection, DNS-over-TCP, VEH crash recovery for secondary BOFs

---

## Key Findings Summary

### What Got Caught

`dns_agent_53.exe` dropped directly to disk was caught immediately by Rustinel's YARA rules:
- `network_tcp_listen` — Winsock socket pattern in the import table
- `Str_Win32_Winsock2_Library` — `ws2_32.dll` string reference

Wazuh collected both as Critical severity alerts tagged to the process at the moment of execution. The first UAC bypass attempt (`uacbybass regshellcmd`) was caught by Defender's behavioral engine (`Behavior:Win32/UACBypassExp.gen!G`).

### What Wasn't Caught

`loader_evade.exe` landed with **zero alerts** across all three layers:
- No YARA hits — RC4-encrypted payload, no PE headers, no Winsock strings, no djb2 hash, minimal IAT
- No Defender static detection — import table looks like a benign timing utility
- No Defender behavioral detection — ETW blinded before any allocation, Monte Carlo prelude defeats sandbox timing analysis
- SSPI UAC bypass — no Defender alert; spawned a SYSTEM-context beacon cleanly

The credential dump BOF and `getsystem` token manipulation both executed with **no alerts generated** in either Wazuh or Defender.

Memory forensics (Volatility 3) was required to reconstruct what actually happened:
- Orphaned PPID in Session 0 revealing the SSPI bypass intermediary
- Anonymous VadS at `0x140000000` — reflectively loaded dns_agent_53.exe with no disk backing
- NTLM/SSPI DLL cluster loaded at the exact timestamp of SYSTEM beacon creation
- `SeTcbPrivilege` in the SYSTEM beacon's token — definitive privilege confirmation

---

## Repository Structure

```
├── 01-dns-c2-infrastructure/    DNS C2 design, Adaptix plugins, BOF loader architecture
├── 02-evasion-loader/           loader_evade.exe evasion techniques (full technical)
├── 03-mitre-attack/             MITRE ATT&CK technique mapping
├── 04-detection-logging/        What YARA/Defender/Wazuh caught and what they missed
├── 05-memory-forensics/         Volatility 3 analysis — UAC bypass, SYSTEM token, reflective load
└── assets/                      Lab screenshots and evidence
```

---

## Lab Environment

```
┌─────────────────────────────────────────────────────────────┐
│  Kali Linux (attacker)         VMware host-only network     │
│  Adaptix C2 v1.2.0             192.168.67.132               │
│  BeaconDNS listener :53                                      │
└────────────────────────┬────────────────────────────────────┘
                         │ UDP port 53 (raw DNS)
┌────────────────────────▼────────────────────────────────────┐
│  Windows 10 20H2 (target)       DESKTOP-N46SBV9             │
│  192.168.67.128                                              │
│                                                              │
│  Microsoft Defender (active + real-time protection)         │
│  Rustinel EDR     (YARA rules via ETW, process-start hook)  │
│  Wazuh Agent      (event forwarding to SIEM)                │
│  Sysmon64         (process, network, registry telemetry)    │
└─────────────────────────────────────────────────────────────┘
```

---

## Attack Timeline

| Time (UTC) | Event | Detection |
|---|---|---|
| 14:05:04 | System boot | — |
| 14:07:35 | `loader2.exe` executed — dns_agent_bof.c COFF loaded in-process via DNS-over-TCP | **None** |
| ~14:07:xx | `uacbybass regshellcmd` BOF executed via DNS C2 | **Defender kills process** |
| 14:09:42 | `uacbybass sspi` BOF — SYSTEM beacon connects | **None** |
| ~14:10:xx | `getsystem token` BOF — SYSTEM impersonation on thread | **None** |
| ~14:10:xx | Credential dump BOF | **None** |
| 14:10:01 | Blue team acquires memory image via go-winpmem | — |

---

## Tools Used

| Tool | Purpose |
|---|---|
| Adaptix C2 v1.2.0 | C2 framework |
| SysWhispers3 (jumper) | Indirect syscall stubs |
| Volatility 3 (v2.28.1) | Memory forensics |
| go-winpmem | Live memory acquisition |
| Process Monitor (Sysinternals) | Loader activity tracing |
| Wazuh | SIEM / alert collection |
| Rustinel | YARA-based EDR (Rust) |

---

## Sections

- [DNS C2 Infrastructure](01-dns-c2-infrastructure/README.md)
- [Evasion Loader Technical Analysis](02-evasion-loader/README.md)
- [MITRE ATT&CK Mapping](03-mitre-attack/README.md)
- [Detection and Logging Analysis](04-detection-logging/README.md)
- [Memory Forensics](05-memory-forensics/README.md)

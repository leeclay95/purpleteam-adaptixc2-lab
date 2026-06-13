# DNS C2 BOF Output Fix — Root Cause Analysis

**Date:** 2026-05-27  
**Symptom:** BOF tasks dispatched successfully to the DNS agent, but no output ever appeared in the Adaptix GUI. Task stayed pending indefinitely.  
**Same BOFs worked correctly on the Gopher (HTTP) agent.**

---

## Symptom

After implementing the BOF loader (`bof_loader.c` + `beacon_api.c`) and wiring it into the DNS agent plugin, every BOF command behaved identically:

1. Task was created in the GUI — confirmed delivered to agent (6.55 KB task payload observed)
2. Agent heartbeat continued normally
3. No output ever appeared in the GUI
4. Task remained in "pending" state forever

Shell commands (`shell whoami`, `shell ipconfig`, `shell systeminfo`) all worked correctly through the same DNS channel. The same BOF binaries ran fine on the Gopher agent.

---

## What Was Ruled Out

### Thread race condition (CreateThread + WaitForSingleObject)

The original BOF executor launched `bof_execute` in a new thread and waited for it. The theory was that the main-thread heap allocations in `g_bof_output` (via `HeapAlloc`/`HeapReAlloc` in `beacon_api.c`) were racing with the spawned thread.

**Verdict: Not the cause.** Windows heap functions are thread-safe by design. However, the code was simplified to call `bof_execute` synchronously from the main agent thread anyway. Did not fix the symptom.

### Multi-chunk output reassembly / null byte truncation

Theory: `bof_execute` returns output that contains null bytes. `string(output)` in Go's `ProcessData` truncates at the first null. The `output_len` field in the wire header might disagree with what actually gets populated.

**Verdict: Not the cause.** The agent sends output bytes with an explicit length field (`[4] output_len LE`). The Go code reads exactly `outputLen` bytes regardless of null content. The `memcpy` in `BeaconOutput` happens before any `memset` in the BOF. No truncation occurs.

### BOF binary format / args packing

Theory: The args pack format sent by the DNS agent differed from what the Gopher agent sends, causing the BOF to crash or fail silently.

**Verdict: Not the cause.** The tested BOFs (whoami suite) take no arguments. `args_len = 0`, `bof_args` points to a valid-but-unused location. BOFs that don't parse args are unaffected by this.

### Symbol resolution failures

Theory: `MSVCRT$calloc`, `MSVCRT$free`, etc. could not be resolved in the MinGW-compiled binary, causing `bof_execute` to fail at the relocation phase and return an error message.

**Verdict: Not confirmed as the root cause.** The `resolve_import` function handles MSVCRT with ucrtbase.dll fallback. More importantly, if symbol resolution failed, `goto cleanup` would run and return a `BeaconPrintf` error message (e.g. `"BOF: unresolved: MSVCRT$calloc\n"`). That error output would have been sent back and the task would have completed with an error — not stayed pending forever. A pending task with zero output means `send_task_output` was never called at all.

---

## Actual Root Cause: miekg/dns TXT Record 255-byte Limit

### How task delivery works

When the agent sends a heartbeat DNS query, the server responds with a TXT record. For the heartbeat response:

1. Server calls `TsAgentGetHostedTasks(agentId, 65535)` → gets packed task bytes
2. Packs into a `RESP_TASKS` frame: `[0x02][data_len_lo][data_len_hi][taskBytes...]`
3. XOR-encrypts the frame bytes
4. Base32-encodes the result
5. Puts the base32 string in a `dns.TXT` record as `Txt: []string{txtData}`
6. Calls `w.WriteMsg(m)` to send the DNS response

### Why shell tasks always worked

A shell command like `shell whoami` produces a task payload of roughly 22 bytes:

```
[1 num_tasks][8 task_id][1 cmd_type=0x01][4 cmd_data_len=8][2 len][6 "whoami"]
= 22 bytes
```

After XOR + base32 encoding: **~36 characters**. Well under 255.

### Why BOF tasks silently failed

A 6.55 KB BOF produces a task payload of roughly 6,729 bytes:

```
[1 num_tasks][8 task_id][1 cmd_type=0x02][4 cmd_data_len][4 bof_len][~6500 bof bytes][4 args_len]
≈ 6,729 bytes
```

After XOR + base32 encoding: **~10,767 characters**.

### The miekg/dns failure

In miekg/dns v1.1.69 (and all versions), `packTxtString` enforces the DNS RFC 1035 limit that each character-string in a TXT RDATA is at most 255 bytes:

```go
// types.go, packTxtString
if l > 255 {
    return offset, &Error{err: "string exceeded 255 bytes in txt"}
}
```

When the server puts 10,767 characters into `Txt: []string{txtData}`, `m.Pack()` returns this error. `WriteMsg` returns the error **without writing anything** to the TCP connection.

The agent is waiting on `recv()` with an 8-second `SO_RCVTIMEO`. After 8 seconds, the socket times out. The agent's `dns_query()` function closes the socket and returns `NULL`.

The main loop sees no response from the heartbeat, treats it as "no tasks", and goes back to sleep. The BOF task stays pending forever. No `send_task_output` is ever called because the agent never received the task in the first place.

### Why this was hard to spot

- Shell tasks are always tiny → always under 255 chars → always worked → "pipeline confirmed working"
- The agent didn't crash → continued heartbeating normally → looked like a BOF execution problem
- The failure was completely silent on both ends: no error logged, no SERVFAIL sent, no partial data

---

## The Fix

**File:** `AdaptixServer/extenders/BeaconDNS/dns_server.go`  
**Function:** `handleDNS`

Split the base32 TXT response into 255-character chunks before building the DNS record. The agent's `dns.c` already correctly concatenates multiple character-strings from a TXT RDATA (lines 291-305), so no agent-side changes are needed.

### Before

```go
rr := &dns.TXT{
    Hdr: dns.RR_Header{
        Name:   q.Name,
        Rrtype: dns.TypeTXT,
        Class:  dns.ClassINET,
        Ttl:    0,
    },
    Txt: []string{txtData},
}
```

### After

```go
// DNS TXT character-strings are limited to 255 bytes each (RFC 1035).
// miekg/dns returns an error and writes nothing if any single Txt
// element exceeds 255 bytes.  Split the base32 response into chunks so
// that large task payloads (e.g. BOF binaries) are delivered correctly.
var txtChunks []string
for len(txtData) > 0 {
    n := 255
    if n > len(txtData) {
        n = len(txtData)
    }
    txtChunks = append(txtChunks, txtData[:n])
    txtData = txtData[n:]
}

rr := &dns.TXT{
    Hdr: dns.RR_Header{
        Name:   q.Name,
        Rrtype: dns.TypeTXT,
        Class:  dns.ClassINET,
        Ttl:    0,
    },
    Txt: txtChunks,
}
```

A 10,767-char base32 string becomes 42 TXT character-strings of ≤255 chars each. The DNS-over-TCP response is approximately 11 KB — well within the 65,535-byte TCP DNS length field and the agent's 65,536-byte receive buffer.

---

## Why the Agent Side Was Already Correct

The agent's `dns_query()` in `dns.c` concatenates all character-strings from the TXT RDATA before base32-decoding:

```c
while (rd_off < rd_end) {
    uint8_t slen = resp_buf[rd_off++];
    if (rd_off + slen > rd_end) break;
    if (txt_raw_len + (int)slen <= resp_len) {
        memcpy(txt_raw + txt_raw_len, resp_buf + rd_off, slen);
        txt_raw_len += (int)slen;
    }
    rd_off += slen;
}
```

This correctly handles split TXT records per RFC 1035. The `txt_raw` buffer is allocated at `resp_len` bytes (up to 65,536), large enough for any response. The comment in `dns.c` even anticipated large payloads:

```c
/* Maximum DNS wire-format packet we will ever send or receive.
 * BOF responses are base32-encoded; a 10 KB BOF produces ~16 KB on the wire. */
#define DNS_BUF_SIZE 65536
```

The buffer sizing was right. The TXT splitting on the server side was the missing piece.

---

## Rebuild and Deploy

```bash
cd /home/kali/AdaptixC2
sudo chown -R kali:kali dist/
make server-ext

sudo cp dist/adaptixserver                  AdaptixServer/server-dist/adaptixserver
sudo cp -r dist/extenders/BeaconDNS         AdaptixServer/server-dist/extenders/
sudo cp -r dist/extenders/dns_agent         AdaptixServer/server-dist/extenders/

sudo pkill -f adaptixserver
cd AdaptixServer/server-dist && sudo ./adaptixserver -profile profile.yaml
```

No C agent (`dns_agent.exe`) rebuild required — the fix is entirely server-side.

---

## Key Lesson

**The DNS TXT 255-byte character-string limit applies per element, not per record.**  
A single TXT record can contain many character-strings concatenated in the RDATA, but each individual string is capped at 255 bytes. Libraries enforce this strictly. Any DNS C2 transport that returns variable-length data in TXT records must chunk its response into ≤255-byte segments on the server side and concatenate on the client side.

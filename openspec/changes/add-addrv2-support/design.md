## Context
BIP 155 replaces the fixed 16-byte address format in `addr` messages with a variable-length format that includes an explicit network ID byte. This enables addresses for networks beyond IPv4/IPv6 (Tor v3, I2P, CJDNS). The node already has a persistent peer database using 16-byte IPv6-mapped addresses; this change extends it to recognize addrv2 while keeping the address book focused on connectable (IPv4/IPv6) addresses.

## Goals / Non-Goals
- Goals: parse and handle addrv2 messages, negotiate sendaddrv2, relay addresses in correct format per peer capability, store IPv4/IPv6 addresses from addrv2 in the address book
- Non-Goals: connecting to Tor/I2P/CJDNS peers, storing non-IPv4/IPv6 addresses in the peer database, implementing addrv2-specific peer diversity logic

## Decisions

### Network ID Constants
Define constants and expected address sizes matching BIP 155:
```
+addrv2-net-ipv4+   = 1  (4-byte address)
+addrv2-net-ipv6+   = 2  (16-byte address)
+addrv2-net-torv2+  = 3  (10-byte, deprecated — recognized but discarded)
+addrv2-net-torv3+  = 4  (32-byte address)
+addrv2-net-i2p+    = 5  (32-byte address)
+addrv2-net-cjdns+  = 6  (16-byte address)
```

An address size map (hash table) maps each known network ID to its expected byte length. Entries with known network IDs but wrong address lengths are skipped (read past, return NIL). Entries with unknown network IDs are also skipped.

### ADDRv2 Entry Format
Each entry in an addrv2 message:
```
[4 bytes]      timestamp (uint32 LE)
[compact-size] services
[1 byte]       network ID
[compact-size] address length
[variable]     address bytes
[2 bytes]      port (uint16 big-endian)
```

Key differences from addr v1:
- Services use compact-size encoding (1-9 bytes) instead of fixed uint64
- Address has explicit network ID + variable length instead of fixed 16 bytes
- Maximum address size: 512 bytes
- Maximum entries per message: 1000 (same limit as addr v1)

### sendaddrv2 Negotiation
- Send empty `sendaddrv2` message after VERSION, before VERACK (same slot as other feature negotiation messages)
- On receiving `sendaddrv2` from peer, set `peer-wants-addrv2` to T
- If received after VERACK, ignore (Bitcoin Core disconnects, but we'll be lenient)

### Address Book Integration
- Only IPv4 (net ID 1) and IPv6 (net ID 2) addresses are added to the address book
- IPv4 addresses from addrv2 are converted to IPv4-mapped IPv6 using existing `ipv4-to-mapped-ipv6`
- IPv6 addresses are stored directly (already 16 bytes)
- All other network types are parsed but silently discarded
- Same 3-hour timestamp plausibility filter as existing addr handling

### Relay Format Selection
When relaying addresses to peers:
- Peers with `wants-addrv2 = T`: send `addrv2` message
- Peers without: send `addr` (v1) message
- For now, only relay IPv4/IPv6 addresses (the only ones we store)

### Persistence Compatibility
The peers.dat format is unchanged — it already stores 16-byte IPv6-mapped addresses. IPv4 addresses from addrv2 are mapped to this format before storage, so no migration is needed.

## Risks / Trade-offs
- Discarding Tor/I2P/CJDNS addresses means we can't relay them to peers that want them — acceptable since we can't connect to those networks anyway
- Being lenient on sendaddrv2-after-VERACK differs from Bitcoin Core's strict disconnect — keeps things simple and doesn't harm us
- Compact-size services encoding in addrv2 entries already supported by existing `read-compact-size`

## Open Questions
- None — design follows BIP 155 spec closely and reuses existing infrastructure

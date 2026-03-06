## 1. Serialization

- [x] 1.1 Add BIP 155 network ID constants to `src/serialization/messages.lisp` — `+addrv2-net-ipv4+` (1), `+addrv2-net-ipv6+` (2), `+addrv2-net-torv2+` (3, deprecated), `+addrv2-net-torv3+` (4), `+addrv2-net-i2p+` (5), `+addrv2-net-cjdns+` (6), and address size map (hash table mapping network ID to expected byte length)
- [x] 1.2 Implement `read-net-addr-v2` in `src/serialization/messages.lisp` — reads timestamp (uint32 LE), services (compact-size), network ID (uint8), address length (compact-size), address bytes (variable), port (uint16 big-endian); returns (VALUES net-addr timestamp network-id) for known networks with correct address length; skips entries with unknown network IDs or mismatched address lengths by reading past their bytes and returning NIL
- [x] 1.3 Implement `make-sendaddrv2-message` in `src/serialization/messages.lisp` — serializes empty `sendaddrv2` message (header only, zero-length payload)
- [x] 1.4 Implement `write-net-addr-v2` in `src/serialization/messages.lisp` — serializes a single addrv2 entry (compact-size services, network ID, address bytes, port) for building addrv2 messages
- [x] 1.5 Implement `make-addrv2-message` in `src/serialization/messages.lisp` — builds complete addrv2 message from list of address entries
- [x] 1.6 Update `src/package.lisp` — export new serialization symbols

## 2. Networking

- [x] 2.1 Add `wants-addrv2` slot (boolean, default NIL) to `peer` struct in `src/networking/peer.lisp`
- [x] 2.2 Send `sendaddrv2` message in `perform-handshake` after sending VERSION, before receiving VERSION response
- [x] 2.3 Handle incoming `sendaddrv2` in the handshake loop — set `peer-wants-addrv2` to T
- [x] 2.4 Implement `handle-addrv2` in `src/networking/protocol.lisp` — parse addrv2 entries (limit 1000 per message), filter IPv4/IPv6 with plausible timestamps (within 3 hours), convert IPv4 to mapped-IPv6, add to address book; skip entries with unknown/unsupported network IDs
- [x] 2.5 Add `"addrv2"` case to `handle-message` in `src/networking/protocol.lisp` — delegates to `handle-addrv2`; add `"sendaddrv2"` case as a no-op (sendaddrv2 is only meaningful during handshake, silently ignored post-handshake)
- [x] 2.6 Update address relay to use addrv2 format for peers with `wants-addrv2 = T` and addr (v1) for others — modify or extend relay logic in `src/networking/protocol.lisp`
- [x] 2.7 Update `src/package.lisp` — export new networking symbols (`peer-wants-addrv2`)

## 3. Tests

- [x] 3.1 Create `tests/addrv2-tests.lisp` with the following test cases:
  - Parse addrv2 entry with IPv4 address (network ID 1, 4-byte addr)
  - Parse addrv2 entry with IPv6 address (network ID 2, 16-byte addr)
  - Parse addrv2 entry with Tor v3 address (network ID 4, 32-byte addr) — parsed but not stored in address book
  - Skip unknown network ID gracefully (read past bytes without error)
  - Skip entry with mismatched address length for known network ID
  - Compact-size services field round-trip
  - Build and parse sendaddrv2 message (empty payload)
  - Build and parse addrv2 message with multiple entries
  - Handle addrv2 adds only IPv4/IPv6 to address book
  - IPv4 from addrv2 converted to mapped-IPv6 correctly
- [x] 3.2 Update `tests/package.lisp` — add `:addrv2-tests` suite
- [x] 3.3 Update `bitcoin-lisp.asd` — add `addrv2-tests` component

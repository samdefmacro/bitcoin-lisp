# Change: Add ADDRv2 Support (BIP 155)

## Why
The node currently only handles `addr` (v1) messages, which encode all addresses as 16-byte IPv6-mapped fields. BIP 155 introduces `addrv2` with variable-length addresses and explicit network IDs, enabling the protocol to carry Tor v3, I2P, and CJDNS addresses. Supporting addrv2 is necessary for modern peer discovery — most Bitcoin Core nodes now send addrv2 by default, so without it we miss addresses advertised by those peers.

## What Changes
- **sendaddrv2 negotiation**: Send `sendaddrv2` during handshake (after VERSION, before VERACK) and track which peers support it
- **addrv2 message parsing**: New `read-net-addr-v2` deserializer supporting variable-length addresses with network ID and compact-size services
- **addrv2 message handling**: `handle-addrv2` feeds IPv4/IPv6 addresses into the address book (same filtering as `handle-addr`); unknown network types are silently skipped
- **Peer tracking**: `peer` struct gains a `wants-addrv2` flag set when the remote peer sends `sendaddrv2`
- **addr relay**: When relaying addresses, use `addrv2` format for peers that negotiated it, `addr` for others

## Impact
- Affected specs: networking (MODIFIED Version Handshake, Peer Discovery, Message Receiving; ADDED ADDRv2 Message Support), serialization (ADDED ADDRv2 Serialization)
- Affected code: `src/networking/peer.lisp` (handshake, peer struct), `src/networking/protocol.lisp` (handle-addrv2, handle-message, relay), `src/serialization/messages.lisp` (addrv2 parsing), `src/package.lisp`

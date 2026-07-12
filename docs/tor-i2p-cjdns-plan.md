# Tor / I2P / CJDNS Transports — Implementation Plan

Date: 2026-07-10. Status: **P0 DONE (PR #248, SOCKS5 outbound); P1 DONE
(tor-address-layer branch: BIP155 address layer, onion/i2p codecs, addrman
netgroups, peers.dat v4 + anchors v2 migrate-on-load, -onlynet/-cjdnsreachable,
dialable-network-p filter). P2+ not started — nothing dials non-IP nets yet.**
Reference: Bitcoin Core `refs/bitcoin/` @ d3056bc (v30-dev). Researched via 2 agents
(Core SOCKS5/torcontrol/SAM/CJDNS at byte level; our networking layer).

## 1. Framing

Privacy-network support decomposes into cleanly separable slices, in descending
value-per-effort: **SOCKS5 outbound proxy** (all outbound through Tor/any SOCKS5 — most of the
privacy win), **address-layer generalization** (BIP155 networks representable at all),
**onion dialing**, **Tor control** (inbound onion service), **I2P SAM**, **CJDNS** (config-only).
Everything is our-node-local policy/plumbing — no consensus, no relay-policy divergence.

Two hard prerequisites discovered in our tree:
1. **The live-loop wiring gap** (see erlay-plan.md §2 — verified): addr/addrv2 ingestion and
   relay are inert in production because `dispatch-ibd-message` never passes
   `:address-book`/`:peers`. Gossiped onion/i2p addresses would go nowhere. Fix first.
2. **The address layer is IPv4/IPv6-only by type**: `peer-address-ip` is hard-typed
   `(simple-array (unsigned-byte 8) (16))` (peerdb.lisp:15-16); the addrv2 decoder parses
   TORV3/I2P/CJDNS correctly but **deliberately returns NIL** for them ("valid parse but not
   storable", messages.lisp:696-698); the encoder errors on non-IP (:727); addrman keys are
   `ip16‖port` (peerdb.lisp:42-48); anchors.dat stores bare IP strings without port
   (node.lisp:1561-1576); `string-to-ip-bytes` parses dotted-quad only (peerdb.lisp:87-92) and
   `ip-netgroup` is IPv4-only (protocol.lisp:38-55) — IPv6 is already second-class.

Good news: **the transport stack is socket-agnostic**. `make-tcp-connection`
(connection.lisp:66-84) is the single outbound `usocket:socket-connect` choke point (the v1
fallback re-dial at peer.lisp:359 also goes through it); v1 and BIP324-v2 transports operate
purely on `connection-stream`. A SOCKS5 layer inside `make-tcp-connection` needs **zero changes
elsewhere**, and BIP324 works through the tunnel unchanged.

## 2. Core spec essentials (what we port)

### SOCKS5 (netbase.cpp:392-520)
Greeting `05 02 00 02` (with auth) / `05 01 00`; RFC1929 sub-negotiation
`01 ulen user plen pass` → expect `01 00`; CONNECT `05 01 00 03 len name port_hi port_lo` —
**ATYP is always 0x03 DOMAINNAME** (proxy resolves; .onion/.b32.i2p/hostnames never touch local
DNS); reply `05 00 00 atyp` + skip BND.ADDR/PORT; Tor extended error codes 0xF0-0xF7. Every
handshake step under a 20s recv timeout, interruptible. **Stream isolation**
(netbase.cpp:748-810): per-process random 8-byte hex prefix; per-connection
username=password=`prefix+counter` (`-proxyrandomize`, default on). Config: `-proxy=addr[:9050]`
(sets all nets + name proxy), `-onion=` overrides Tor only, per-network `=onion/=cjdns` suffixes;
`-proxy` soft-sets `-listen=0 -discover=0`; with a name proxy, DNS-seed hostnames become
peer dials through the proxy instead of getaddrinfo (net.cpp:2353-2358).

### Onion-v3 codec (netaddress.cpp:185-261)
Internal repr = 32-byte ed25519 pubkey (BIP155 id 4, 32 bytes). `.onion` =
lowercase-base32(pubkey ‖ checksum2 ‖ 0x03), exactly 56 chars; checksum =
**SHA3-256**(".onion checksum" ‖ pubkey ‖ 0x03)[0:2] — SHA3, not SHA256 (ironclad has SHA3 —
no new dependency). Legacy v1 addr serialization = 16 zero bytes (these nets exist only in
addrv2 gossip + v2 disk formats).

### Tor control (torcontrol.cpp)
Plain CRLF line protocol on 127.0.0.1:9051; replies `NNN[-+ ]text`; Core never uses SETEVENTS.
Sequence: `PROTOCOLINFO 1` → parse AUTH METHODS + COOKIEFILE → auth: `-torpassword` ⇒
`AUTHENTICATE "pass"`; NULL ⇒ bare; else **SAFECOOKIE**: read 32-byte cookie, send
`AUTHCHALLENGE SAFECOOKIE hex(client_nonce32)`, verify server HMAC-SHA256 with key
`"Tor safe cookie authentication server-to-controller hash"` over cookie‖clientNonce‖serverNonce,
reply `AUTHENTICATE hex(HMAC(...controller-to-server...))` (torcontrol.cpp:504-548). Then
if `-onion` unset: `GETINFO net/listeners/socks` → auto-set the onion proxy. Then
`ADD_ONION <key> Port=<chain-default-port>,127.0.0.1:<port+1>` where key = saved
`onion_v3_private_key` file content (verbatim `ED25519-V3:<b64>` string) or `NEW:ED25519-V3`;
parse ServiceID (56-char) + PrivateKey; persist key; `AddLocal(service)`. Control connection
stays open for the service's lifetime; reconnect backoff 1.0s ×1.5 cap 600s. Activation:
`-listenonion` (default true when listening).

### I2P SAM 3.1 (i2p.cpp)
Newline-terminated line protocol to `-i2psam` (default port 7656); i2p-base64 uses `-~` for
`+/`. Per-socket `HELLO VERSION MIN=3.1 MAX=3.1`. Keys: `DEST GENERATE SIGNATURE_TYPE=7`;
persist binary to `i2p_private_key`. Persistent session (needed for inbound):
`SESSION CREATE STYLE=STREAM ID=<10hex> DESTINATION=<b64 privkey> i2cp.leaseSetEncType=4,0
inbound.quantity=3 outbound.quantity=3` — **session dies when its control socket closes**.
Outbound: fresh socket + HELLO + `NAMING LOOKUP NAME=x.b32.i2p` + `STREAM CONNECT ID=
DESTINATION= SILENT=false`; on OK **that same socket becomes the peer stream**. Inbound:
`STREAM ACCEPT`; first line after OK = connecting peer's destination, subsequent bytes are P2P
data — line reads must never over-consume (Core uses MSG_PEEK; in Lisp read byte-by-byte to
`\n`). Address = base32(SHA256(raw destination)) + ".b32.i2p" (52 chars); port always 0;
transient sessions (`DESTINATION=TRANSIENT`) for outbound-only mode, pooled (cap 10). Config:
`-i2psam`, `-i2pacceptincoming` (default true).

### CJDNS
**No transport code at all**: plain IPv6 in fc00::/8 via the cjdroute TUN. Port =
`-cjdnsreachable` flag + retag IPv6 addrs with first byte 0xFC to NET_CJDNS at every ingress
(`MaybeFlipIPv6toCJDNS`, netbase.cpp:942-949) so they count as routable + bucket separately.
BIP155 id 6, 16 bytes.

### Plumbing
Reachability set + `-onlynet` (restricts automatic outbound only); per-target-network proxy
lookup in the connect path; addrman groups: Tor/I2P bucket by `[net, addr[0]|0x0F]`, CJDNS
`[net, addr[0], addr[1]|0x0F]` (netgroup.cpp:52-77); default ports: onion = chain default, I2P
= 0; onion inbound arrives on a local listener (default `127.0.0.1:port+1`) that Tor forwards
to, tagged don't-advertise.

## 3. Staged milestones

| Phase | Deliverable | Size |
|-------|-------------|------|
| **P0** | **SOCKS5 outbound**: socks5 client module (byte-exact handshake, RFC1929, DOMAINNAME-always, timeouts); proxy config (`-proxy`/`-onion`/`-proxyrandomize`, per-network table); wrap `make-tcp-connection`; stream-isolation credentials; no-local-DNS discipline when proxied (dial DNS-seed hostnames through the proxy; `resolve-dns-seed`'s `get-host-by-name` bypassed). Works today for clearnet-over-Tor with zero address-layer changes | M |
| **P1** | **Address layer generalization**: network-typed address record (net-id + var-len bytes) replacing the hard 16-byte IP; addrv2 decode/encode for TORV3/I2P/CJDNS (codec sizes already tabled, messages.lisp:652-661); onion-v3 + b32.i2p codecs (SHA3 checksum); addrman keying/net-groups/peers.dat v4; anchors.dat format (+port); `-onlynet` reachability. Prereq: live-loop addr wiring fix (erlay-plan P0) | M-L |
| **P2** | **Outbound onion dialing** (P0+P1): dial `<56char>.onion:8333` via SOCKS5 DOMAINNAME; outbound-selection awareness of networks (per-network proxy pick; skip unreachable nets); **CJDNS** (fc00::/8 retag + `-cjdnsreachable`) — requires finishing IPv6 second-class fixes (`string-to-ip-bytes`, `ip-netgroup`) | S-M |
| **P3** | **Tor control / inbound onion**: torcontrol client thread (line protocol, SAFECOOKIE HMAC, ADD_ONION, key persistence, backoff); local onion listener on port+1; advertise the onion address (needs minimal self-advertisement — currently we advertise nothing: dummy addr_from, messages.lisp:254-255; ties into the deferred self-advertisement item) | M |
| **P4** | **I2P SAM**: session manager (persistent + transient), STREAM CONNECT/ACCEPT, key persistence, `-i2psam`/`-i2pacceptincoming`, careful line reader | M-L |

Each phase independently shippable; P0 alone is the classic "run your node over Tor" feature.
Suggested order: P0 → P1 → P2 → P3, P4 optional/last (I2P peers are scarce; value is niche).

## 4. Effort & risk

~10-15 PRs total; P0 ≈ 2 PRs. Risks are all local-plumbing, not protocol: (a) the address-layer
refactor (P1) touches addrman/peers.dat/eviction/netgroup diversification — needs the same
care as any persistence format bump (version the file, migrate on load); (b) proxied dialing
changes connect latency/timeout behavior — keep the 10s connect timeout but Core's 20s SOCKS
handshake timeouts on top; (c) torcontrol/SAM are long-lived side connections needing their own
reconnect supervision (pattern exists: sync-thread loops). Testing: SOCKS5 against a local Tor
daemon on the test server (regtest-on-server rule applies); byte-level unit tests for codecs
(onion checksum vectors from Core), handshake state machines testable against canned replies.
FASL clear on deploy (peer-address/peer struct changes).

## 5. Open decisions

1. Scope: P0 only (Tor-outbound), or through P3 (inbound onion service)? P4 (I2P) worth it?
2. peers.dat/anchors format bump strategy: migrate-on-load (recommended) vs fresh start.
3. `-listen` interaction: Core soft-disables listen under `-proxy`; keep that default?
4. Do we also send `getaddr` (we currently never do — addrman fills only passively; small
   adjacent fix that matters much more once onion addrs exist)?

## 6. Source anchors

Core: netbase.{h,cpp} (Socks5 392-520, proxy tables 33-35/700-746, isolation 748-810, timeouts
40-41, no-DNS 144-156); torcontrol.{h,cpp} (protocol 88-205, parsing 214-324, auth 464-624,
ADD_ONION 429-462/476-481, key file 340-345/450-453/665-668, backoff 626-663); netaddress.{h,cpp}
(BIP155 ids 263-270, SetNetFromBIP155Network 49-98, onion codec 185-261/569-578, CJDNS 432-434);
i2p.{h,cpp} (grammar 293-340, sessions 408-459, connect 222-279, accept 158-220, dest→addr
90-104); netgroup.cpp:19-107; net.cpp (ConnectNode proxy branch 372-552, I2P accept thread
3163-3204, default ports 3395-3404, onion binds 3437-3455/1768-1772); init.cpp (option wiring
1529-1551, 1696-1801, 2114-2255). Ours: connection.lisp:66-84 (choke point), peer.lisp:359
(fallback re-dial), messages.lisp:644-730 (addrv2 codec), peerdb.lisp:11-92 (address record),
addrman.lisp:42-115 (keys/groups), node.lisp:1561-1600 (anchors), protocol.lisp:25-36 (DNS leak),
:38-55 (netgroup), config.lisp:344-414 (option surface).

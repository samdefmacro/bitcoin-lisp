# GA11 dimension 10 - second reader: the P2P transport and liveness seam

Survey only: nothing under `src/` or `tests/` was changed. Findings are in
`dim-p2p-liveness.json`; this note records what was read, what was run, and what
was left for another dimension.

Oracle: Bitcoin Core `d3056bc` in `refs/bitcoin/`. Container: this worktree's warm
image (`bitcoin-lisp-sbcl:2.6.5-4`); every probe below ran through
`scripts/dev.sh eval`.

## The live observation, answered first

Both production nodes log 50-70 `Peer <addr> connection dead - disconnecting`
lines an hour, the same addresses recurring, on builds before and after this
week's fixes. The answer has two halves and neither is a health check gone wrong.

1. **That line is a reap, not a verdict.** `handle-peer-fin`
   (`src/networking/ibd.lisp:1591`) fires on one condition -
   `(not (connection-connected conn))` - for a peer in any state. Nothing sets
   that slot except a socket that already failed: `%abandon-receive` (EOF, an
   I/O error, or a give-up that had consumed bytes), a failed send, or one of
   the three v2-transport failures. Every one of our own liveness rules
   (`check-peer-health`, `connection-receive-expired-p`,
   `retry-timed-out-requests`, `consider-peer-eviction`) calls `disconnect-peer`
   directly and logs a *different* line. So each of those 50-70 lines is a
   socket the remote closed, or a write of ours that failed - and the line
   carries no reason code to tell which, at WARN where Core logs the same event
   at `LogDebug(BCLog::NET)`.

   Executed to close this off: a real loopback TCP peer driven through
   `drain-and-reap-peer` fifty times with nothing sent stayed
   `:READY / connected T`. We do not declare a quiet-but-alive peer dead.

2. **The repetition is our dialer.** `replace-disconnected-peers` walks
   `node-known-addresses` - a snapshot of `max-peers * 8` addrman picks taken
   once at start-up (`src/node/peers.lisp:541`) and never refreshed - in fixed
   order, with no last-try cooldown and no back-off. `maintain-peers` runs once
   per sync pass, so a peer that drops us is redialed within ~30 seconds,
   forever. Core re-samples addrman on every attempt and skips any address tried
   in the last 10 minutes (`net.cpp:2839-2841`).

Three of the other findings feed the same loop: one stall round disconnects a
peer holding a full block window (`d2396ac9`), any handler error disconnects the
peer (`50dc142d`), and our height-based eviction - which Core does not have -
drops inbound and `-addnode` peers on sight (`d49c3f1b`).

## What was compared

| ours | Core |
|---|---|
| `handle-peer-fin`, `drain-and-reap-peer` (`ibd.lisp:1591`, `:1740`) | `net.cpp:2204-2218` SocketHandlerConnected |
| `check-peer-health`, `check-handshake-timeout` (`peer.lisp:1479`, `:1492`) | `MaybeSendPing` (`net_processing.cpp:5487-5510`), `InactivityCheck` (`net.cpp:2008-2059`) |
| `receive-bytes-resumable`, `receive-bytes`, `%abandon-receive`, `%receive-gave-up` (`connection.lisp:718`, `:837`, `:645`, `:659`) | `Transport::ReceivedBytes`, `CNode::ReceiveMsgBytes` |
| `send-bytes`, `%flush-send-queue-locked`, `connection-send-paused-p/-stalled-p` | `PushMessage`, `SocketSendData`, `fPauseSend`, "socket sending timeout" |
| `%v2-recv-packet` and its teardown (`v2-transport.lisp:139`) | `V2Transport::ReceivedBytes`, `CloseConnection` |
| `receive-message` / `receive-message-blocking` framing (`peer.lisp:576`, `:684`) | `net.cpp:678-683`, `:752-755`, `:819-825` |
| `safely-dispatch-peer-message` (`ibd.lisp:1723`) | `ProcessMessage`'s catch (`net_processing.cpp:5283-5287`) |
| `retry-timed-out-requests`, `compute-block-download-timeout`, `release-orphaned-in-flight`, `request-blocks-from-peers` | SendMessages' stalling / `BLOCK_DOWNLOAD_TIMEOUT` / headers-sync-timeout block (`net_processing.cpp:6093-6155`) |
| `consider-chain-sync-eviction`, `evict-extra-outbound-peers` (`ibd.lisp:2377`, `:2456+`) | `ConsiderEviction` (`:5292`), `EvictExtraOutboundPeers` (`:5352`) |
| `consider-peer-eviction` (`peer.lisp:1565`) | no counterpart in Core |
| `record-misbehavior`, `ban-peer`, `disconnect-peer` | `MaybeDiscourageAndDisconnect` (`:5171`), `FinalizeNode` |
| `replace-disconnected-peers`, `connect-to-peers`, `maintain-block-relay-peers`, `%dial-outbound-peer`, `do-feeler-connection` | `ThreadOpenConnections` (`net.cpp:2760-2900`), `ConnectNode` |
| `merge-inbound-peers`, `evict-least-valuable-inbound`, `run-inbound-listener` | `eviction.cpp`, `AcceptConnection` |
| `perform-handshake`, `perform-inbound-handshake`, `%await-verack`, `send-post-handshake-messages` | `net_processing.cpp:3611-3744`, `:3822`, `:3928-3973` |
| block-relay handlers: `ping`, `pong`, `sendheaders`, `feefilter`, `inv` (block arm), `headers`, `block`, `getheaders` | the matching `ProcessMessage` branches |

## Probes that were run

1. **`handle-peer-fin` is state-blind.** Dead connection + `:ready` -> reaped;
   dead + `:handshaking` -> also reaped; live connection -> not reaped.
2. **Quiet-but-alive peer.** A real loopback TCP pair, 50 `drain-and-reap-peer`
   passes, nothing sent: `:READY`, connected, no read in progress, not expired.
3. **Redial cadence.** `%dial-outbound-peer` stubbed to record and fail; five
   `replace-disconnected-peers` sweeps produced 20 dials to the same 4
   addresses in the same order. The node had **no address book at all**, which
   proves the refill path never calls addrman.
4. **Block-timeout budget.** 16 in-flight blocks (the per-peer cap) backdated
   200s, one `retry-timed-out-requests` call: counter 0 -> 16 against a budget
   of 15, peer `:DISCONNECTED` after **one** stall round.
5. **Short payloads.** `pong`/0 bytes, `pong`/4, `ping`/0, `feefilter`/3,
   `sendcmpct`/1 each raised `INVALID-ARRAY-INDEX-ERROR` and each was
   disconnected by `safely-dispatch-peer-message`. Core has a named,
   non-punishing branch for exactly the `pong` case.
6. **Ping / inactivity decisions** on a real socket: never pinged -> ping;
   119s -> ok; 121s -> ping; outstanding 1199s -> ok; 1201s -> disconnect;
   silent 25 min but answering pings -> ok; send queue stalled 21 min ->
   disconnect; **empty queue, nothing sent for 21 min -> ok** (Core disconnects).
7. **Partial-message reaper.** 12 of 24 header bytes then silence: in progress,
   not expired; at 299s not expired, at 301s expired, next drain -> disconnected.
8. **Height eviction and the disconnect hook.** `consider-peer-eviction` evicts
   inbound and manual peers exactly like outbound ones; `disconnect-peer` fires
   `*peer-disconnect-hook*` while `record-misbehavior` and `ban-peer` do not.

## Verified clean - deliberately not reported

- The ping interval (120s) and timeout (1200s) are Core's `PING_INTERVAL` and
  `TIMEOUT_INTERVAL`, and both boundaries behave correctly.
- The pump does not disconnect a quiet-but-alive peer.
- The post-verack disconnects for `sendaddrv2` / `wtxidrelay` / `sendtxrcncl`
  are present, correctly placed, and carry Core's exact log wording.
- `relay-transaction` already refuses to announce to an `fRelay=0` peer (which
  is what Core disconnects for), and `handle-inv` already implements Core's
  `reject_tx_invs` disconnect.
- The headers count is bounded at `+max-headers-count+` inside the parser.
- The `consider-chain-sync-eviction` port is faithful apart from Core's
  `state.fSyncStarted` gate; the only window where that differs is IBD, where
  branch A clears anyway. Judged too speculative to report without execution.

## Not covered - and who inherits it

- **The tx-relay half of `protocol.lisp`** (`handle-tx`, `handle-notfound`, the
  tx-request tracker, the inv trickle). Surveyed as dimension 4; its eleven
  findings are not repeated here.
- **cmpctblock / blocktxn / getblocktxn and the high-bandwidth peer set.**
  Excluded as just-fixed (`exclusions.md`); only the timeout hook
  (`check-compact-block-timeout`) was read.
- **BIP324 handshake cryptography and the v1/v2 detection sniff.** Only their
  connection-teardown effects were traced. -> the crypto dimension.
- **addrman internals** (bucket mathematics, `Good`/`Attempt` accounting,
  peers.dat). This survey only shows that the full-relay refill never calls into
  it. -> the peer-addrman dimension.
- **The inbound handshake running inline on the accept thread.** Already in the
  GA1-GA9 exclusion list; not re-reported.
- **SOCKS5, Tor control and I2P transports.** Not opened.
- **Concurrency.** Every probe ran on one thread. Races between the sync
  thread's pump, the inbound listener pushing to `pending-inbound-peers`, and
  RPC-thread disconnects (`disconnectnode`, `setban`) are untested here, and
  that is where the residual risk in this seam sits: `node-peers` is
  single-writer only by convention.

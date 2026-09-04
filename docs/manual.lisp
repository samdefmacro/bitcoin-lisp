;;;; docs/manual.lisp — PAX developer manual for bitcoin-lisp.
;;;;
;;;; Loaded by scripts/docs-check.lisp (purely additive — not part of the
;;;; bitcoin-lisp ASDF system). `scripts/dev.sh docs-check` documents every
;;;; section below in a cold container: a reference to a symbol that does
;;;; not exist (or exists as a different kind of thing) is an error, and a
;;;; cl-transcript whose recorded values drift from reality fails the run.
;;;; So the entry-point lists here are checked, not decorative -- when a
;;;; function is renamed, this file goes red with it.
;;;;
;;;; One section per layer, in load order. Each says what the layer is, which
;;;; Core files it mirrors, what it exports as entry points, what must stay
;;;; true, and where the traps are. It is the first thing to read before
;;;; touching a module.

(mgl-pax:define-package :bitcoin-lisp.docs
  (:use #:common-lisp #:mgl-pax)
  (:export #:@bitcoin-lisp-manual
           #:@docs-check-selftest
           #:@docs-check-dangling-selftest))

(in-package :bitcoin-lisp.docs)

(defsection @bitcoin-lisp-manual (:title "bitcoin-lisp developer manual")
  "A Bitcoin full node in Common Lisp (SBCL). Consensus-critical code
  matches Bitcoin Core behaviour exactly; `refs/bitcoin/` is the canonical
  spec and every module below names the Core files it mirrors.

  The tree is a stack of ASDF systems, each compiled before the next, so a
  reference upward is a compile error rather than a convention:

      bitcoin-lisp/util           nicknames, conditions, byte I/O, chain params, node-context, token bucket
      bitcoin-lisp/crypto         hashes, secp256k1, BIP324 ciphers, BIP32
      bitcoin-lisp/logging        categories, levels, rate limit, deferred lines
      bitcoin-lisp/config         the option registry and the CLI / conf / settings parsers
      bitcoin-lisp/kv             LevelDB, flat files, datadir layout, fsync
      bitcoin-lisp/serialization  wire and disk encodings, messages, PSBT
      bitcoin-lisp/storage        block store, coins view, chain state, indexes, pruning
      bitcoin-lisp/net            sockets, SOCKS5, BIP324 transport, BIP155, addrman, Tor
      bitcoin-lisp/rpc-server     JSON-RPC over HTTP, auth, warmup, DEFINE-RPC
      bitcoin-lisp                script interpreter (Coalton), validation, mempool, mining,
                                  the P2P protocol, the RPC methods, wallet, node

  Cross-package references use the local nicknames installed by
  `bitcoin-lisp.nicknames`: `bl:` for the node package, then `bl.err`,
  `bl.bytes`, `bl.chain`, `bl.ctx`, `bl.rl`, `bl.crypto`, `bl.log`,
  `bl.cfg`, `bl.kv`, `bl.ser`, `bl.store`, `bl.net`, `bl.rpc`, `bl.val`,
  `bl.mp`, `bl.mining`, `bl.wallet`, `bl.script`, `bl.interop`. The node
  package re-exports what it inherits from the layers below, so `bl:`
  keeps naming the whole API from above.

  Three lanes verify a change: the warm image (`scripts/dev.sh eval`,
  `dev.sh test SUITE`) for the edit loop, the from-scratch cold build
  (`cl-workbench validation run cold-unit`, `cold-unit-fresh` after a
  macro or defstruct change) as the verification of record, and
  `dev.sh docs-check` for this manual."
  (@util section)
  (@crypto section)
  (@logging section)
  (@config section)
  (@kv section)
  (@serialization section)
  (@storage section)
  (@net section)
  (@p2p section)
  (@rpc-server section)
  (@script section)
  (@validation section)
  (@mempool section)
  (@mining section)
  (@rpc-methods section)
  (@wallet section)
  (@zmq section)
  (@node section))

(defsection @util (:title "util: the chain-agnostic base")
  "Seven small packages every other layer can name. Core: `util/`,
  `kernel/chainparams.cpp`, `node/context.h`, `util/signalinterrupt.h`,
  `validationinterface.h` (as hook lists: validation and the mempool
  announce a block connected or disconnected, a tip update, a transaction
  added or removed, and the wallet, ZMQ, the indexes and the node's own
  housekeeping subscribe with `define-validation-hook` -- so the lower
  layers name nothing above themselves). Subscribers run in registration
  order, which the load order fixes as ZMQ, the indexes, the wallet, and a
  block's hooks fire after the without-interrupts section that applied it:
  an interrupt in that window leaves an index one block behind the tip,
  and its startup catch-up closes the gap, as Core's asynchronous indexes
  do.

  Invariants: nothing here knows a chain except through the
  `chain-params` table; a file that DEFINES a package ends with
  `install-package-nicknames`, because a warm-image reload of a defpackage
  drops that package's nicknames.

  Traps: `*network*` is read at load time by anything that dispatches on
  the chain, so start-node sets it before the option globals are applied
  (a mainnet-only check once read it too early and saw the testnet
  default). The stop seam has TWO meanings -- a real shutdown and the
  assumeutxo sync pause -- and a consumer that must tell them apart has to
  say so."
  (bitcoin-lisp.nicknames package)
  (bitcoin-lisp.nicknames:install-package-nicknames function)
  (bitcoin-lisp.nicknames:*package-nicknames* variable)
  (bitcoin-lisp.conditions package)
  (bitcoin-lisp.conditions:bitcoin-lisp-error condition)
  (bitcoin-lisp.conditions:consensus-error condition)
  (bitcoin-lisp.conditions:policy-error condition)
  (bitcoin-lisp.conditions:error-reason generic-function)
  (bitcoin-lisp.conditions::define-simple-error macro)
  (bitcoin-lisp.bytes package)
  (bitcoin-lisp.bytes:byte-buf class)
  (bitcoin-lisp.bytes:with-byte-buf macro)
  (bitcoin-lisp.bytes:byte-reader class)
  (bitcoin-lisp.bytes:+max-compact-size+ constant)
  (bitcoin-lisp.chainparams package)
  (bitcoin-lisp.chainparams:define-chain-params macro)
  (bitcoin-lisp.chainparams:find-chain-params function)
  (bitcoin-lisp.chainparams:chain-params class)
  (bitcoin-lisp.chainparams:chain-names function)
  (bitcoin-lisp.chainparams:*network* variable)
  (bitcoin-lisp.chainparams:network-magic function)
  (bitcoin-lisp.context package)
  (bitcoin-lisp.context:node-context class)
  (bitcoin-lisp.context:*interrupt-check* variable)
  (bitcoin-lisp.context:interrupt-requested-p function)
  (bitcoin-lisp.ratelimit package)
  (bitcoin-lisp.ratelimit:make-rate-limiter function)
  (bitcoin-lisp.ratelimit:token-bucket-allow-p function)
  (bitcoin-lisp.validation-interface package)
  (bitcoin-lisp.validation-interface:define-validation-hook macro)
  (bitcoin-lisp.validation-interface:validation-hooks function)
  (bitcoin-lisp.validation-interface:notify-block-connected function)
  (bitcoin-lisp.validation-interface:notify-block-disconnected function)
  (bitcoin-lisp.validation-interface:notify-updated-block-tip function)
  (bitcoin-lisp.validation-interface:notify-transaction-added function)
  (bitcoin-lisp.validation-interface:notify-transaction-removed function)
  "The chain table answers every per-network question; the five chains
  are one DEFINE-CHAIN-PARAMS form each in `src/util/chainparams.lisp`:

  ```cl-transcript
  (bitcoin-lisp.chainparams:chain-names)
  => (:MAINNET :TESTNET3 :TESTNET4 :SIGNET :REGTEST)
  ```

  ```cl-transcript
  (bitcoin-lisp.chainparams:network-magic :mainnet)
  => #(249 190 180 217)
  ```

  Hashes are stored in wire order and DISPLAYED reversed; the genesis
  hash a block explorer shows is the stored bytes reversed:

  ```cl-transcript
  (bitcoin-lisp.crypto:bytes-to-hex
   (bitcoin-lisp.crypto:reverse-bytes
    (bitcoin-lisp.chainparams:chain-params-genesis-hash
     (bitcoin-lisp.chainparams:find-chain-params :mainnet))))
  => \"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f\"
  ```")

(defsection @crypto (:title "crypto: hashes and libsecp256k1")
  "Core: `crypto/`, `hash.cpp`, `key.cpp`, `pubkey.cpp`, `bip324.cpp`, and
  the libsecp256k1 library itself (ECDSA, Schnorr, ellswift, MuSig)
  through CFFI. The library path is the `BL_SECP_LIB` seam; the project
  container ships v0.7.1 with the musig module.

  Invariants: every primitive has a known-answer vector in the test tree
  (Core's `crypto_tests`, BIP340, BIP324, BIP32); a replacement without
  one is not a speed-up, it is a consensus change. Signature verification
  goes through the signature cache, whose key must include everything
  that decides validity.

  Traps: `reverse-bytes` exists because SBCL elides a `(coerce (reverse
  ...))` pair on the fast path -- use it. Heavy FFI calls cannot be
  interrupted mid-call, so a long foreign call can look like a hung eval
  (exit code 4) and then recover."
  (bitcoin-lisp.crypto package)
  (bitcoin-lisp.crypto:sha256 function)
  (bitcoin-lisp.crypto:hash256 function)
  (bitcoin-lisp.crypto:hash160 function)
  (bitcoin-lisp.crypto:tagged-hash function)
  (bitcoin-lisp.crypto:hmac-sha256 function)
  (bitcoin-lisp.crypto:siphash-2-4 function)
  (bitcoin-lisp.crypto:bytes-to-hex function)
  (bitcoin-lisp.crypto:hex-to-bytes function)
  (bitcoin-lisp.crypto:reverse-bytes function)
  (bitcoin-lisp.crypto:verify-signature function)
  (bitcoin-lisp.crypto:sign-ecdsa function)
  (bitcoin-lisp.crypto:verify-schnorr-signature function)
  (bitcoin-lisp.crypto:sign-schnorr function)
  (bitcoin-lisp.crypto:make-fschacha20 function)
  (bitcoin-lisp.crypto:hkdf-sha256-extract function)
  (bitcoin-lisp.crypto:make-muhash function)
  "`hash256` is SHA-256 applied twice, the hash of every header,
  transaction and message checksum:

  ```cl-transcript
  (bitcoin-lisp.crypto:bytes-to-hex
   (bitcoin-lisp.crypto:hash256 (bitcoin-lisp.crypto:hex-to-bytes \"\")))
  => \"5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456\"
  ```")

(defsection @logging (:title "logging: categories, levels, rate limit")
  "Core: `logging.cpp`, `logging/timer.h`. Category logging as Core has
  it (`-debug=net`, `-loglevel=net:trace`), a per-location rate limiter,
  and `-alertnotify`-style notify commands.

  Invariants: `node-log` is the one sink; the `log-*` macros expand to it
  so a disabled level costs nothing. Nothing is ever written to stderr by
  the running node -- Core's functional framework reads a node's stderr
  back at every stop and requires it empty.

  Trap: option parsing runs BEFORE debug.log exists. A line logged there
  goes to the console only and is invisible to any test that asserts on
  the log; use `defer-log`, and `flush-deferred-log-lines` replays the
  lines once the file is open."
  (bitcoin-lisp.logging package)
  (bitcoin-lisp.logging:log-info macro)
  (bitcoin-lisp.logging:log-warn macro)
  (bitcoin-lisp.logging:log-error macro)
  (bitcoin-lisp.logging:log-debug macro)
  (bitcoin-lisp.logging:log-cat macro)
  (bitcoin-lisp.logging:node-log function)
  (bitcoin-lisp.logging:defer-log function)
  (bitcoin-lisp.logging:flush-deferred-log-lines function)
  (bitcoin-lisp.logging:enable-log-category function)
  (bitcoin-lisp.logging:log-category-enabled-p function)
  (bitcoin-lisp.logging:*log-rate-limit* variable)
  (bitcoin-lisp.logging:run-notify-command function))

(defsection @config (:title "config: the option registry and the parsers")
  "Core: `common/args.cpp` (ArgsManager), `common/config.cpp`,
  `common/settings.cpp`, `util/strencodings.cpp`. The registry is the
  mechanism; the TABLE -- one DEFINE-OPTION per option bitcoind accepts --
  is `src/config-options.lisp` in the node, and the glue that turns a
  parsed alist into START-NODE's keywords is `src/node/args.lisp`.

  Invariants: definition is registration -- an option that is not in the
  table is an `Invalid parameter` at startup, exactly as in Core, and the
  table is the only place that knows an option's name. Every occurrence of
  a repeatable option counts (Core GetArgs); a scalar takes its LAST
  command-line occurrence and its FIRST config-file one.

  Traps: before changing an option, read Core's READER for it (GetArg,
  GetArgs, GetBoolArg decide the semantics, not the declaration); moving
  an option out of the core-only list must add a real row or the node
  refuses to start. A `:global` row sets a special; a repeatable option
  sets its special through `:apply`."
  (bitcoin-lisp.config package)
  (bitcoin-lisp.config:define-option macro)
  (bitcoin-lisp.config:define-core-only-options macro)
  (bitcoin-lisp.config:config-option class)
  (bitcoin-lisp.config:*config-options* variable)
  (bitcoin-lisp.config:find-config-option function)
  (bitcoin-lisp.config:parse-option-value function)
  (bitcoin-lisp.config:apply-option-globals function)
  (bitcoin-lisp.config:parse-cli-args function)
  (bitcoin-lisp.config:check-cli-args function)
  (bitcoin-lisp.config:interpret-arg function)
  (bitcoin-lisp.config:parse-bitcoin-conf function)
  (bitcoin-lisp.config:resolve-network-from-config function)
  (bitcoin-lisp.config:parse-settings-json function)
  (bitcoin-lisp.config:render-settings-json function)
  (bitcoin-lisp.config:conf-parse-bool function)
  (bitcoin-lisp.config:conf-parse-money function)
  (bitcoin-lisp.config:config-parse-error condition)
  (bitcoin-lisp.config:cli-parse-error condition)
  (bitcoin-lisp.config:option-definition-error condition)
  "The command line becomes an ordered alist of lower-case names and raw
  strings; a bare flag is `1`:

  ```cl-transcript
  (bitcoin-lisp.config:parse-cli-args '(\"-regtest\" \"-maxconnections=8\"))
  => ((\"regtest\" . \"1\") (\"maxconnections\" . \"8\"))
  ```

  Amounts parse to satoshis, as Core's ParseMoney does:

  ```cl-transcript
  (bitcoin-lisp.config:conf-parse-money \"0.0001\")
  => 10000
  ```")

(defsection @kv (:title "kv: LevelDB, flat files, datadir, fsync")
  "Core: `dbwrapper.cpp`, `flatfile.cpp`, `util/fs_helpers.cpp`,
  `node/caches.cpp`, `util/obfuscation.h`. The block index, the coins
  database and every index live in LevelDB through CFFI; blocks and undo
  data live in numbered blk/rev flat files with Core's record framing and
  XOR obfuscation.

  Invariants: a record on disk is framed and checksummed; a directory
  fsync follows every file rename that must survive a crash; the datadir
  layout is Core's, so a Core node can read what we write.

  Trap: LevelDB `max-open-files` is Core's 1000 on purpose. A larger
  value pushes LevelDB out of mmap into real file descriptors and a
  socket then gets fd > 1023 -- which `select()` cannot represent. The
  readiness poll is `poll(2)`-based so the ceiling cannot come back, but
  the LevelDB knob stays."
  (bitcoin-lisp.kv package)
  (bitcoin-lisp.kv:ensure-libleveldb-loaded function)
  (bitcoin-lisp.kv:leveldb-open function)
  (bitcoin-lisp.kv:leveldb-get function)
  (bitcoin-lisp.kv:leveldb-put function)
  (bitcoin-lisp.kv:leveldb-write function)
  (bitcoin-lisp.kv:leveldb-compact function)
  (bitcoin-lisp.kv:leveldb-close function)
  (bitcoin-lisp.kv:flat-file-pos class)
  (bitcoin-lisp.kv:flat-file-name function)
  (bitcoin-lisp.kv:flat-file-allocate function)
  (bitcoin-lisp.kv:flat-file-flush function)
  (bitcoin-lisp.kv:find-next-record function)
  (bitcoin-lisp.kv:compute-crc32 function)
  (bitcoin-lisp.kv:fsync-file function)
  (bitcoin-lisp.kv:fsync-directory function)
  (bitcoin-lisp.kv:calculate-cache-sizes function)
  (bitcoin-lisp.kv:datadir-layout-report function)
  (bitcoin-lisp.kv:*blocks-xor* variable)
  (bitcoin-lisp.kv:*fast-prune* variable)
  (bitcoin-lisp.kv:+max-blockfile-size+ constant))

(defsection @serialization (:title "serialization: wire and disk encodings")
  "Core: `serialize.h`, `primitives/transaction.h`, `primitives/block.h`,
  `protocol.cpp` and `net_processing`'s message structs, `psbt.cpp`,
  `compressor.cpp`. Each P2P message is one DEFINE-MESSAGE form that
  yields the struct, its reader and its writer together.

  Invariants: canonical bytes are a public contract -- the txid is the
  hash of the bytes this layer writes, and a round trip alone proves
  nothing. Deserializers bound every length and count before allocating,
  and refuse non-canonical CompactSize encodings where Core does.

  Trap: block DESERIALIZATION, not signature checking, is the IBD
  bottleneck (profiled); the byte-reader family is the fast path and the
  stream family is a thin shell kept for the few callers that need it."
  (bitcoin-lisp.serialization package)
  (bitcoin-lisp.serialization:read-uint32-le function)
  (bitcoin-lisp.serialization:write-uint32-le function)
  (bitcoin-lisp.serialization:read-compact-size function)
  (bitcoin-lisp.serialization:write-compact-size function)
  (bitcoin-lisp.serialization:compact-size-length function)
  (bitcoin-lisp.serialization:define-message macro)
  (bitcoin-lisp.serialization:transaction class)
  (bitcoin-lisp.serialization:transaction-inputs function)
  (bitcoin-lisp.serialization:transaction-outputs function)
  (bitcoin-lisp.serialization:transaction-hash function)
  (bitcoin-lisp.serialization:transaction-wtxid function)
  (bitcoin-lisp.serialization:serialize-transaction function)
  (bitcoin-lisp.serialization:bitcoin-block class)
  (bitcoin-lisp.serialization:block-header class)
  (bitcoin-lisp.serialization:block-header-hash function)
  (bitcoin-lisp.serialization:serialize-message function)
  (bitcoin-lisp.serialization:*network-magic* variable)
  (bitcoin-lisp.serialization:parse-psbt function)
  (bitcoin-lisp.serialization:serialize-psbt function)
  (bitcoin-lisp.serialization:compress-script function)
  (bitcoin-lisp.serialization:get-node-time function)
  "CompactSize is one byte up to 252 and a marker plus 2, 4 or 8 bytes
  beyond:

  ```cl-transcript
  (list (bitcoin-lisp.serialization:compact-size-length 252)
        (bitcoin-lisp.serialization:compact-size-length 253))
  => (1 3)
  ```")

(defsection @storage (:title "storage: blocks, coins, chain state, indexes")
  "Core: `node/blockstorage.cpp`, `coins.cpp`, `txdb.cpp`, `chain.cpp`,
  `index/base.cpp` and the index files, `node/utxo_snapshot.cpp`. The
  block store keeps bodies and undo data in flat files and prunes them
  with Core's policy; the coins view is a write-back cache over LevelDB;
  the chain state owns the block index and the tip; every index
  implements the BASE-INDEX generic functions and catches up at startup.

  Invariants: the three-phase flush (blocks, undo, then the coins
  database) is what makes a crash recoverable; an index is only as
  current as its recorded best block; pruning keeps
  `+min-blocks-to-keep+` and never touches a block under a prune lock
  (assumeutxo, rescans); a coins-cache entry that survives a sync carries
  neither DIRTY nor FRESH, since FRESH claims the base view has no such
  coin and the sync just wrote it there; and the restart scan ENUMERATES
  the blk/rev files that exist instead of counting from 0, because
  pruning deletes the lowest-numbered pair first and leaves a hole.

  Traps: `prune-old-blocks` takes its byte target as an argument because
  the node halves it while a historical chainstate exists -- storage
  never reads the node. An index whose startup catch-up is not wired is
  silently empty forever (it happened to txospenderindex; a structural
  test now checks every index is caught up). A defstruct slot added here
  breaks even a fresh container, because the FASL volume persists --
  `cold-unit-fresh` after a layout change."
  (bitcoin-lisp.storage package)
  (bitcoin-lisp.storage:block-store class)
  (bitcoin-lisp.storage:init-block-store function)
  (bitcoin-lisp.storage:store-block function)
  (bitcoin-lisp.storage:get-block function)
  (bitcoin-lisp.storage:block-exists-p function)
  (bitcoin-lisp.storage:prune-old-blocks function)
  (bitcoin-lisp.storage:prune-target-bytes function)
  (bitcoin-lisp.storage:automatic-pruning-p function)
  (bitcoin-lisp.storage:*prune-target-mib* variable)
  (bitcoin-lisp.storage:+min-blocks-to-keep+ constant)
  (bitcoin-lisp.storage:chain-state class)
  (bitcoin-lisp.storage:utxo-set class)
  (bitcoin-lisp.storage:utxo-entry class)
  (bitcoin-lisp.storage:get-utxo function)
  (bitcoin-lisp.storage:coins-view-cache class)
  (bitcoin-lisp.storage:coin-view-get function)
  (bitcoin-lisp.storage:disconnect-block-from-utxo-set function)
  (bitcoin-lisp.storage:save-utxo-set function)
  (bitcoin-lisp.storage:load-utxo-set function)
  (bitcoin-lisp.storage:base-index class)
  (bitcoin-lisp.storage:index-name generic-function)
  (bitcoin-lisp.storage:index-height generic-function)
  (bitcoin-lisp.storage:index-write-block generic-function)
  (bitcoin-lisp.storage:index-rewind-block generic-function)
  (bitcoin-lisp.storage:index-prepare-sync generic-function)
  (bitcoin-lisp.storage:index-sync generic-function)
  (bitcoin-lisp.storage:tx-index class)
  (bitcoin-lisp.storage:txospender-index class)
  (bitcoin-lisp.storage:reindex-block-index function)
  (bitcoin-lisp.storage:migrate-blocks-to-flat-files function))

(defsection @net (:title "net: the transport")
  "The half of `src/networking/` that knows no chain, compiled as
  `bitcoin-lisp/net`. Core: `net.cpp` (sockets, send/receive buffers),
  `netbase.cpp` (SOCKS5, proxies), `netaddress.cpp` (BIP155,
  reachability), `addrman.cpp` (the address book and peers.dat),
  `torcontrol.cpp`, `bip324.cpp` and `net.cpp`'s V2Transport.

  Invariants: `send-bytes` NEVER blocks -- it queues, and the pump
  flushes; `receive-bytes` is resumable and bounded per pass, so one slow
  peer cannot stall the node (a 24-byte header followed by silence once
  froze every peer). Readiness is `poll(2)`, never `select()`. The
  address book is tried/new tables with Core's bucketing, so nothing
  asserts an exact count.

  Trap: a test that drives two real connections without a pump hangs
  until its timeout, because nothing ever sends; drain the send queue."
  (bitcoin-lisp.networking package)
  (bitcoin-lisp.networking:connection class)
  (bitcoin-lisp.networking:make-tcp-connection function)
  (bitcoin-lisp.networking:close-connection function)
  (bitcoin-lisp.networking:send-bytes function)
  (bitcoin-lisp.networking:receive-bytes function)
  (bitcoin-lisp.networking:flush-send-buffer function)
  (bitcoin-lisp.networking:socket-input-ready-p function)
  (bitcoin-lisp.networking:open-listener function)
  (bitcoin-lisp.networking:accept-connection function)
  (bitcoin-lisp.networking:*proxy* variable)
  (bitcoin-lisp.networking:*onion-proxy* variable)
  (bitcoin-lisp.networking:socks5-connect function)
  (bitcoin-lisp.networking:socks5-error condition)
  (bitcoin-lisp.networking:*v2-transport-enabled* variable)
  (bitcoin-lisp.networking:v2-available-p function)
  (bitcoin-lisp.networking:*reachable-networks* variable)
  (bitcoin-lisp.networking:+bip155-networks+ variable)
  (bitcoin-lisp.networking:parse-subnet function)
  (bitcoin-lisp.networking:address-book class)
  (bitcoin-lisp.networking:address-book-add function)
  (bitcoin-lisp.networking:address-book-good function)
  (bitcoin-lisp.networking:address-book-select function)
  (bitcoin-lisp.networking:save-address-book function)
  (bitcoin-lisp.networking:load-address-book function)
  (bitcoin-lisp.networking:tor-controller class)
  (bitcoin-lisp.networking:start-tor-control function)
  (bitcoin-lisp.networking:stop-tor-control function))

(defsection @p2p (:title "p2p: the protocol on top of the transport")
  "The other half of `src/networking/`, in the main system and the SAME
  package: peers, the message handlers, headers sync, initial block
  download, eviction. Core: `net_processing.cpp`, `headerssync.cpp`,
  `net.cpp`'s connection management and eviction.

  Invariants: every message handler is a DEFINE-P2P-HANDLER row -- the
  function HANDLE-<command> of (peer payload ctx) and its dispatch facts
  (the token bucket it drains, whether it needs a mempool) in one form, so
  a handler cannot exist without being dispatched (HANDLE-MESSAGE was a
  31-branch STRING= COND, and the command names were spelled out again
  in the rate limiter). Every handler runs under the node lock and acts on
  a NODE-CONTEXT, one value, so a dispatch cannot forget an argument (a
  dispatch that passed two of eight once disabled tx relay, addr gossip
  and compact blocks outside unit tests). A peer's traffic is metered by
  the token bucket per message class, then discouraged, then
  disconnected. Outbound eclipse resistance rotates the extra outbound
  slot on a stale tip (`*max-tip-age-seconds*` is Core's
  nPowTargetSpacing * 3). A compact-block announcement is admitted in
  Core's handler order -- parent lookup, the anti-DoS work floor (the
  greater of nMinimumChainWork and tip work minus 144 tip proofs), then
  the header goes INTO the block index -- because everything past those
  gates is work a ~100-byte message buys: the shortid map SipHashes the
  whole mempool, and a header that never reaches the index is unknown
  again on every replay.

  Traps: `getheaders` must send the locator of the LAST header the peer
  gave us, never our own tip, or an ordinary lagging peer loops forever.
  The is-IBD answer is a one-way latch. A reorg used to be triggered only
  by an ARRIVING block -- the sync pass now re-evaluates the best chain
  itself."
  (bitcoin-lisp.networking:peer class)
  (bitcoin-lisp.networking:connect-peer function)
  (bitcoin-lisp.networking:disconnect-peer function)
  (bitcoin-lisp.networking:handle-message function)
  (bitcoin-lisp.networking:define-p2p-handler macro)
  (bitcoin-lisp.networking:p2p-handler-for function)
  (bitcoin-lisp.networking:send-message function)
  (bitcoin-lisp.networking:pump-peer-messages function)
  (bitcoin-lisp.networking:ingest-headers-from-peer function)
  (bitcoin-lisp.networking:initial-block-download-p function)
  (bitcoin-lisp.networking::run-ibd function)
  (bitcoin-lisp.networking:request-ibd-stop function)
  (bitcoin-lisp.networking:ibd-stop-requested-p function)
  (bitcoin-lisp.networking:consider-peer-eviction function)
  (bitcoin-lisp.networking:discourage-peer function)
  (bitcoin-lisp.networking:ban-address function)
  (bitcoin-lisp.networking:*default-ban-time-seconds* variable)
  (bitcoin-lisp.networking:*max-tip-age-seconds* variable))

(defsection @rpc-server (:title "rpc-server: JSON-RPC over HTTP")
  "Compiled as `bitcoin-lisp/rpc-server`, without a single method. Core:
  `rpc/server.cpp` (the table, warmup, execute), `httprpc.cpp` (auth,
  the cookie, the 250ms brute-force pause), `httpserver.cpp` (bind, the
  address ACL, path handlers), `rpc/request.cpp` (1.0/1.1/2.0 requests,
  batches, named parameters).

  Invariants: the listening socket binds BEFORE the cookie is written,
  Core's order, so a second process on a running node's datadir cannot
  clobber the live secret. The ACL gates the whole acceptor, so `/rest/`
  and `/ui/` inherit it. The rate limiter throttles the UNAUTHENTICATED
  side only. A method is registered by its DEFINE-RPC form -- there is no
  list to forget it in. The REST interface and the web UI register their
  HTTP surfaces with REGISTER-HTTP-SURFACE at the end of their files;
  the server never names them.

  Traps: `+json-false+` is TRUTHY -- read positional booleans through
  the `positional-bool` helpers or a `(var :bool)` spec in the handler's
  DEFINE-RPC lambda list, never raw truthiness. A nested JSON
  array reaches a handler as a LIST, a top-level one as the empty-array
  sentinel; build test parameters through the request normalizer, not by
  hand. The wallet learns its `/wallet/<name>` endpoint from
  `*rpc-request-uri*`, never from the transport."
  (bitcoin-lisp.rpc package)
  (bitcoin-lisp.rpc:start-rpc-server function)
  (bitcoin-lisp.rpc:stop-rpc-server function)
  (bitcoin-lisp.rpc:register-http-surface function)
  (bitcoin-lisp.rpc:rpc-server-data-directory generic-function)
  (bitcoin-lisp.rpc:*rpc-request-uri* variable)
  (bitcoin-lisp.rpc:define-rpc macro)
  (bitcoin-lisp.rpc:register-rpc-method function)
  (bitcoin-lisp.rpc:dispatch-rpc-method function)
  (bitcoin-lisp.rpc:set-rpc-warmup-status function)
  (bitcoin-lisp.rpc:finish-rpc-warmup function)
  (bitcoin-lisp.rpc::parse-json-rpc-request function)
  (bitcoin-lisp.rpc:+json-false+ constant)
  (bitcoin-lisp.rpc:json-bool function)
  (bitcoin-lisp.rpc:json-array function)
  (bitcoin-lisp.rpc:json-object function)
  (bitcoin-lisp.rpc:+rpc-misc-error+ constant)
  (bitcoin-lisp.rpc:+rpc-invalid-parameter+ constant)
  (bitcoin-lisp.rpc:*rpc-rate-limit* variable)
  (bitcoin-lisp.rpc:+max-rpc-body-size+ constant))

(defsection @script (:title "script: the Coalton interpreter")
  "The one piece of the node written in Coalton: `src/coalton/` holds the
  types, the byte codecs and the script interpreter, and `interop.lisp`
  is the minimal bridge validation calls. Core: `script/interpreter.cpp`,
  `script/script.cpp`, `script/sigcache.cpp`. Settled policy: the
  interpreter stays Coalton; everything else is CL.

  Invariants: every script flag is ALWAYS on, with Core's per-chain
  exception table for the historical blocks that violate one; the
  Bitcoin Core `script_tests.json` corpus runs in full in the cold lane
  (1,222 vectors). CastToBool treats a multi-byte negative zero as false.

  Traps: a Coalton or defstruct layout change needs a FRESH FASL volume
  -- the persistent volume keeps stale expansions through a warm rebuild,
  an image restart and an ordinary cold run. The script-execution cache
  must key on everything that decides validity, including the spent
  scriptPubKey. The transaction version and the spent amount are SIGNED
  slots -- that is what the wire format reads back -- while Core streams
  them as raw words, so the BIP 143 and BIP 341 preimages write their bit
  patterns: a version with bit 31 set is legal and arrives here negative."
  (bitcoin-lisp.coalton.script package)
  (bitcoin-lisp.coalton.interop package)
  (bitcoin-lisp.validation:execute-script function)
  (bitcoin-lisp.validation:validate-input-script function)
  (bitcoin-lisp.validation:classify-script function)
  (bitcoin-lisp.validation:script-type-name function)
  (bitcoin-lisp.validation:disassemble-script function)
  (bitcoin-lisp.validation:compute-script-flags-for-height function)
  (bitcoin-lisp.validation:block-script-flags function))

(defsection @validation (:title "validation: consensus and mempool acceptance")
  "Core: `validation.cpp` (CheckBlock, ConnectBlock, ActivateBestChain,
  MemPoolAccept), `consensus/tx_check.cpp`, `consensus/tx_verify.cpp`,
  `policy/packages.cpp`, `policy/policy.cpp`, `versionbits.cpp`,
  `signet.cpp`. Validation names the mempool -- MemPoolAccept is in
  validation.cpp in Core too -- and the mempool never names validation,
  which is why the mempool loads first.

  Invariants: consensus checks are ported check by check with Core's
  order and Core's reject reasons (the reason vocabulary is Core's, cross-
  checked by the functional tests). Validation announces through the
  validation interface (`notify-block-connected` after the tip update and
  the mempool's conflict removals, then `notify-updated-block-tip`; the
  disconnect side tip-first in the reorg's commit phase) and calls nothing
  in `src/node/` by name. Signature validation of a block's
  scripts is batched and cached but never skipped -- same-block chained
  spends once bypassed it. Long loops poll `interrupt-requested-p`
  between blocks so shutdown and the assumeutxo pause can cut in.

  Traps: the P2SH-witness redeem script is the STACK TOP, not the last
  push (a consensus split when it was the latter). Block weight includes
  the header and the transaction-count varint. Witness and taproot are
  height-gated for us and always on in Core -- the exception table, not
  the gate, is the source of truth. Every path that writes a block BODY
  to disk runs ACCEPT-BLOCK-BODY first (Core AcceptBlock's CheckBlock +
  ContextualCheckBlock pair); BL.STORE:STORE-BLOCK validates nothing, and
  four persist paths once reached it with no check at all. A rejected body
  marks its index entry :invalid unless the verdict is mutation-class,
  which Core's InvalidBlockFound also exempts -- the block hash does not
  commit to what those checks read, so marking one would let a peer poison
  an honest header by mangling the body in transit."
  (bitcoin-lisp.validation package)
  (bitcoin-lisp.validation:validate-transaction-structure function)
  (bitcoin-lisp.validation:validate-transaction-contextual function)
  (bitcoin-lisp.validation:validate-transaction-scripts function)
  (bitcoin-lisp.validation:validate-transaction-for-mempool function)
  (bitcoin-lisp.validation:validate-package-for-mempool function)
  (bitcoin-lisp.validation:package-tx-result class)
  (bitcoin-lisp.validation:tx-reject-reason-string function)
  (bitcoin-lisp.validation:validate-block-header function)
  (bitcoin-lisp.validation:validate-block function)
  (bitcoin-lisp.validation:accept-block-body function)
  (bitcoin-lisp.validation:test-block-validity function)
  (bitcoin-lisp.validation:connect-block function)
  (bitcoin-lisp.validation:activate-best-chain function)
  (bitcoin-lisp.validation:perform-reorg function)
  (bitcoin-lisp.validation:versionbits-state function)
  (bitcoin-lisp.validation:check-signet-block-solution function))

(defsection @mempool (:title "mempool: the pool and its policy")
  "Core: `txmempool.cpp`, `txgraph.cpp`, `cluster_linearize.h`,
  `policy/rbf.cpp`, `policy/truc_policy.cpp`, `txorphanage.cpp`,
  `policy/fees.cpp`, `kernel/mempool_persist.cpp`. Policy, never
  consensus: a rule here decides what we relay and mine, not what is
  valid.

  Invariants: the cluster mempool keeps every cluster linearized; RBF
  and TRUC checks run in Core's order with Core's limits; mempool.dat is
  written in Core's format so the two implementations can exchange one.

  Traps: an 83 MB mempool.dat turns a restart into a long silent replay
  -- load in batches and log progress. Fee estimation reads the block
  policy estimator, not the pool's current fee rates."
  (bitcoin-lisp.mempool package)
  (bitcoin-lisp.mempool:mempool class)
  (bitcoin-lisp.mempool:make-mempool function)
  (bitcoin-lisp.mempool:mempool-entry class)
  (bitcoin-lisp.mempool:mempool-add function)
  (bitcoin-lisp.mempool:mempool-get function)
  (bitcoin-lisp.mempool:mempool-has function)
  (bitcoin-lisp.mempool:mempool-remove-recursive function)
  (bitcoin-lisp.mempool:mempool-trim-to-size function)
  (bitcoin-lisp.mempool:mempool-update-for-reorg function)
  (bitcoin-lisp.mempool:*max-mempool-bytes* variable)
  (bitcoin-lisp.mempool:mempool-effective-min-fee-rate function)
  (bitcoin-lisp.mempool:sigop-adjusted-vsize function)
  (bitcoin-lisp.mempool:check-rbf-rules function)
  (bitcoin-lisp.mempool:single-truc-checks function)
  (bitcoin-lisp.mempool:feefrac class)
  (bitcoin-lisp.mempool:depgraph class)
  (bitcoin-lisp.mempool:txgraph class)
  (bitcoin-lisp.mempool:linearize function)
  (bitcoin-lisp.mempool:make-orphan-pool function)
  (bitcoin-lisp.mempool:fee-estimator class)
  (bitcoin-lisp.mempool:estimate-fee-rate function)
  (bitcoin-lisp.mempool:save-mempool-file function))

(defsection @mining (:title "mining: block templates")
  "Core: `node/miner.cpp`. Transaction selection walks the mempool's
  linearized chunks under the weight and sigop limits, builds the coinbase
  and the witness commitment, and the regtest miner solves the header.

  Invariants: the template honours `-blockmaxweight`,
  `-blockreservedweight` and `-blockmintxfee` exactly as Core's
  BlockAssembler does; getblocktemplate follows the miner contract of
  BIP22/BIP23. Trap: the reserved weight exists because the header and
  the transaction-count varint count toward the block weight."
  (bitcoin-lisp.mining package)
  (bitcoin-lisp.mining:assemble-block-template function)
  (bitcoin-lisp.mining:block-template class)
  (bitcoin-lisp.mining:build-coinbase-transaction function)
  (bitcoin-lisp.mining:assemble-full-block function)
  (bitcoin-lisp.mining:mine-block function)
  (bitcoin-lisp.mining:next-block-required-bits function)
  (bitcoin-lisp.mining:*block-max-weight* variable)
  (bitcoin-lisp.mining:*block-reserved-weight* variable)
  (bitcoin-lisp.mining:*block-min-tx-fee-rate* variable))

(defsection @rpc-methods (:title "rpc: the methods, REST and the web UI")
  "One file per Core `rpc/*.cpp` (blockchain, net, mempool,
  rawtransaction, node, mining, output-script, signmessage), the wallet's
  under `src/wallet/`, plus `rest.lisp` (Core `rest.cpp`) and the web UI.
  The named-argument tables are generated from Core's RPCHelpMan
  declarations into `core-tables.lisp` -- data, regenerated on a Core
  upgrade, never hand-edited.

  Invariants: every method is a DEFINE-RPC form; the node lock is the
  OUTERMOST lock, so a handler that mutates node state holds it for the
  whole operation and a long-polling handler never holds it across its
  wait. Error codes and messages are Core's.

  Trap: the recurring failure shape in this tree is correct code with
  the wrong or missing caller -- an index built but never maintained, a
  check present but never reached. Test the wire, not the function."
  (bitcoin-lisp.rpc:with-node-lock macro)
  (bitcoin-lisp.rpc:rpc-get-chain-state function)
  (bitcoin-lisp.rpc::*rpc-named-arg-names* variable)
  (bitcoin-lisp.rpc::*rpc-arg-conversions* variable)
  (bitcoin-lisp.rpc:open-browser-to-ui function))

(defsection @wallet (:title "wallet: descriptor wallets")
  "Core: `wallet/` -- descriptor wallets only, no legacy BDB wallets, no
  BIP39. Watch-only and spending, PSBT, encryption and backup, the
  `/wallet/<name>` endpoint. Enabled by default on test networks and off
  by default on mainnet.

  Invariants: a wallet's chain view is driven by the node's block and
  mempool notifications (the `wallets-*` entry points), never by polling;
  the descriptor expansion is cached by descriptor STRING, and every
  script construction change must invalidate it.

  Traps: a locked wallet could once still sign because a parsed
  descriptor kept its embedded xprv; the key-provider is the only source
  now. RENAME-FILE merges a target pathname with the source, so a backup
  that renamed wrote nothing. Core SORTS musig participants (BIP328); an
  x-only print flag is not the 32-vs-33-byte push decision."
  (bitcoin-lisp.wallet package)
  (bitcoin-lisp.wallet:wallet-manager class)
  (bitcoin-lisp.wallet:init-wallet-manager function)
  (bitcoin-lisp.wallet:load-wallets-on-startup function)
  (bitcoin-lisp.wallet:close-wallet-manager function)
  (bitcoin-lisp.wallet:wallets-block-connected function)
  (bitcoin-lisp.wallet:wallets-block-disconnected function)
  (bitcoin-lisp.wallet:wallets-mempool-tx-added function)
  (bitcoin-lisp.wallet:wallets-maybe-resend function)
  (bitcoin-lisp.wallet::wallet-for-request function)
  (bitcoin-lisp.wallet::*rpc-wallet-name* variable))

(defsection @zmq (:title "zmq: the notification sockets")
  "`src/zmq.lisp`. Core: `zmq/zmqnotificationinterface.cpp`,
  `zmq/zmqpublishnotifier.cpp`. Five PUB sockets -- hashblock, hashtx,
  rawblock, rawtx, sequence -- each bound by its own `-zmqpub<topic>`
  option, each message the topic, the body and a per-topic sequence
  counter. libzmq is loaded lazily, only when a `-zmqpub*` option is set,
  so a host without it runs the node with ZMQ off.

  Invariants: the notifications are validation-interface hooks (see the
  util section): BlockConnected publishes every transaction, then the
  block and a sequence `C`; BlockDisconnected the transactions and a `D`;
  a transaction entering the mempool its hashtx/rawtx and an `A` carrying
  the mempool sequence, one leaving for any reason but mining an `R`. A
  background (assumeutxo) chainstate's blocks are not announced, as Core's
  interface returns early for ChainstateRole::BACKGROUND.

  Traps: ZMQ_LINGER defaults to -1, so closing a socket with messages
  queued for a departed subscriber blocks forever -- it is set to 0 as Core
  does. `bitcoin-block-transactions` is a LIST, not a vector."
  (bitcoin-lisp:zmq-start-publishers function)
  (bitcoin-lisp:zmq-stop-publishers function)
  (bitcoin-lisp:zmq-specs-from-config function)
  (bitcoin-lisp:zmq-notifications-info function)
  (bitcoin-lisp:zmq-topic-active-p function)
  (bitcoin-lisp:zmq-notify-block-connected function)
  (bitcoin-lisp:zmq-notify-block-disconnected function)
  (bitcoin-lisp:zmq-notify-tx-accepted function)
  (bitcoin-lisp:zmq-notify-tx-removed function))

(defsection @node (:title "node: start-up, the sync thread, shutdown")
  "The top of the stack. Core: `init.cpp` (AppInitMain in twelve steps
  here, `src/node/init.lisp`), `node/` and `validationinterface.cpp`.
  `src/config.lisp` holds the process-wide specials the option table
  sets; `src/config-options.lisp` is the table; `src/node/args.lisp`
  turns a parsed alist into START-NODE's keywords and applies the
  parameter interactions; `src/node/shutdown.lisp` installs the stop
  predicate every long loop polls.

  Invariants: the RPC server comes up early and answers -28 until warmup
  finishes; the sync thread is the only writer of chain state; shutdown
  is cooperative, with a watchdog as the last resort; a node exits with
  Core's meaning of clean, error and watchdog.

  Traps: a changed DEFCONSTANT needs an image RESTART -- the warm image
  goes stale whichever way the continuable error is answered; a changed
  MACRO or defstruct needs a fresh FASL volume. Re-derive process state
  from the machine, never from a notification."
  (bitcoin-lisp package)
  (bitcoin-lisp:node class)
  (bitcoin-lisp:*node* variable)
  (bitcoin-lisp:start-node function)
  (bitcoin-lisp:start-node-from-args function)
  (bitcoin-lisp:stop-node function)
  (bitcoin-lisp:node-main function)
  (bitcoin-lisp::args->start-node-plist function)
  (bitcoin-lisp::apply-config-globals function)
  (bitcoin-lisp:sync-blockchain function)
  (bitcoin-lisp:node-status function)
  (bitcoin-lisp:request-node-shutdown function)
  (bitcoin-lisp:node-shutdown-requested-p function)
  (bitcoin-lisp:run-node-watchdog function)
  (bitcoin-lisp:effective-prune-target-bytes function)
  (bitcoin-lisp:*blocksonly* variable)
  (bitcoin-lisp:*p2p-port-override* variable)
  (bitcoin-lisp:*assumevalid-override* variable))

(defsection @docs-check-selftest (:title "docs-check red self-test")
  "Deliberately broken transcript: the recorded value below is wrong, so
  verifying this section MUST fail. If it ever passes, transcript checking
  is silently off and scripts/docs-check.lisp fails the whole run.

  ```cl-transcript
  (+ 1 2)
  => 4
  ```")

(defsection @docs-check-dangling-selftest (:title "docs-check red self-test: dangling reference")
  "Deliberately dangling reference: the entry below names a function that
  does not exist, so documenting this section MUST fail. If it ever
  passes, the manual's entry-point lists are no longer being checked
  against the image and scripts/docs-check.lisp fails the whole run."
  (bitcoin-lisp.docs::no-such-function-anywhere function))

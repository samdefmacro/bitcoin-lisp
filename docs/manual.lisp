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

  Invariant on peer text: a string that came from a peer is filtered by
  SANITIZE-STRING (Core's SanitizeString) at the boundary, once, and the
  filtered form is what is stored -- the log, getpeerinfo and everything
  else then need no escaping of their own. The log's own escape pass
  deliberately lets a newline through, exactly as Core's LogEscapeMessage
  does, so the boundary filter is what stops a peer from writing lines of
  its own.

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
  (bitcoin-lisp.bytes:sanitize-string function)
  (bitcoin-lisp.chainparams package)
  (bitcoin-lisp.chainparams:define-chain-params macro)
  (bitcoin-lisp.chainparams:find-chain-params function)
  (bitcoin-lisp.chainparams:chain-params class)
  (bitcoin-lisp.chainparams:chain-names function)
  (bitcoin-lisp.chainparams:*network* variable)
  (bitcoin-lisp.chainparams:network-magic function)
  (bitcoin-lisp.chainparams:chain-params-template function)
  (bitcoin-lisp.chainparams:chain-params-override function)
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

  A row is the DEFAULT construction, not the last word: an option can
  instantiate a chain, the way Core's `SigNetParams(SigNetOptions)` is a
  constructor rather than a table. `-signetchallenge` derives its own
  message start, clears the seeds and zeroes the chain-work floor;
  `chain-params-template` is the table row and `chain-params-override` is
  what this run installed over it, with `find-chain-params` preferring the
  override.

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
  "Core: `crypto/`, `hash.cpp`, `key.cpp`, `pubkey.cpp`, `bip324.cpp`,
  `random.cpp`, and the libsecp256k1 library itself (ECDSA, Schnorr,
  ellswift, MuSig) through CFFI. The library path is the `BL_SECP_LIB`
  seam; the project container ships v0.7.1 with the musig module.

  Invariants: every primitive has a known-answer vector in the test tree
  (Core's `crypto_tests`, BIP340, BIP324, BIP32); a replacement without
  one is not a speed-up, it is a consensus change. Signature verification
  goes through the signature cache, whose key must include everything
  that decides validity. Every value an adversary SEES (a ping or
  compact-block nonce, a BIP330 salt) or must not PREDICT (the eviction
  netgroup key) comes from RAND-U64, the OS source, and never from
  CL:RANDOM -- SBCL's MT19937 is invertible from its own output and its
  fresh-image state is fixed at SBCL build time.

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
  (bitcoin-lisp.crypto:rand-u64 function)
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
  "Core: `logging.cpp`, `logging/timer.h`, `node/warnings.cpp`. Category
  logging as Core has it (`-debug=net`, `-loglevel=net:trace`), a
  per-location rate limiter, the `-*notify` shell hooks, and the node's
  WARNINGS map -- which lives here, below every producer, because
  validation raises warnings and knows nothing about a node.

  Invariants: `node-log` is the one sink; the `log-*` macros expand to it
  so a disabled level costs nothing. Nothing is ever written to stderr by
  the running node -- Core's functional framework reads a node's stderr
  back at every stop and requires it empty. `set-warning` and
  `unset-warning` return whether the state CHANGED, and that return value
  is the mechanism, not a convenience: `set-kernel-warning` fires
  `-alertnotify` only on a change, so the pager rings once per transition
  rather than once per block. `warnings-for-rpc` is the whole `warnings`
  field of getblockchaininfo, getnetworkinfo and getmininginfo; only the
  KERNEL warnings reach the pager, as in Core. `alert-notify` sanitizes
  the message and THEN wraps it in single quotes, which is what makes the
  quoting safe -- the safe character set holds no quote.

  Traps: option parsing runs BEFORE debug.log exists. A line logged there
  goes to the console only and is invisible to any test that asserts on
  the log; use `defer-log`, and `flush-deferred-log-lines` replays the
  lines once the file is open. The startup scroll of debug.log is
  `-shrinkdebugfile`, whose DEFAULT Core derives from another option --
  false as soon as any `-debug` category is set -- so `start-file-logging`
  takes it as an argument and `%init-logging` computes it."
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
  (bitcoin-lisp.logging:run-notify-command function)
  (bitcoin-lisp.logging:default-shrink-debug-file-p function)
  (bitcoin-lisp.logging:set-warning function)
  (bitcoin-lisp.logging:unset-warning function)
  (bitcoin-lisp.logging:set-kernel-warning function)
  (bitcoin-lisp.logging:warnings-for-rpc function)
  (bitcoin-lisp.logging:reset-warnings function)
  (bitcoin-lisp.logging:*alert-notify-command* variable)
  (bitcoin-lisp.logging:*client-version-is-release* variable))

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
  command-line occurrence and its FIRST config-file one. A config-file key
  carries its own section when it is dotted (`main.rpcport=8332`), so a
  line's section is CONF-SETTINGS-ROWS' answer rather than the `[header]`
  above it. Every source is parsed into settings ROWS -- (name value json)
  -- and MERGED-CONFIG-ALIST resolves each option name across all four in
  Core's precedence order; a NEGATION (`-nofoo`, the JSON `false`) erases
  the values before it in its source and blocks the sources below it,
  which is why the merge cannot be an APPEND of the four alists. A
  `:network-only` row (Core NETWORK_ONLY: -port, -rpcport, -bind, -rpcbind,
  -connect, -addnode, -wallet, -walletdir) does not read the config file's
  default section off mainnet, and refuses to start when that is the only
  place it is set. A `:sensitive` row (Core SENSITIVE: -rpcuser,
  -rpcpassword, -rpcauth, -torpassword) has its VALUE replaced by `****` in
  the startup arg log, so a secret never reaches debug.log.

  Traps: before changing an option, read Core's READER for it (GetArg,
  GetArgs, GetBoolArg decide the semantics, not the declaration); moving
  an option out of the core-only list must add a real row or the node
  refuses to start. A `:global` row sets a special; a repeatable option
  sets its special through `:apply`. A `:global` row is only ASSIGNED when
  the option is present, so an option that must return to its default on
  every start belongs in a `:key` row that START-NODE re-applies -- which
  is also why the soft-set half of such an option lives in
  CONFIG-ALIST->START-NODE-PLIST rather than APPLY-PARAMETER-INTERACTIONS.

  Locating the config file is its own seam, and Core's ordering is
  load-bearing: the datadir and the config path are recorded BEFORE the
  file is read, because a `datadir=` line inside it moves the datadir --
  and the `bitcoin.conf` sitting in the directory it moved to is then
  ignored. CHECK-IGNORED-CONFIG-FILE refuses to start on that, and on a
  `-conf=` that shadows the datadir's own file, unless `-allowignoredconf`
  downgrades it; RESOLVE-CONF-PATH resolves a relative `-conf` against the
  datadir, and CHECK-CONFIG-FILE-READABLE makes an explicit `-conf` that
  cannot be opened fatal instead of a silent start on defaults."
  (bitcoin-lisp.config package)
  (bitcoin-lisp.config:define-option macro)
  (bitcoin-lisp.config:define-core-only-options macro)
  (bitcoin-lisp.config:config-option class)
  (bitcoin-lisp.config:*config-options* variable)
  (bitcoin-lisp.config:find-config-option function)
  (bitcoin-lisp.config:parse-option-value function)
  (bitcoin-lisp.config:apply-option-globals function)
  (bitcoin-lisp.config:cli-settings-rows function)
  (bitcoin-lisp.config:parse-cli-args function)
  (bitcoin-lisp.config:check-cli-args function)
  (bitcoin-lisp.config:interpret-arg function)
  (bitcoin-lisp.config:conf-settings-rows function)
  (bitcoin-lisp.config:parse-bitcoin-conf function)
  (bitcoin-lisp.config:settings-config-rows function)
  (bitcoin-lisp.config:merged-config-alist function)
  (bitcoin-lisp.config:merge-setting function)
  (bitcoin-lisp.config:merge-settings-list function)
  (bitcoin-lisp.config:network-only-option-p function)
  (bitcoin-lisp.config:sensitive-config-option-p function)
  (bitcoin-lisp.config:use-default-section-p function)
  (bitcoin-lisp.config:unsuitable-section-only-options function)
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
  fsync follows every file rename that must survive a crash -- through
  `fsync-parent-directory` wherever the caller holds the file's path, since
  `fsync-directory` given a file syncs that file and reports success; a
  failed fsync is logged and never swallowed, as Core's `FileCommit` and
  `DirectoryCommit` log and return false; the datadir layout is Core's, so
  a Core node can read what we write.

  Traps: LevelDB `max-open-files` is Core's 1000 on purpose. A larger
  value pushes LevelDB out of mmap into real file descriptors and a
  socket then gets fd > 1023 -- which `select()` cannot represent. The
  readiness poll is `poll(2)`-based so the ceiling cannot come back, but
  the LevelDB knob stays. And `leveldb-compact` is not an erasure
  primitive: `CompactRange` reads the top level that has files BEFORE it
  flushes the memtable, so on a young database the flush lands above
  everything the compaction then rewrites. Bytes that must leave the disk
  need a rebuild into a new directory (`wallet-db-rewrite`)."
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
  (bitcoin-lisp.kv:fsync-parent-directory function)
  (bitcoin-lisp.kv:rename-path function)
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
  and refuse non-canonical CompactSize encodings where Core does. A
  peer-supplied string field says its own bound -- `(:var-string :max N
  :name ...)`, Core's LIMITED_STRING -- and an over-long one FAILS the
  message rather than being truncated, which is how the peer gets dropped.
  A wire boolean is read the way Core reads one: the byte is assigned to
  the bool (`serialize.h:277`), so EVERY nonzero byte is true and
  `br-read-bool` is the only place that rule is written down -- a field
  that tests the byte against 1 rejects what Core accepts.

  A transaction is read by Core's UnserializeTransaction, whose shape is
  not `look at the marker byte\': an EMPTY vin is the dummy, the flag byte
  after it may be 0 (a legal 0-input 0-output transaction, which
  CheckTransaction rejects later), and a witness-flagged transaction whose
  stacks are all empty is a `Superfluous witness record\'. `:allow-witness\'
  is Core\'s TX_NO_WITNESS, which is what lets the RPC layer read one hex
  string BOTH ways (see `bl.rpc:decode-tx\'). The WRITER is the mirror:
  `transaction-wire-bytes\' is TX_WITH_WITNESS and emits the marker only for
  a transaction that has witness data, while
  `serialize-witness-transaction\' emits it unconditionally and is a
  primitive, not the wire form.

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
  (bitcoin-lisp.serialization:transaction-wire-bytes function)
  (bitcoin-lisp.serialization:read-transaction function)
  (bitcoin-lisp.serialization:bitcoin-block class)
  (bitcoin-lisp.serialization:block-header class)
  (bitcoin-lisp.serialization:block-header-hash function)
  (bitcoin-lisp.serialization:serialize-message function)
  (bitcoin-lisp.serialization:+max-subversion-length+ constant)
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
  current as its recorded best block, and that marker is only meaningful
  while it names a block on the ACTIVE chain -- INDEX-HEIGHT resolves it
  against the chainstate and INDEX-PREPARE-SYNC rewinds one that has
  fallen off, undoing the abandoned branch for an index whose records a
  reconnect does not overwrite; pruning keeps
  `+min-blocks-to-keep+` and never touches a block under a prune lock
  (assumeutxo, rescans); a coins-cache entry that survives a sync carries
  neither DIRTY nor FRESH, since FRESH claims the base view has no such
  coin and the sync just wrote it there; the block index reaches disk
  BEFORE the coins pointer that names one of its entries, which is what
  `*persist-block-index-hook*` is for; an EMPTIED coins database names no
  block, because the reindex wipe erases the best-block pointer with the
  coins and nothing reconciles a tip record toward an empty view (Core's
  is_coinsview_empty, node/chainstate.cpp:69-70); and the restart scan
  ENUMERATES the blk/rev files that exist instead of counting from 0,
  because pruning deletes the lowest-numbered pair first and leaves a
  hole.

  The header index and its delta log are shared by every chainstate on a
  datadir (they take no storage-suffix), so what binds the delta to the
  snapshot it extends is a per-BASE-PATH record, not a chain-state slot:
  Core keeps the block index in BlockManager, outside any chainstate, and
  a per-chainstate copy of that binding let a snapshot chainstate and the
  primary invalidate each other's log. Replaying that log MUTATES the entry
  a hash already has -- Core's InsertBlockIndex is a try_emplace, so there
  is exactly one object per hash and a prev-entry pointer can never
  disagree with a lookup; installing a second object left every ancestry
  walk handing out the superseded copy.

  Traps: `prune-old-blocks` takes its byte target as an argument because
  the node halves it while a historical chainstate exists -- storage
  never reads the node. An index whose startup catch-up is not wired is
  silently empty forever (it happened to txospenderindex; a structural
  test now checks every index is caught up). A defstruct slot added here
  breaks even a fresh container, because the FASL volume persists --
  `cold-unit-fresh` after a layout change.

  A store has TWO bases. `base-path` is the network data directory and
  `store-blocks-path` is where the blk/rev/xor bulk goes -- the same split
  Core makes between `GetDataDirNet()` and `GetBlocksDirPath()`, so
  `-blocksdir` moves hundreds of GB of block data to a second volume while
  the block INDEX stays under the datadir and the directory remains
  readable by Core."
  (bitcoin-lisp.storage package)
  (bitcoin-lisp.storage:block-store class)
  (bitcoin-lisp.storage:init-block-store function)
  (bitcoin-lisp.storage:store-blocks-path function)
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
  (bitcoin-lisp.storage:*persist-block-index-hook* variable)
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
  flushes -- and it never DISCARDS: past the send-buffer cap the peer is
  send-paused, which stops the pump reading that peer's INPUT (Core's
  fPauseSend gate in ProcessMessages), so the work is deferred instead of
  a reply we already decided to send going missing; a peer that never
  drains is dropped by the 20-minute socket-sending timeout, as in Core.
  That twenty minutes is Core's TIMEOUT_INTERVAL and there is exactly ONE
  of it: `+timeout-interval-seconds+` is what the send-stall window, the
  half-read-message reaper and the ping timeout all are, because Core
  measures every liveness rule against the same constant -- spelled
  separately, the reaper's copy had drifted to a quarter of it and dropped
  peers Core keeps. A connection that dies records WHY: every failure path
  clears CONNECTED through one helper that stores a reason, so the pump's
  reap logs Core's own line (the reason, then `disconnecting peer=<id>`)
  under -debug=net instead of an unconditional warning saying only that a
  connection is dead.
  `receive-bytes` is resumable and bounded per pass, so one slow
  peer cannot stall the node (a 24-byte header followed by silence once
  froze every peer). Readiness is `poll(2)`, never `select()`. The
  address book is tried/new tables with Core's bucketing, so nothing
  asserts an exact count. Every AUTOMATIC dial is drawn through one
  filter, SELECT-DIALABLE-ADDRESS: the network must be dialable by our
  transport and reachable under -onlynet, and an ipv4/ipv6 record must
  not name a port on Core's IsBadPort deny-list, or a gossiped
  `victim:25' turns the node into someone else's SMTP client. Storage
  and relay are deliberately unfiltered, as in Core, and manual
  connections bypass addrman entirely. A failed dial says WHOSE fault it
  was: MAKE-TCP-CONNECTION's second value is Core's
  `proxy_connection_failed', raised only when the TCP connect to the
  SOCKS5 proxy itself failed and never for a handshake the proxy
  answered, and CONNECT-PEER passes it through so the addrman recorder
  can charge the address nothing for an outage of ours.

  A name is handed to the LOCAL resolver only when `-dns` allows it:
  `*name-lookup*` is Core's fNameLookup and DIAL-NAME-REFUSAL states its
  whole condition, `fNameLookup && !HaveNameProxy()`, over the string a
  dial is about to resolve. With a proxy the target travels inside the
  SOCKS5 CONNECT and only the proxy's own host can reach the resolver. It
  does NOT gate the DNS seeds; those are `-dnsseed`, which Core queries
  with a hardcoded fAllowLookup.

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
  (bitcoin-lisp.networking:*name-lookup* variable)
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
  disconnected -- unless it is a NoBan peer or a MANUAL one, two
  independent exemptions Core applies before punishing anyone. Every
  retirement path ends in DISCONNECT-PEER, which is Core's single
  FinalizeNode: the tx-request tracker's announcements, the orphanage
  entries and the headers-sync buffer are released there and nowhere
  else, so a path that open-codes its own teardown leaks per-peer state
  keyed by the peer OBJECT. An error raised by a message HANDLER is caught, counted
  per command and forgiven with the connection kept, which is Core's
  ProcessMessages catch: the failure is per-peer but the trigger is per
  message TYPE, so a blanket disconnect drops every peer that sends the
  message a handler happens to mishandle. A disconnect comes only from a
  named rule -- one written inside a handler, the framing layer's own bad
  magic / oversized checks, or a protocol VECTOR over its maximum
  (a PROTOCOL-LIMIT-ERROR), which is the one deserialization failure Core
  answers with Misbehaving. Block download has TWO separate
  disconnects and neither is the per-hash retry: releasing a timed-out
  request re-routes it and costs its holder nothing, while a peer is
  dropped either for holding the download window shut (its own stalling
  clock, whose timeout DOUBLES from 2s toward 64s after each use so our
  own bandwidth cannot evict a fleet) or for going silent past
  nPowTargetSpacing * (1 + 0.5 * other downloading peers) measured from
  its LAST DELIVERY, never from when we asked. -peertimeout is the GATE in
  front of every liveness verdict, not one timeout among several: Core's
  ShouldRunInactivityChecks guards all four InactivityCheck rules and, on
  its own first line, MaybeSendPing's ping timeout, which is how raising
  the knob silences liveness disconnects wholesale -- Core's functional
  framework writes peertimeout=999999999 into every node so that mocktime
  jumps disconnect nobody. Behind that gate are Core's rules themselves:
  nothing ever sent or received inside the first -peertimeout seconds,
  nothing SENT for TIMEOUT_INTERVAL, nothing RECEIVED for TIMEOUT_INTERVAL,
  and an unfinished handshake. The receive rule is suspended while a peer
  is send-paused, because our pump -- unlike Core's socket thread -- stops
  READING a paused peer, so its last-recv would measure our own pause;
  CONNECTION-SEND-STALLED-P, which additionally wants data pending, stays
  the separate backpressure signal and bounds that peer anyway.
  Outbound eclipse resistance rotates the extra outbound
  slot on a stale tip (`*max-tip-age-seconds*` is Core's
  nPowTargetSpacing * 3). The outbound refill IS
  ThreadOpenConnections: every try is a FRESH addrman draw, up to 100
  per connection, skipping a candidate whose last_try is under ten
  minutes old until 30 have been rejected -- a boot-time snapshot of
  picks re-walked in fixed order could only ever fill the eight
  full-relay slots from the addresses the node happened to know at
  start-up, and re-dialled a dead one every thirty seconds forever.
  Everything that decides an outbound dial reads
  OUTBOUND peers only -- the full-relay count, the /16 netgroup set a
  candidate is vetoed against, and the online test that says whether an
  addrman FAILURE may be charged -- because inbound connections are free
  for an attacker to make; the inbound eviction reserve likewise protects
  each disadvantaged network's LONGEST-connected peers, which is what
  \"precludes attacks that start later\" means. An inbound ONION peer is
  granted no -whitelist permission by its address, because the address is
  not its own: every one of them arrives from the local Tor daemon on the
  onion listener, so one loopback range would hand the operator's trusted-peer
  flags to every anonymous onion peer (Core's inbound_onion carve-out).
  -whitebind still applies -- it describes the listening socket. A compact-block
  announcement is admitted in Core's handler order -- parent lookup, the
  anti-DoS work floor (the greater of nMinimumChainWork and tip work minus 144 tip proofs), then
  the header goes INTO the block index -- because everything past those
  gates is work a ~100-byte message buys: the shortid map SipHashes the
  whole mempool, and a header that never reaches the index is unknown
  again on every replay. The three feature negotiations BIP155, BIP330 and
  BIP339 place strictly between VERSION and VERACK -- sendaddrv2,
  sendtxrcncl, wtxidrelay -- are handled inside that window by
  %AWAIT-VERACK, so their table rows exist only to drop a peer that sends
  one afterwards, with Core's own log line. A getdata is answered from a
  per-peer QUEUE (Core Peer::m_getdata_requests): serving stops while the
  peer is send-paused and the rest waits there until the next pump pass,
  which drains it before it decides whether to read that peer at all --
  dropping the remainder instead made the peer wait out its own request
  timeout for data we had already looked up, and the queue is what lets the
  deep-getblocktxn full-block fallback inherit the getdata path's
  backpressure and serving guards rather than carry a private copy of them.
  A gossiped address this node has banned or discouraged is dropped at
  ingest, before addrman and before relay, so the node never re-propagates
  an address it has itself judged hostile -- but the announcer is still marked as knowing it, which
  is Core's order (AddAddressKnown before the ban test, ++num_proc after
  it): a peer is never handed back an address it has just told us, and
  `addr_processed` counts only what got past both filters. Relaying an
  address only QUEUES it on the chosen peers (Core RelayAddress ->
  PushAddress); one addr/addrv2 per peer carries the whole queue when that
  peer's own exponential 30s deadline passes, because sending at receive
  time would tell an observer when and from whom we learned each address.
  Our OWN address rides that same queue: Core sends only the first
  self-announcement on a connection as its own message and pushes every
  later one, resetting the peer's addr-known filter first so the flush
  cannot drop the repeat, because a lone addr arriving by itself says
  exactly when the 24h timer fired. The queue's destinations are the top one
  or two of a ranking keyed by a PER-NODE secret (`*ADDRESS-RELAY-SALT*`,
  Core nSeed0/nSeed1) -- an unsalted ranking over public inputs lets an
  attacker compute the destinations in advance and pick addresses to steer
  them -- and the rotation epoch that fixes that ranking for a day carries
  the address's own hash, so each address turns its destinations over at its
  own instant rather than the whole topology rotating at 00:00 UTC. The
  relay stops at those picks: a peer that already knows the address is
  simply not queued to, never replaced by the next peer down the ranking,
  which is what keeps a repeated address inside its two destinations for
  the period.

  Which peer is asked for a transaction is Core's txrequest state machine:
  an announcement is CANDIDATE while its NONPREF/TXID_RELAY/OVERLOADED delay
  runs and after it, REQUESTED while its getdata is outstanding, and
  COMPLETED -- never deleted -- once the peer answered notfound, let the
  request expire, or delivered something, so it cannot re-announce its way
  into a second window and its MAX_PEER_TX_ANNOUNCEMENTS budget stays
  charged; the whole txhash is forgotten only when the LAST non-completed
  announcement completes, or at a genuine resolution (mempool acceptance, a
  connected block, orphan intake, a non-reconsiderable rejection). Among the
  candidates the winner is `SipHash(node salt, txhash || peer) | preferred <<
  63`, highest first, so it is uniform, per-transaction and not computable by
  an announcer -- selecting by announcement order handed every request to
  whoever announced first. A delivery completes ONE announcement
  (ReceivedResponse), which is what stops an unsolicited witness-malleated
  twin from releasing every honest announcer of a txid.

  What we announce BACK is the mirror of that. A peer's known-tx filter
  (Core m_tx_inventory_known_filter) records every transaction it has told
  us about as well as every one we have told it about -- the inv, the tx
  message, and each parent of an orphan it delivered -- and it is keyed by
  the id THAT peer's inventory uses, wtxid once it negotiated wtxidrelay and
  txid otherwise, so a reader builds the inv first and looks the filter up by
  its hash; a site that writes a txid into a filter the relay path reads by
  wtxid is writing where nobody looks. The inv write sits OUTSIDE the IBD
  gate on purpose, so a peer that announced while we were still syncing is
  not told about the transaction afterwards.

  The per-peer announcement queue is never truncated -- a dropped entry is an announcement nothing re-queues,
  so that peer simply never hears of the transaction -- and the pressure
  valve instead is a drain that ACCELERATES with the backlog
  (INVENTORY_BROADCAST_TARGET + size/1000*5, capped at
  INVENTORY_BROADCAST_MAX). What it drains is the top of a heap ordered by
  the mempool's mining order with topology, not the front of a queue:
  \"topologically and fee-rate sort the inventory we send for privacy and
  priority reasons\", so the per-flush cut keeps the announcements worth the
  most and the order leaks mempool state rather than arrival order. The
  topology half is load-bearing -- a plain feerate sort would announce a
  child before its parent, which insertion order never does.

  Erlay's reconciliation sets are the one thing here with no Core to check
  against (Core ships the sendtxrcncl handshake and nothing else; BIP-330 is
  the specification), and their invariant is that a SUCCESSFUL round retires
  the whole frozen snapshot on both sides, not just the symmetric
  difference: the differing ids were just requested or announced, and the
  ids that CANCELLED in the sketch cancelled precisely because both sides
  hold them. Retiring only the difference left the cancelled ids in the set
  for the life of the connection, so every later sketch was sized against
  dead weight -- the bandwidth Erlay exists to save.

  Traps: `getheaders` must send the locator of the LAST header the peer
  gave us, never our own tip, or an ordinary lagging peer loops forever.
  The is-IBD answer is a one-way latch -- and both halves of Core's IBD gate
  on transactions read it, the inv handler and the tx handler, so a test
  driving either has to say which side of it the node is on. A reorg used to
  be triggered only by an ARRIVING block -- the sync pass now re-evaluates
  the best chain itself."
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
  side only. `-rpcwhitelist` gates the JSON-RPC surface only (Core
  registers the whitelist inside HTTPReq_JSONRPC, not around `/rest/`),
  keyed by the user name CHECK-AUTH returns, and a batch is refused as a
  unit when any member is off the list. A method is registered by its
  DEFINE-RPC form -- there is no list to forget it in. The REST interface and the web UI register their
  HTTP surfaces with REGISTER-HTTP-SURFACE at the end of their files;
  the server never names them.

  Traps: `+json-false+` is TRUTHY -- read positional booleans through
  the `positional-bool` helpers or a `(var :bool)` spec in the handler's
  DEFINE-RPC lambda list, never raw truthiness. A nested JSON
  array reaches a handler as a LIST, a top-level one as the empty-array
  sentinel; build test parameters through the request normalizer, not by
  hand. The wallet learns its `/wallet/<name>` endpoint from
  `*rpc-request-uri*`, never from the transport. A STORAGE-CONDITION is NOT
  an ERROR, so the three request boundaries handle it separately: a stack
  exhaustion answers -32603 once HANDLER-CASE has unwound, a heap exhaustion
  is left to propagate (RPC-RECOVERABLE-STORAGE-CONDITION-P)."
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
  (1,222 vectors, the 113 witness ones and the 5 autogenerated Taproot
  ones included). CastToBool treats a multi-byte negative zero as false.
  That corpus compares Core's ACCEPT/REJECT verdict AND, for every
  failing vector, Core's expected SCRIPT_ERR_* NAME -- the comparison
  Core's own runner makes (test/script_tests.cpp:134-135). Each
  ScriptError variant therefore stands for exactly ONE Core error:
  `script-error-name' in the engine states that for the variants, and
  `bl.interop:+script-errors+' states it for the keywords the CL layers
  return, together with the ScriptErrorString sentence Core puts in the
  parenthetical of `mempool-script-verify-flag-failed (%s)'. Several of
  ours may name one Core error (SE-StackUnderflow and
  SE-InvalidStackOperation are both INVALID_STACK_OPERATION); none may
  name two, or the corpus stops being able to compare the error at all.

  Traps: a Coalton or defstruct layout change needs a FRESH FASL volume
  -- the persistent volume keeps stale expansions through a warm rebuild,
  an image restart and an ordinary cold run. The script-execution cache
  keys on (wtxid, flags) and NOTHING else -- not the spent scriptPubKeys
  -- because the wtxid commits to every input's OUTPOINT and an outpoint
  names one output of one transaction, whose txid commits to that
  output's script and amount (Core states the assumption at
  validation.cpp:2069-2073 and asserts it on its only writing path,
  CheckInputsFromMempoolAndCache, :405-430). Block connect CONSULTS that
  cache and never writes it -- ConnectBlock sets `fCacheResults =
  fJustCheck' -- so the mempool's consensus pass is the only writer and
  both readers must pass the flag set the block will use.
  What FindAndDelete deletes is the signature's PUSH
  (Core `CScript() << vchSig'), never its bare bytes, and an EMPTY
  signature's pattern is the one byte OP_0 -- so it deletes something;
  every call site builds it through one helper because three of them
  once disagreed. A rule Core keeps in EvalScript applies to all three
  legacy scripts (scriptSig, scriptPubKey, P2SH redeem script) and to
  unexecuted branches: CONST_SCRIPTCODE's OP_CODESEPARATOR rejection is
  pre-scanned in verify-script for exactly that reason.
  A number decoded non-minimally is SCRIPTNUM, Core's CScriptNum
  exception; MINIMALDATA is the PUSH rule alone. A P2SH redeem-script
  hash mismatch is EVAL_FALSE, because Core has already run the
  scriptPubKey and stopped on its false top element before reaching the
  P2SH branch. A P2WPKH pubkey that does not hash to the program fails
  the implied script's OP_EQUALVERIFY, not the program match.
  An opcode that carries its OWN verify flag is a PLAIN NOP when that
  flag is off, never a discouraged one -- DISCOURAGE_UPGRADABLE_NOPS is
  OP_NOP1 and OP_NOP4..OP_NOP10's alone, and CLTV/CSV lost it when BIP65
  and BIP112 gave them flags. Core's IsPushOnly asks only whether the
  opcode is `> OP_16', which makes OP_RESERVED push-TYPE. CHECKMULTISIG
  charges its key count against the 201-op budget the moment it reads
  it, before any verification. CheckPubKeyEncoding runs for EVERY
  signature, an empty one included, so an ill-encoded key fails under
  STRICTENC with no signature to check at all. Both CHECKSIG paths --
  legacy/P2WSH and P2WPKH -- run ONE encoding check in Core's order
  (`check-checksig-encodings'): DER, then low-S, then the hashtype byte,
  and only then the pubkey arms, STRICTENC before WITNESS_PUBKEYTYPE.
  Low-S is an ENCODING rule, decided before any pubkey is looked at and
  before the verify; the P2WPKH path decides the pubkey encoding inside
  the CHECKSIG, as Core does, not ahead of the program match.
  The transaction version and the spent amount are SIGNED
  slots -- that is what the wire format reads back -- while Core streams
  them as raw words, so the BIP 143 and BIP 341 preimages write their bit
  patterns: a version with bit 31 set is legal and arrives here negative.

  `disassemble-script' is Core's ScriptToAsmStr and produces every `asm'
  field the node emits. It is Core's rendering, not a pretty-printer of
  our own: a push of four bytes or fewer is its CScriptNum value in
  DECIMAL (fRequireMinimal false), OP_0/OP_1NEGATE/OP_1..OP_16 spell
  0/-1/1..16 because that is what GetOpName returns for them, an unnamed
  opcode is OP_UNKNOWN, and a push running off the end ends the string
  with [error]. `:sighash-decode' is fAttemptSighashDecode and belongs to
  a scriptSig ALONE -- Core passes it from TxToUniv's scriptSig branch
  and decodepsbt's final_scriptSig, and suppresses it for an unspendable
  script so OP_RETURN data shaped like a signature is not read as one.

  CheckMinimalPush is ONE helper, `bl.interop:minimal-push-encoding-p',
  with three callers and no second copy: the interpreter applies it under
  the MINIMALDATA flag, while the solver's GetScriptNumber and
  miniscript's DecomposeScript apply it UNCONDITIONALLY, because both
  need the mapping from bytes to meaning to be one to one. That is also
  why `classify-script' reads the bare-multisig counts through
  GetScriptNumber rather than through the OP_1..OP_16 range: 17 through
  20 have no OP_n opcode and reach Core only as a minimal push."
  (bitcoin-lisp.coalton.script package)
  (bitcoin-lisp.coalton.interop package)
  (bitcoin-lisp.coalton.script:script-error-name function)
  (bitcoin-lisp.coalton.interop:+script-errors+ variable)
  (bitcoin-lisp.coalton.interop:script-error-keyword function)
  (bitcoin-lisp.coalton.interop:script-error-for-keyword function)
  (bitcoin-lisp.coalton.interop:script-error-name function)
  (bitcoin-lisp.coalton.interop:script-error-message function)
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
  checked by the functional tests). A reject reason is a keyword, or the
  list (KEYWORD SCRIPT-ERROR) the two script passes return so that
  TX-REJECT-REASON-STRING can render Core's
  `mempool-script-verify-flag-failed (<ScriptErrorString>)' parenthetical
  from `bl.interop:script-error-message'. Validation announces through the
  validation interface (`notify-block-connected` after the tip update and
  the mempool's conflict removals, then `notify-updated-block-tip`; the
  disconnect side tip-first in the reorg's commit phase) and calls nothing
  in `src/node/` by name. Signature validation of a block's
  scripts is batched and cached but never skipped -- same-block chained
  spends once bypassed it. A block's intra-block coin overlay obeys the
  same rules as the coins view it stands in for, so an output Core's
  AddCoin drops (provably unspendable) is never staged and a same-block
  spend of one fails as a MISSING INPUT rather than in the script engine.
  Long loops poll `interrupt-requested-p`
  between blocks so shutdown and the assumeutxo pause can cut in. A chain
  found INVALID that carries more than six blocks' worth of work beyond
  our tip raises Core's LARGE_WORK_INVALID_CHAIN warning
  (`%check-fork-warning-conditions`, re-evaluated after every activation
  step so it is lowered again when our own chain catches up); that is what
  the `warnings` RPC field and `-alertnotify` report, and it is why
  %MARK-BLOCK-SUBTREE-INVALID is the ONE place a block is marked invalid. VERIFY-DB
  is Core's CVerifyDB over the last `-checkblocks` blocks at `-checklevel`
  (defaults 6 and 3, the level clamped to 0-4): it runs at startup over
  every chainstate whose coins view names a block, and a
  :CORRUPTED-BLOCK-DB result refuses the start, the way Core's own
  `Corrupted block database detected` does. Level 3 is the one that
  compares the two databases -- it disconnects the tail into a scratch
  coins view over the chainstate's own LevelDB, never flushed -- so it is
  what catches a UTXO set that lost its coins under an unchanged tip.

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
  an honest header by mangling the body in transit. Every chain-dependent
  consensus value comes from the chain, never from a constant: the BIP94
  timewarp rule is gated on `bl.chain:enforce-bip94-p' (testnet4, and
  regtest under -test=bip94) and fires at the chain's own retarget period,
  144 on regtest and 2016 elsewhere. BOTH connect paths -- CONNECT-BLOCK
  and the reorg's commit phase -- ask HISTORICAL-CHAINSTATE-P before they
  touch the mempool or the tx-relay filters, because an assumeutxo
  background chainstate reaches the reorg path whenever it fast-forwards
  more than one block, and its blocks are ancient. The versionbits state
  machine REPORTS and tells the miner what to signal; it decides no
  activation. Its regtest deployment windows are the one thing an option
  can move: -vbparams=deployment:start:end[:min_activation_height] rewrites
  them through APPLY-VERSIONBITS-PARAMETERS, on regtest only, exactly as
  Core's ReadRegTestArgs feeds RegTestOptions. Miniscript's 201-op limit is
  a P2WSH rule and tapscript has none (miniscript.h:1566), which is also how
  the script interpreter gates it.

  Miniscript is the one part of this layer whose input DEPTH an attacker
  picks: `n:' costs one script byte and a tapscript leaf may be 329,482 of
  them, so a descriptor well under the RPC body limit carries a
  hundred-thousand-node tree. The parser and every walk over the result run
  on an EXPLICIT stack -- MS-PARSE is Core's state machine, and everything
  else goes through MS-TREE-EVAL (Core TreeEval, miniscript.h:645-752). Do
  not add a recursive walker: what one raises is a STORAGE-CONDITION, which
  is not an ERROR, so it escapes the RPC boundary and takes the worker thread
  with it."
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
  (bitcoin-lisp.validation:reset-fork-warning-state function)
  (bitcoin-lisp.validation:verify-db function)
  (bitcoin-lisp.validation:test-block-validity function)
  (bitcoin-lisp.validation:connect-block function)
  (bitcoin-lisp.validation:activate-best-chain function)
  (bitcoin-lisp.validation:perform-reorg function)
  (bitcoin-lisp.validation:versionbits-state function)
  (bitcoin-lisp.validation:apply-versionbits-parameters function)
  (bitcoin-lisp.validation:compute-block-version function)
  (bitcoin-lisp.validation:versionbits-gbt-status function)
  (bitcoin-lisp.validation:check-signet-block-solution function))

(defsection @mempool (:title "mempool: the pool and its policy")
  "Core: `txmempool.cpp`, `txgraph.cpp`, `cluster_linearize.h`,
  `policy/rbf.cpp`, `policy/truc_policy.cpp`, `txorphanage.cpp`,
  `policy/fees.cpp`, `kernel/mempool_persist.cpp`. Policy, never
  consensus: a rule here decides what we relay and mine, not what is
  valid.

  Invariants: the cluster mempool keeps every cluster linearized; the
  mining chunk index is maintained incrementally -- one extract and one
  insert per changed chunk, never a rebuild over the pool; RBF and TRUC
  checks run in Core's order with Core's limits; mempool.dat is written
  in Core's format so the two implementations can exchange one.

  The txgraph measures SIGOP-ADJUSTED WEIGHT, as Core's does: entries are
  staged with max(weight, sigops * 20) and the cluster cap is 404000 WU
  (the configured 101 kvB times WITNESS_SCALE_FACTOR). The division to
  virtual bytes happens only at the consumer boundary --
  `feefrac-per-vsize', Core's ToFeePerVSize -- and only where Core applies
  it: the rolling minimum fee bumped from an evicted chunk and the block
  assembler's `-blockmintxfee' comparison. The chunk feerates the RPCs
  report are Core's weight units, unconverted.

  Fee estimation reads the block policy estimator and NOTHING else: the
  absence of an estimate is reported as absence (Core's `Insufficient data
  or no feerate found'), never as a percentile of what miners took, which
  is the one thing that cannot say a feerate FAILED to confirm. What the
  estimator is fed is gated as Core gates it -- a transaction is recorded
  only at the estimator's own best seen height, and only when it was not
  re-added by a reorg with the limits bypassed, not submitted in a
  package, the chainstate is current, and it has no unconfirmed parents.
  The last of those is why a CPFP child does not teach the estimator that
  its own low feerate confirmed in one block.

  Traps: dividing a size before comparing feerates is not a rounding
  detail -- it decides chunk BOUNDARIES, so a per-transaction ceiling
  applied first turns one CPFP chunk into two and flips a strict mining
  order. A rule that BOUNDS a later step's work has to RUN before it, and
  a LET binding runs where it is bound rather than where it is read --
  rule 5's cluster cap is the bound on the RBF descendant expansion, so
  the expansion cannot be a sibling binding of the guard that limits it.
  An 83 MB mempool.dat turns a restart into a long silent replay
  -- load in batches and log progress. The policy estimator must EXIST
  before fee_estimates.dat is loaded, or the file's estimator section is
  discarded on every start. The mining index
  finds a chunk by its mining key, so a cluster's chunks must leave the
  index before anything changes that key -- a relinearization, a depgraph
  edit, or a re-pointing of its handles; that is also why a handle's
  caller payload is passed to `txgraph-add-transaction` instead of being
  assigned to the handle it returns."
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
  (bitcoin-lisp.mempool:make-block-policy-estimator function)
  (bitcoin-lisp.mempool:*block-policy-estimator* variable)
  (bitcoin-lisp.mempool:save-mempool-file function)
  (bitcoin-lisp.mempool:*persist-mempool-v1* variable))

(defsection @mining (:title "mining: block templates")
  "Core: `node/miner.cpp`. Transaction selection walks the mempool's
  linearized chunks under the weight and sigop limits, builds the coinbase
  and the witness commitment, and the regtest miner solves the header.

  Invariants: the template honours `-blockmaxweight`,
  `-blockreservedweight` and `-blockmintxfee` exactly as Core's
  BlockAssembler does; getblocktemplate follows the miner contract of
  BIP22/BIP23; every coinbase-construction site gates the BIP141 reserved
  witness on `bl.val:segwit-active-at-height-p` -- the commitment OUTPUT
  is unconditional, the WITNESS is not, and a block carrying one below
  the segwit height is rejected `:unexpected-witness'.

  The template's nVersion is Core's ComputeBlockVersion over the
  versionbits state machine -- every STARTED or LOCKED_IN deployment's bit
  -- and `-blockversion' replaces it on regtest alone, as Core gates that
  on MineBlocksOnDemand(). getblocktemplate reports the same machine's
  three groups: signalling and locked-in in `vbavailable', active in
  `rules'.

  Traps: the chunk feerate the builder hands out is fee per sigop-adjusted
  WEIGHT, so it converts through `bl.mp:feefrac-per-vsize' before meeting
  `-blockmintxfee', which is a sat-per-1000-VBYTE rate (Core's
  ToFeePerVSize at miner.cpp:294). The reserved weight exists because the
  header and the transaction-count varint count toward the block weight. The BIP94
  mintime floor applies on EVERY network, whether or not the rule is
  consensus there, at the chain's own retarget period. MINE-BLOCK
  returns the number of FAILED nonces as a second value, because
  `maxtries' is one budget for a whole generate* call rather than a fresh
  allowance per block, and an exhausted budget returns the blocks already
  mined instead of erroring."
  (bitcoin-lisp.mining package)
  (bitcoin-lisp.mining:assemble-block-template function)
  (bitcoin-lisp.mining:block-template class)
  (bitcoin-lisp.mining:build-coinbase-transaction function)
  (bitcoin-lisp.mining:assemble-full-block function)
  (bitcoin-lisp.mining:mine-block function)
  (bitcoin-lisp.mining:next-block-required-bits function)
  (bitcoin-lisp.mining:next-block-version function)
  (bitcoin-lisp.mining:next-block-mintime function)
  (bitcoin-lisp.mining:*block-version-override* variable)
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
  wait. Error codes and messages are Core's. REST checks RPC warmup at
  its single dispatch point (Core calls CheckWarmup at the head of every
  handler) and answers HTTP 503 until the node is ready.

  Every transaction hex an RPC is handed goes through `decode-hex-tx\',
  Core\'s DecodeHexTx: the bytes are read BOTH ways, a reading counts only
  when it consumes all of them (so trailing bytes are -22 and not a
  transaction whose txid names a prefix), and CheckTxScriptsSanity breaks
  the tie. `iswitness\' restricts which readings are tried.

  createrawtransaction, createpsbt and walletcreatefundedpsbt share Core's
  ONE AddInputs rule for a per-input nSequence (`default-input-sequence\'):
  `replaceable\' is an OPTIONAL bool whose absence means TRUE, so the
  default sequence is 0xfffffffd and only an explicit false falls through
  to 0xfffffffe (locktime set) or 0xffffffff. An all-final transaction
  makes its own nLockTime unenforceable, which is why the default matters.

  Every scriptPubKey object the RPC and REST surfaces emit is
  `script-to-json\', Core's ScriptToUniv, in Core's key order (asm, desc,
  hex, address, type) -- there is no second copy to drift, and the
  verbosity-3 prevout object is the same helper as the vout. Its `desc'
  is Core's InferScript with no signing provider, so the TYPED arms come
  first -- pk() for a bare pubkey, multi() for a bare multisig, rawtr()
  for a taproot output whose program is a valid x-only key -- and only
  then addr(), with raw() last. `decodescript\'
  is that object plus Core's can_wrap and can_wrap_P2WSH gates: a P2SH
  wrapper is offered only for a script that may be wrapped, which is why
  a NULL_DATA, a SCRIPTHASH, a taproot output, an ANCHOR, an unknown
  witness version, an unparseable script and one carrying OP_CHECKSIGADD
  or an OP_SUCCESS get none, and the segwit object only for the four
  types that survive can_wrap_P2WSH with compressed keys. reqSigs and the
  plural addresses are Core's pre-v22 shape and are gone.

  Trap: the recurring failure shape in this tree is correct code with
  the wrong or missing caller -- an index built but never maintained, a
  check present but never reached. Test the wire, not the function."
  (bitcoin-lisp.rpc:with-node-lock macro)
  (bitcoin-lisp.rpc:script-to-json function)
  (bitcoin-lisp.rpc:script->address function)
  (bitcoin-lisp.rpc:decode-tx function)
  (bitcoin-lisp.rpc:decode-hex-tx function)
  (bitcoin-lisp.rpc:default-input-sequence function)
  (bitcoin-lisp.rpc:parse-outputs function)
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
  script construction change must invalidate it; a stored transaction
  record that will not load is Core's `NEED_RESCAN` -- the wallet still
  loads, and the catch-up rescans from height 0 instead of from the
  stored locator, which no longer describes what is in memory; the record
  scan is a DRIVER (`map-wallet-db-records`), so a load and a backup cost
  one record of heap and not the wallet file, while a scan stopped by a bad
  block still signals rather than returning a short set; and every failure
  of the database itself answers Core's `DatabaseStatus` pair -- the cheap
  format probe (`wallet-db-format-recognized-p`, Core's `IsSQLiteFile`)
  gives -18, anything past it gives -4, and a storage condition never
  reaches a client as an internal error. The
  options Core reads once into a wallet field are process specials here
  (`-addresstype`, `-changetype`, `-avoidpartialspends`): Core stores them
  per wallet but only ever writes them from the node's own arguments, so
  every wallet in a process holds the same value.
  `-avoidpartialspends` is the INITFORM of the coin control's slot, as it
  is Core's CCoinControl constructor, so the two writers that remain --
  the avoid_reuse argument and the -maxapsfee retry -- can only raise it.

  Traps: a locked wallet could once still sign because a parsed
  descriptor kept its embedded xprv; the key-provider is the only source
  now. RENAME-FILE merges a target pathname with the source, so a backup
  that renamed wrote nothing. Core SORTS musig participants (BIP328); an
  x-only print flag is not the 32-vs-33-byte push decision. `encryptwallet`
  ends in a database REWRITE, not a compaction: deleting the plaintext key
  records only tombstones them, and the compaction that stood there left the
  master secret in a live `.ldb` on every wallet young enough to matter."
  (bitcoin-lisp.wallet package)
  (bitcoin-lisp.wallet:wallet-manager class)
  (bitcoin-lisp.wallet:init-wallet-manager function)
  (bitcoin-lisp.wallet:load-wallets-on-startup function)
  (bitcoin-lisp.wallet:close-wallet-manager function)
  (bitcoin-lisp.wallet:wallets-block-connected function)
  (bitcoin-lisp.wallet:wallets-block-disconnected function)
  (bitcoin-lisp.wallet:wallets-mempool-tx-added function)
  (bitcoin-lisp.wallet:wallets-maybe-resend function)
  (bitcoin-lisp.wallet:set-wallet-default-output-type function)
  (bitcoin-lisp.wallet:*wallet-default-address-type* variable)
  (bitcoin-lisp.wallet:*wallet-default-change-type* variable)
  (bitcoin-lisp.wallet:*wallet-avoid-partial-spends* variable)
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
  Core's meaning of clean, error and watchdog. -blocknotify runs only
  once the node is past init (Core's POST_INIT gate) -- the same
  :updated-block-tip event also drives -stopatheight and the periodic
  flush, which must keep firing during IBD, so each subscriber decides
  for itself rather than the announcement being filtered. WHICH trigger
  fired reaches the flush: a write driven by the clock or the block count
  syncs the coins cache and KEEPS its entries, and only the size tier, a
  critical flush, shutdown and reindex empty it (Core's empty_cache,
  validation.cpp:2761-2766).

  Traps: a changed DEFCONSTANT needs an image RESTART -- the warm image
  goes stale whichever way the continuable error is answered; a changed
  MACRO or defstruct needs a fresh FASL volume. Re-derive process state
  from the machine, never from a notification. A DEFVAR initform runs at
  ASDF LOAD time, before INIT-NODE seeds anything, so per-process
  randomness belongs in the start-up path: SEED-EVICTION-NETGROUP-KEY is
  drawn there, next to SEED-GLOBAL-RANDOM-STATE, as Core draws its
  CConnman seeds at AppInitMain."
  (bitcoin-lisp package)
  (bitcoin-lisp:node class)
  (bitcoin-lisp:*node* variable)
  (bitcoin-lisp:start-node function)
  (bitcoin-lisp:start-node-from-args function)
  (bitcoin-lisp:stop-node function)
  (bitcoin-lisp:node-main function)
  (bitcoin-lisp::args->start-node-plist function)
  (bitcoin-lisp::apply-config-globals function)
  (bitcoin-lisp::resolve-conf-path function)
  (bitcoin-lisp::check-config-file-readable function)
  (bitcoin-lisp::check-ignored-config-file function)
  (bitcoin-lisp::blocks-dir-path function)
  (bitcoin-lisp::signet-chain-params function)
  (bitcoin-lisp::should-persist-mempool-p function)
  (bitcoin-lisp::save-mempool-at-shutdown function)
  (bitcoin-lisp:sync-blockchain function)
  (bitcoin-lisp:node-status function)
  (bitcoin-lisp:request-node-shutdown function)
  (bitcoin-lisp:node-shutdown-requested-p function)
  (bitcoin-lisp:run-node-watchdog function)
  (bitcoin-lisp:effective-prune-target-bytes function)
  (bitcoin-lisp::seed-global-random-state function)
  (bitcoin-lisp::tip-notification-post-init-p function)
  (bitcoin-lisp::seed-eviction-netgroup-key function)
  (bitcoin-lisp:*blocksonly* variable)
  (bitcoin-lisp:*wallet-broadcast* variable)
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

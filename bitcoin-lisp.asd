;;; Ensure local coalton checkout is found by ASDF
;;; Use *load-pathname* since system isn't defined yet
(eval-when (:compile-toplevel :load-toplevel :execute)
  (let* ((this-file (or *compile-file-pathname* *load-pathname*))
         (coalton-path (when this-file
                         (merge-pathnames "refs/coalton/" (make-pathname :directory (pathname-directory this-file))))))
    (when (and coalton-path (probe-file coalton-path))
      (pushnew coalton-path asdf:*central-registry* :test #'equal))))

(defsystem "bitcoin-lisp/util"
  :description "The chain-agnostic base every other layer builds on: the
bl.* package nicknames, the condition hierarchy, index-based byte I/O with
CompactSize, chain parameters and the node-context struct. No project
package above it exists while it compiles, so an upward reference here is
a compile error, not a layering-test entry."
  :depends-on ("ironclad" "flexi-streams" "alexandria")
  :pathname "src"
  :serial t
  :components ((:file "util/package")
               (:file "util/conditions")
               (:module "util"
                :components ((:file "bytes")
                             (:file "chainparams")
                             (:file "context")
                             (:file "ratelimit")
                             (:file "validation-interface")))))

(defsystem "bitcoin-lisp/crypto"
  :description "Hashes, ChaCha20, MuHash, the libsecp256k1 FFI, BIP324
key exchange, addresses, BIP32 and the OS randomness source -- everything
Bitcoin needs from cryptography and nothing that needs Bitcoin's chain
state. Depends on the util layer for chain parameters (bech32 HRPs) only."
  :depends-on ("bitcoin-lisp/util" "ironclad" "cffi" "nibbles" "flexi-streams" "alexandria")
  :pathname "src"
  :serial t
  :components ((:file "crypto/package")
               (:module "crypto"
                :components ((:file "hash")
                             ;; after hash: RAND-U64 assembles its bytes with
                             ;; BYTES-TO-UINT64-LE
                             (:file "random")
                             (:file "crypter")
                             (:file "chacha20")
                             (:file "muhash")
                             (:file "secp256k1")
                             (:file "bip324")
                             (:file "address")
                             (:file "bip32")))))

(defsystem "bitcoin-lisp/logging"
  :description "The node's log (levels, Core-style categories, ring buffer,
file stream, rate limiter, deferred lines, notify hooks): package
bitcoin-lisp.logging, which the main package :USEs and re-exports."
  :depends-on ("bitcoin-lisp/util" "bordeaux-threads" "alexandria")
  :pathname "src"
  :components ((:file "logging")))

(defsystem "bitcoin-lisp/config"
  :description "The option registry (DEFINE-OPTION) and the parsers for the
command line, bitcoin.conf, settings.json and option values -- Core's
common/args.cpp, config.cpp and settings.cpp without the option table,
which the chain above supplies (src/config-options.lisp)."
  :depends-on ("bitcoin-lisp/util" "bitcoin-lisp/crypto" "bitcoin-lisp/logging" "yason")
  :pathname "src"
  :serial t
  :components ((:file "config/package")
               (:module "config"
                :components ((:file "registry")   ; the table's mechanism, and reading a value its way
                             (:file "values")     ; one option value: ints, bools, money, hex, proxies, binds
                             (:file "args")       ; the command line
                             (:file "conf")       ; bitcoin.conf
                             (:file "settings")   ; settings.json
                             (:file "merge"))))) ; one merged alist from all three

(defsystem "bitcoin-lisp/kv"
  :description "Persistence primitives: the LevelDB binding, flat file
sequences with XOR obfuscation, the datadir layout, fsync. Package
bitcoin-lisp.kv, which bitcoin-lisp.storage :USEs and re-exports."
  :depends-on ("bitcoin-lisp/util" "bitcoin-lisp/crypto" "bitcoin-lisp/logging" "cffi" "bordeaux-threads" "ironclad" "alexandria")
  :pathname "src"
  :serial t
  :components ((:file "kv/package")
               (:module "kv"
                :components ((:file "fsync")
                             (:file "datadir")
                             (:file "flatfile")
                             (:file "leveldb")))))

(defsystem "bitcoin-lisp/serialization"
  :description "Bitcoin's wire and disk encodings: the byte codecs, the
transaction / block / header types, CompactSize, the P2P message table
(define-message), the UTXO compressor and PSBT. Chain-specific, but it
needs nothing above util and crypto, so it is a layer of its own."
  :depends-on ("bitcoin-lisp/util" "bitcoin-lisp/crypto" "flexi-streams" "cl-base64" "alexandria")
  :pathname "src"
  :serial t
  :components ((:file "serialization/package")
               (:module "serialization"
                :components ((:file "binary")
                             (:file "compressor")
                             (:file "types")
                             (:file "message-macro")
                             (:file "messages")
                             (:file "psbt")))))

(defsystem "bitcoin-lisp/storage"
  :description "The block store, undo data, the coins view and its cache,
the header/block index, reindexing, and the four optional indexes -- on top
of the kv and serialization layers. The pruning policy knobs live here
(prune-policy.lisp) so the store never reaches up into the node."
  :depends-on ("bitcoin-lisp/util" "bitcoin-lisp/crypto" "bitcoin-lisp/logging"
               "bitcoin-lisp/kv" "bitcoin-lisp/serialization"
               "flexi-streams" "ironclad" "bordeaux-threads" "alexandria")
  :pathname "src"
  :serial t
  :components ((:file "storage/package")
               (:module "storage"
                :components ((:file "prune-policy")
                             (:file "utxo")
                             (:file "block-undo")
                             (:file "blocks")
                             (:file "coins-view")
                             (:file "coins-view-cache")
                             (:file "coins-view-migration")
                             (:file "chain")
                             (:file "reindex")
                             (:file "migrate-blocks")
                             (:file "index-base")      ; the protocol the four indexes below implement
                             (:file "txindex")
                             (:file "txospenderindex")
                             (:file "blockfilter")
                             (:file "blockfilterindex")
                             (:file "coinstatsindex")))))

(defsystem "bitcoin-lisp/net"
  :description "The transport layer below the Bitcoin protocol: poll-based
readiness, TCP connections through an optional SOCKS5 proxy, the BIP324 v2
transport, BIP155 addresses and reachability, addrman with its peers.dat,
the Tor control client and minisketch. The protocol itself -- peer,
protocol, headers-sync, ibd, txreconciliation-set -- stays in the main
system, in this same package, because it drives validation and the mempool."
  :depends-on ("bitcoin-lisp/util" "bitcoin-lisp/crypto" "bitcoin-lisp/logging"
               "bitcoin-lisp/kv" "bitcoin-lisp/serialization"
               "usocket" "bordeaux-threads" "ironclad" "flexi-streams" "alexandria")
  :pathname "src"
  :serial t
  :components ((:file "networking/package")
               (:module "networking"
                :components ((:file "fd-wait")    ; before everything: poll-based readiness (select's fd ceiling)
                             (:file "minisketch")
                             (:file "socks5")     ; before connection: make-tcp-connection tunnels through *proxy*
                             (:file "connection")
                             (:file "v2-transport")
                             (:file "peerdb")
                             (:file "netaddress") ; BIP155 codecs/reachability; before addrman (netgroups)
                             (:file "addrman")
                             (:file "torcontrol")))))

(defsystem "bitcoin-lisp/rpc-server"
  :description "The JSON-RPC-over-HTTP server without its methods: request
parsing and replies (1.0/1.1/2.0, batches, named parameters), the cookie and
-rpcauth credentials, the address ACL, the unauthenticated-side rate limit,
warmup, and DEFINE-RPC -- the registry a chain's handlers add themselves to.
The handlers, the REST interface and the web UI are the main system's, in
this same package."
  :depends-on ("bitcoin-lisp/util" "bitcoin-lisp/crypto" "bitcoin-lisp/logging"
               "bitcoin-lisp/net"
               "hunchentoot" "yason" "usocket" "bordeaux-threads" "ironclad"
               "flexi-streams" "cl-base64")
  :pathname "src"
  :serial t
  :components ((:file "rpc/package")
               (:file "rpc/errors")
               (:file "rpc/define-rpc")
               (:file "rpc/json")
               (:file "rpc/server")))

(defsystem "bitcoin-lisp"
  :version "0.1.0"
  :author "samdefmacro"
  :license "MIT"
  :description "Bitcoin full node implementation in Common Lisp"
  :depends-on ("bitcoin-lisp/util"
               "bitcoin-lisp/crypto"
               "bitcoin-lisp/logging"
               "bitcoin-lisp/config"
               "bitcoin-lisp/kv"
               "bitcoin-lisp/serialization"
               "bitcoin-lisp/storage"
               "bitcoin-lisp/net"
               "bitcoin-lisp/rpc-server"
               "ironclad"
               "nibbles"
               "cffi"
               "usocket"
               "flexi-streams"
               "alexandria"
               "bordeaux-threads"
               "coalton"
               "hunchentoot"
               "yason"
               "cl-base64")
  :serial t
  :components ((:module "src"
                :components
                (;; Packages first, all of them: config.lisp (fourth) already
                 ;; names later packages, and src/package.lisp -- last,
                 ;; because its top package :USEs the others -- installs the
                 ;; bl.* nicknames on every package that exists by then.
                 ;; Each module's package lives next to its code.
                 ;; bitcoin-lisp/util and bitcoin-lisp/crypto load before this
                 ;; system (:depends-on): their packages, nicknames and
                 ;; conditions already exist here.
                 (:file "validation/package")
                 (:file "mempool/package")
                 (:file "mining/package")
                 (:file "package")
                 ;; util first: byte I/O that the script interpreter's
                 ;; sighash code inlines must be loaded before src/coalton/.
                 (:file "config")
                 ;; The node struct and *node* (Core node/context.h) load
                 ;; right after the globals: every layer above validation
                 ;; reads the node's slots, and this file needs only the
                 ;; packages and the storage layer below it. It used to be
                 ;; the second file of src/node/ -- the LAST module -- so the
                 ;; rpc, wallet, networking and mining references to it were
                 ;; upward, invisible to a package-level layering test.
                 (:file "node/state")
                 (:file "zmq")
                 (:module "coalton"
                  :components ((:file "package")
                               (:file "types")
                               (:file "crypto")
                               (:file "binary")
                               (:file "serialization")
                               (:file "script")
                               (:file "interop")))
                 (:module "mempool"
                  :components ((:file "feefrac")
                               (:file "cluster-linearize")
                               (:file "spanning-forest")
                               (:file "txgraph")
                               (:file "orphan")
                               (:file "mempool")
                               (:file "block-policy-estimator")
                               (:file "fee-estimator")))
                 ;; Validation names the mempool -- MemPoolAccept lives in Core's
                 ;; validation.cpp too -- and the mempool never names
                 ;; validation, so the mempool loads first.
                 (:module "validation"
                  :components ((:file "script")
                               (:file "solver")
                               (:file "miniscript")
                               (:file "transaction")
                               (:file "packages")
                               (:file "block")
                               (:file "versionbits")
                               (:file "signet")))
                 (:module "mining"
                  :components ((:file "assembler")
                               (:file "builder")))
                 ;; The transport below these (connection, addrman, tor, ...)
                 ;; is bitcoin-lisp/net; these are the protocol on top of it.
                 (:module "networking"
                  :components ((:file "p2p-handlers")
                               (:file "txreconciliation-set")
                               (:file "peer")
                               (:file "protocol")
                               (:file "headers-sync")
                               (:file "ibd")))
                 ;; The server itself is bitcoin-lisp/rpc-server; these are
                 ;; the chain's methods, on top of it.
                 (:module "rpc"
                  :components ((:file "core-tables")
                               (:file "accessors")
                               (:file "amounts")
                               (:file "descriptors")
                               ;; The handlers, one file per Core rpc/*.cpp.
                               (:file "blockchain")
                               (:file "net")
                               (:file "mempool")
                               (:file "rawtransaction")
                               (:file "node")
                               (:file "mining")
                               (:file "output-script")
                               (:file "signmessage")))
                 ;; The wallet (Core wallet/ and wallet/rpc/): its own package,
                 ;; after the RPC helpers it uses and before the server files
                 ;; that reach into it.
                 (:module "wallet"
                  :serial t
                  :components ((:file "package")
                               (:file "wallet-store")
                               (:file "wallet")
                               (:file "wallet-crypt")
                               (:file "wallet-tx")
                               (:file "wallet-coins")
                               (:file "wallet-spend")
                               (:file "psbt")
                               (:file "signmessage")))
                 ;; The RPC server proper, last: it dispatches to everything above.
                 (:module "rpc-server"
                  :pathname "rpc"
                  :serial t
                  :components ((:file "merkleproof")
                               (:file "rest")
                               (:file "ui")))
                 ;; The option table: after every module whose specials its
                 ;; :global / :apply rows name, before the node that reads it.
                 (:file "config-options")
                 ;; The node itself (Core init.cpp / bitcoind.cpp), one file
                 ;; per concern; init.lisp (start-node and the executable's
                 ;; entry point) last, since it drives everything above it.
                 (:module "node"
                  :serial t
                  :components (
                               (:file "params")
                               (:file "args")      ; the parsed options meet the node
                               (:file "notify")
                               (:file "datadir")
                               (:file "rpc-config")
                               (:file "logging")
                               (:file "entropy")
                               (:file "housekeeping")
                               (:file "eviction")
                               (:file "recovery")
                               (:file "listen")
                               (:file "mempool-persist")
                               (:file "assumeutxo")
                               (:file "shutdown")
                               (:file "indexes")
                               (:file "flush")
                               (:file "reindex")
                               (:file "wallet-hooks")
                               (:file "peers")
                               (:file "sync")
                               (:file "init"))))))
  :in-order-to ((test-op (test-op "bitcoin-lisp/tests"))))

(defsystem "bitcoin-lisp/tests"
  :depends-on ("bitcoin-lisp"
               "fiveam"
               "yason"
               ;; structural-tests reads SB-INTROSPECT:WHO-CALLS at COMPILE
               ;; time, so the package must exist before the file is compiled;
               ;; the warm image has it only because Swank pulls it in, and the
               ;; cold battery loads no Swank.
               (:require "sb-introspect"))
  :components ((:module "tests"
                :components ((:file "support/package")  ; the shared fixtures, before the package that :USEs them
                             (:file "support/fixtures")
                             (:file "support/transactions")
                             (:file "support/chain")
                             (:file "support/mempool-fixtures")
                             (:file "support/wallet")
                             (:file "package")
                             (:file "crypto/crypto-tests")
                             (:file "serialization/serialization-tests")
                             (:file "storage/storage-tests")
                             (:file "validation/validation-tests")
                             (:file "integration-tests")
                             ;; Coalton tests
                             (:file "coalton/coalton-package")
                             (:file "coalton/coalton-types-tests")
                             (:file "coalton/coalton-crypto-tests")
                             (:file "coalton/coalton-serialization-tests")
                             (:file "coalton/coalton-binary-tests")
                             (:file "coalton/coalton-script-tests")
                             ;; Bitcoin Core compatibility tests
                             (:file "coalton/bitcoin-core-script-tests")
                             ;; IBD tests
                             (:file "networking/ibd-tests")
                             ;; Mempool tests
                             (:file "mempool/mempool-tests")
                             ;; Cluster mempool: FeeFrac + CompareChunks (Core feefrac_tests.cpp)
                             (:file "mempool/feefrac-tests")
                             ;; Cluster mempool: DepGraph/chunking/linearization
                             (:file "mempool/cluster-linearize-tests")
                             (:file "mempool/spanning-forest-tests")
                             ;; Cluster mempool: txgraph engine (Core txgraph.{h,cpp})
                             (:file "mempool/txgraph-tests")
                             ;; Cluster mempool P3: shadow-mode mempool/txgraph equivalence
                             (:file "mempool/mempool-shadow-tests")
                             ;; Package relay tests (submitpackage)
                             (:file "validation/package-tests")
                             ;; Opportunistic 1p1c package relay over P2P
                             (:file "networking/package-relay-tests")
                             ;; Mining / regtest tests
                             (:file "mining/mining-tests")
                             ;; Deserializer robustness / fuzz tests
                             (:file "robustness-tests")
                             ;; Serialize<->deserialize round-trip property tests
                             (:file "util/roundtrip-tests")
                             ;; Core SanitizeString, the peer-string boundary filter
                             (:file "util/sanitize-tests")
                             ;; Script SCRIPT_VERIFY flag-gating matrix
                             (:file "coalton/script-flag-tests")
                             ;; Inbound listening + handshake
                             (:file "networking/inbound-listening-tests")
                             ;; Serving getheaders/getblocks/getaddr to peers
                             (:file "networking/serve-requests-tests")
                             ;; Persistence, peer health, reorg tests
                             (:file "storage/persistence-tests")
                             ;; RPC tests
                             (:file "rpc/rpc-tests")
                             ;; Output descriptor engine (Core descriptor_tests.cpp vectors)
                             (:file "wallet/descriptor-tests")
                             ;; Web UI serving + Origin-check tests (gui-plan P0)
                             (:file "rpc/ui-tests")
                             ;; Mainnet support tests
                             (:file "mainnet-tests")
                             ;; Pruning tests
                             (:file "storage/pruning-tests")
                             ;; Peer database tests
                             (:file "networking/peerdb-tests")
                             ;; Address manager (new/tried buckets) tests
                             (:file "networking/addrman-tests")
                             ;; Compact block relay tests (BIP 152)
                             (:file "networking/compact-block-tests")
                             (:file "kv/db-cache-tests")
                               (:file "structural-tests")
                             ;; ADDRv2 tests (BIP 155)
                             (:file "networking/addrv2-tests")
                             ;; Network-typed address codecs (onion/i2p/base32) + reachability
                             (:file "networking/netaddress-tests")
                             ;; DoS protection tests
                             (:file "networking/dos-protection-tests")
                             ;; Difficulty adjustment tests
                             (:file "storage/difficulty-tests")
                             (:file "validation/signet-tests")
                             ;; Block weight tests (BIP 141)
                             (:file "serialization/weight-tests")
                             ;; Sigops validation tests
                             (:file "validation/sigops-tests")
                             ;; Bitcoin Core comparison feature tests
                             (:file "validation/new-features-tests")
                             ;; Bitcoin Core sighash test vectors
                             (:file "coalton/bitcoin-core-sighash-tests")
                             ;; Chain reorganization tests
                             (:file "validation/reorg-tests")
                             ;; Block validation end-to-end tests
                             (:file "validation/block-e2e-tests")
                             ;; Bitcoin Core tx_valid/tx_invalid test vectors
                             (:file "validation/bitcoin-core-tx-tests")
                             ;; Merkle tree edge case tests
                             (:file "validation/merkle-tests")
                             ;; Bitcoin Core BIP 341 taproot test vectors
                             (:file "coalton/bitcoin-core-bip341-tests")
                               (:file "crypto/bitcoin-core-vector-tests")
                             (:file "crypto/bitcoin-core-key-io-tests")
                             (:file "mempool/block-policy-estimator-tests")
                             (:file "node/zmq-tests")
                             ;; -blocknotify / -shutdownnotify operator hooks
                             (:file "node/notify-tests")
                             ;; BIP 158 compact block filter tests
                             (:file "storage/blockfilter-tests")
                             ;; BIP 174 PSBT tests
                             (:file "serialization/psbt-tests")
                             ;; BIP 324 cipher suite tests
                             (:file "crypto/bip324-crypto-tests")
                             ;; BIP 324 v2 transport loopback tests
                             (:file "networking/bip324-transport-tests")
                             ;; MuHash3072 tests
                             (:file "crypto/muhash-tests")
                             ;; coinstatsindex tests
                             (:file "storage/coinstatsindex-tests")
                             (:file "storage/txospenderindex-tests")
                             (:file "validation/versionbits-tests")
                             ;; -reindex-chainstate tests
                             (:file "storage/reindex-tests")
                             ;; Connection types (block-relay-only + feeler)
                             (:file "networking/conn-type-tests")
                             ;; Low-work headers sync (anti-DoS presync/redownload)
                             (:file "networking/headers-sync-tests")
                             ;; Wave 9A: eclipse/DoS hardening (outbound accounting,
                             ;; non-blocking send, addr rate limit, generic presync)
                             (:file "networking/eclipse-dos-tests")
                             ;; bitcoin.conf + CLI argument parsing
                             (:file "config/config-tests")
                             ;; The chain-params table
                             (:file "util/chainparams-tests")
                             (:file "logging/logging-tests")
                             ;; SOCKS5 outbound proxy (-proxy) client
                             (:file "networking/socks5-tests")
                             ;; Tor control client + onion service + self-advertisement
                             (:file "networking/torcontrol-tests")
                             ;; TxOutCompression + hash_serialized_3
                             (:file "serialization/compressor-tests")
                             (:file "storage/block-undo-tests")
                             (:file "validation/miniscript-tests")
                             (:file "networking/minisketch-tests")
                             (:file "networking/txreconciliation-set-tests")
                             (:file "kv/flatfile-tests")
                             ;; Assumeutxo snapshot format (dumptxoutset/loadtxoutset)
                             (:file "storage/snapshot-tests")
                             ;; Chainstate list + selection accessors + storage suffix
                             (:file "storage/chainstate-tests")
                             ;; Assumeutxo P4: dual chainstate + background IBD
                             (:file "storage/assumeutxo-tests")
                             ;; Wallet P1: container + keystore + wallet RPCs
                             (:file "wallet/wallet-tests")
                             ;; Wallet P2: chain tracking (hooks, TxState,
                             ;; conflicts, rescan, tx RPCs)
                             (:file "wallet/wallet-chain-tests")
                             ;; Wallet P3: balances, coins, labels,
                             ;; getaddressinfo, abandontransaction
                             (:file "wallet/wallet-balance-tests")
                             ;; Wallet P4: coin selection, spending RPCs,
                             ;; wallet signing, rebroadcast
                             (:file "wallet/wallet-spend-tests")
                             ;; Wallet P6: crypter KATs, encryption lifecycle,
                             ;; locked-wallet gating, relock timer, backup
                             (:file "wallet/wallet-encryption-tests")
                             ;; Process RNG seeding (*random-state* must not
                             ;; replay SBCL's build-time stream on every start)
                             (:file "crypto/entropy-tests")
                             ;; Wave 10: RPC boolean/error-code parity, HTTP
                             ;; layer, BIP64 getutxos, config wires, arg
                             ;; handling, banlist persistence
                             (:file "wave10-tests")
                             ;; GA8 W1-A: intra-block coin overlay (chained-spend
                             ;; script validation + same-block double spends)
                             (:file "validation/intrablock-coins-tests")
                             ;; Randomised totality/roundtrip properties over
                             ;; the parsers a hostile peer reaches
                             (:file "fuzz-property-tests"))))
  :perform (test-op (op c)
                    (symbol-call :fiveam :run! :bitcoin-lisp-tests)))

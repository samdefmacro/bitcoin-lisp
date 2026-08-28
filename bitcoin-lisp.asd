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
  :depends-on ("ironclad" "flexi-streams")
  :pathname "src"
  :serial t
  :components ((:file "util/package")
               (:file "util/conditions")
               (:module "util"
                :components ((:file "bytes")
                             (:file "chainparams")
                             (:file "context")
                             (:file "ratelimit")))))

(defsystem "bitcoin-lisp/crypto"
  :description "Hashes, ChaCha20, MuHash, the libsecp256k1 FFI, BIP324
key exchange, addresses and BIP32 -- everything Bitcoin needs from
cryptography and nothing that needs Bitcoin's chain state. Depends on the
util layer for chain parameters (bech32 HRPs) only."
  :depends-on ("bitcoin-lisp/util" "ironclad" "cffi" "nibbles" "flexi-streams" "alexandria")
  :pathname "src"
  :serial t
  :components ((:file "crypto/package")
               (:module "crypto"
                :components ((:file "hash")
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
  :depends-on ("bitcoin-lisp/util" "bordeaux-threads")
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
                             (:file "settings"))))) ; settings.json

(defsystem "bitcoin-lisp/kv"
  :description "Persistence primitives: the LevelDB binding, flat file
sequences with XOR obfuscation, the datadir layout, fsync. Package
bitcoin-lisp.kv, which bitcoin-lisp.storage :USEs and re-exports."
  :depends-on ("bitcoin-lisp/util" "bitcoin-lisp/crypto" "cffi" "bordeaux-threads" "ironclad")
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
  :depends-on ("bitcoin-lisp/util" "bitcoin-lisp/crypto" "flexi-streams" "cl-base64")
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
               "flexi-streams" "ironclad" "bordeaux-threads")
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
                 (:file "zmq")
                 (:module "coalton"
                  :components ((:file "package")
                               (:file "types")
                               (:file "crypto")
                               (:file "binary")
                               (:file "serialization")
                               (:file "script")
                               (:file "interop")))
                 (:module "validation"
                  :components ((:file "script")
                               (:file "miniscript")
                               (:file "transaction")
                               (:file "packages")
                               (:file "block")
                               (:file "versionbits")
                               (:file "signet")))
                 (:module "mempool"
                  :components ((:file "feefrac")
                               (:file "cluster-linearize")
                               (:file "spanning-forest")
                               (:file "txgraph")
                               (:file "orphan")
                               (:file "mempool")
                               (:file "block-policy-estimator")
                               (:file "fee-estimator")))
                 (:module "mining"
                  :components ((:file "assembler")
                               (:file "builder")))
                 ;; The transport below these (connection, addrman, tor, ...)
                 ;; is bitcoin-lisp/net; these are the protocol on top of it.
                 (:module "networking"
                  :components ((:file "txreconciliation-set")
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
                               (:file "state")
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
                :components ((:file "package")
                             (:file "crypto-tests")
                             (:file "serialization-tests")
                             (:file "storage-tests")
                             (:file "validation-tests")
                             (:file "integration-tests")
                             ;; Coalton tests
                             (:file "coalton-package")
                             (:file "coalton-types-tests")
                             (:file "coalton-crypto-tests")
                             (:file "coalton-serialization-tests")
                             (:file "coalton-binary-tests")
                             (:file "coalton-script-tests")
                             ;; Bitcoin Core compatibility tests
                             (:file "bitcoin-core-script-tests")
                             ;; IBD tests
                             (:file "ibd-tests")
                             ;; Mempool tests
                             (:file "mempool-tests")
                             ;; Cluster mempool: FeeFrac + CompareChunks (Core feefrac_tests.cpp)
                             (:file "feefrac-tests")
                             ;; Cluster mempool: DepGraph/chunking/linearization
                             (:file "cluster-linearize-tests")
                             (:file "spanning-forest-tests")
                             ;; Cluster mempool: txgraph engine (Core txgraph.{h,cpp})
                             (:file "txgraph-tests")
                             ;; Cluster mempool P3: shadow-mode mempool/txgraph equivalence
                             (:file "mempool-shadow-tests")
                             ;; Package relay tests (submitpackage)
                             (:file "package-tests")
                             ;; Opportunistic 1p1c package relay over P2P
                             (:file "package-relay-tests")
                             ;; Mining / regtest tests
                             (:file "mining-tests")
                             ;; Deserializer robustness / fuzz tests
                             (:file "robustness-tests")
                             ;; Serialize<->deserialize round-trip property tests
                             (:file "roundtrip-tests")
                             ;; Script SCRIPT_VERIFY flag-gating matrix
                             (:file "script-flag-tests")
                             ;; Inbound listening + handshake
                             (:file "inbound-listening-tests")
                             ;; Serving getheaders/getblocks/getaddr to peers
                             (:file "serve-requests-tests")
                             ;; Persistence, peer health, reorg tests
                             (:file "persistence-tests")
                             ;; RPC tests
                             (:file "rpc-tests")
                             ;; Output descriptor engine (Core descriptor_tests.cpp vectors)
                             (:file "descriptor-tests")
                             ;; Web UI serving + Origin-check tests (gui-plan P0)
                             (:file "ui-tests")
                             ;; Mainnet support tests
                             (:file "mainnet-tests")
                             ;; Pruning tests
                             (:file "pruning-tests")
                             ;; Peer database tests
                             (:file "peerdb-tests")
                             ;; Address manager (new/tried buckets) tests
                             (:file "addrman-tests")
                             ;; Compact block relay tests (BIP 152)
                             (:file "compact-block-tests")
                             (:file "db-cache-tests")
                               (:file "structural-tests")
                             ;; ADDRv2 tests (BIP 155)
                             (:file "addrv2-tests")
                             ;; Network-typed address codecs (onion/i2p/base32) + reachability
                             (:file "netaddress-tests")
                             ;; DoS protection tests
                             (:file "dos-protection-tests")
                             ;; Difficulty adjustment tests
                             (:file "difficulty-tests")
                             (:file "signet-tests")
                             ;; Block weight tests (BIP 141)
                             (:file "weight-tests")
                             ;; Sigops validation tests
                             (:file "sigops-tests")
                             ;; Bitcoin Core comparison feature tests
                             (:file "new-features-tests")
                             ;; Bitcoin Core sighash test vectors
                             (:file "bitcoin-core-sighash-tests")
                             ;; Chain reorganization tests
                             (:file "reorg-tests")
                             ;; Block validation end-to-end tests
                             (:file "block-e2e-tests")
                             ;; Bitcoin Core tx_valid/tx_invalid test vectors
                             (:file "bitcoin-core-tx-tests")
                             ;; Merkle tree edge case tests
                             (:file "merkle-tests")
                             ;; Bitcoin Core BIP 341 taproot test vectors
                             (:file "bitcoin-core-bip341-tests")
                               (:file "bitcoin-core-vector-tests")
                             (:file "bitcoin-core-key-io-tests")
                             (:file "block-policy-estimator-tests")
                             (:file "zmq-tests")
                             ;; BIP 158 compact block filter tests
                             (:file "blockfilter-tests")
                             ;; BIP 174 PSBT tests
                             (:file "psbt-tests")
                             ;; BIP 324 cipher suite tests
                             (:file "bip324-crypto-tests")
                             ;; BIP 324 v2 transport loopback tests
                             (:file "bip324-transport-tests")
                             ;; MuHash3072 tests
                             (:file "muhash-tests")
                             ;; coinstatsindex tests
                             (:file "coinstatsindex-tests")
                             (:file "txospenderindex-tests")
                             (:file "versionbits-tests")
                             ;; -reindex-chainstate tests
                             (:file "reindex-tests")
                             ;; Connection types (block-relay-only + feeler)
                             (:file "conn-type-tests")
                             ;; Low-work headers sync (anti-DoS presync/redownload)
                             (:file "headers-sync-tests")
                             ;; Wave 9A: eclipse/DoS hardening (outbound accounting,
                             ;; non-blocking send, addr rate limit, generic presync)
                             (:file "eclipse-dos-tests")
                             ;; bitcoin.conf + CLI argument parsing
                             (:file "config-tests")
                             ;; The chain-params table
                             (:file "chainparams-tests")
                             (:file "logging-tests")
                             ;; SOCKS5 outbound proxy (-proxy) client
                             (:file "socks5-tests")
                             ;; Tor control client + onion service + self-advertisement
                             (:file "torcontrol-tests")
                             ;; TxOutCompression + hash_serialized_3
                             (:file "compressor-tests")
                             (:file "block-undo-tests")
                             (:file "miniscript-tests")
                             (:file "minisketch-tests")
                             (:file "txreconciliation-set-tests")
                             (:file "flatfile-tests")
                             ;; Assumeutxo snapshot format (dumptxoutset/loadtxoutset)
                             (:file "snapshot-tests")
                             ;; Chainstate list + selection accessors + storage suffix
                             (:file "chainstate-tests")
                             ;; Assumeutxo P4: dual chainstate + background IBD
                             (:file "assumeutxo-tests")
                             ;; Wallet P1: container + keystore + wallet RPCs
                             (:file "wallet-tests")
                             ;; Wallet P2: chain tracking (hooks, TxState,
                             ;; conflicts, rescan, tx RPCs)
                             (:file "wallet-chain-tests")
                             ;; Wallet P3: balances, coins, labels,
                             ;; getaddressinfo, abandontransaction
                             (:file "wallet-balance-tests")
                             ;; Wallet P4: coin selection, spending RPCs,
                             ;; wallet signing, rebroadcast
                             (:file "wallet-spend-tests")
                             ;; Wallet P6: crypter KATs, encryption lifecycle,
                             ;; locked-wallet gating, relock timer, backup
                             (:file "wallet-encryption-tests")
                             ;; Process RNG seeding (*random-state* must not
                             ;; replay SBCL's build-time stream on every start)
                             (:file "entropy-tests")
                             ;; Wave 10: RPC boolean/error-code parity, HTTP
                             ;; layer, BIP64 getutxos, config wires, arg
                             ;; handling, banlist persistence
                             (:file "wave10-tests")
                             ;; GA8 W1-A: intra-block coin overlay (chained-spend
                             ;; script validation + same-block double spends)
                             (:file "intrablock-coins-tests")
                             ;; Randomised totality/roundtrip properties over
                             ;; the parsers a hostile peer reaches
                             (:file "fuzz-property-tests"))))
  :perform (test-op (op c)
                    (symbol-call :fiveam :run! :bitcoin-lisp-tests)))

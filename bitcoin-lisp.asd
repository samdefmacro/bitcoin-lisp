;;; Ensure local coalton checkout is found by ASDF
;;; Use *load-pathname* since system isn't defined yet
(eval-when (:compile-toplevel :load-toplevel :execute)
  (let* ((this-file (or *compile-file-pathname* *load-pathname*))
         (coalton-path (when this-file
                         (merge-pathnames "refs/coalton/" (make-pathname :directory (pathname-directory this-file))))))
    (when (and coalton-path (probe-file coalton-path))
      (pushnew coalton-path asdf:*central-registry* :test #'equal))))

(defsystem "bitcoin-lisp"
  :version "0.1.0"
  :author "samdefmacro"
  :license "MIT"
  :description "Bitcoin full node implementation in Common Lisp"
  :depends-on ("ironclad"
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
                ((:file "package")
                 (:file "logging")
                 (:file "config")
                 (:module "coalton"
                  :components ((:file "package")
                               (:file "types")
                               (:file "crypto")
                               (:file "binary")
                               (:file "serialization")
                               (:file "script")
                               (:file "interop")))
                 (:module "crypto"
                  :components ((:file "hash")
                               (:file "chacha20")
                               (:file "muhash")
                               (:file "secp256k1")
                               (:file "bip324")
                               (:file "address")
                               (:file "bip32")))
                 (:module "serialization"
                  :components ((:file "binary")
                               (:file "compressor")
                               (:file "types")
                               (:file "messages")
                               (:file "psbt")))
                 (:module "storage"
                  :components ((:file "blocks")
                               (:file "utxo")
                               (:file "leveldb")
                               (:file "coins-view")
                               (:file "coins-view-cache")
                               (:file "coins-view-migration")
                               (:file "chain")
                               (:file "txindex")
                               (:file "blockfilter")
                               (:file "blockfilterindex")
                               (:file "coinstatsindex")))
                 (:module "validation"
                  :components ((:file "script")
                               (:file "transaction")
                               (:file "packages")
                               (:file "block")
                               (:file "signet")))
                 (:module "mempool"
                  :components ((:file "feefrac")
                               (:file "cluster-linearize")
                               (:file "txgraph")
                               (:file "orphan")
                               (:file "mempool")
                               (:file "fee-estimator")))
                 (:module "mining"
                  :components ((:file "assembler")
                               (:file "builder")))
                 (:module "networking"
                  :components ((:file "socks5")     ; before connection: make-tcp-connection tunnels through *proxy*
                               (:file "connection")
                               (:file "v2-transport")
                               (:file "peer")
                               (:file "peerdb")
                               (:file "netaddress") ; BIP155 codecs/reachability; before addrman (netgroups)
                               (:file "addrman")
                               (:file "torcontrol") ; Tor control client (inbound onion service)
                               (:file "protocol")
                               (:file "headers-sync")
                               (:file "ibd")))
                 (:module "rpc"
                  :components ((:file "package")
                               (:file "accessors")
                               (:file "descriptors")
                               (:file "methods")
                               (:file "wallet-store")
                               (:file "wallet")
                               (:file "wallet-tx")
                               (:file "wallet-coins")
                               (:file "wallet-spend")
                               (:file "psbt")
                               (:file "merkleproof")
                               (:file "rest")
                               (:file "ui")
                               (:file "server")))
                 (:file "node"))))
  :in-order-to ((test-op (test-op "bitcoin-lisp/tests"))))

(defsystem "bitcoin-lisp/tests"
  :depends-on ("bitcoin-lisp"
               "fiveam"
               "yason")
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
                             ;; SOCKS5 outbound proxy (-proxy) client
                             (:file "socks5-tests")
                             ;; Tor control client + onion service + self-advertisement
                             (:file "torcontrol-tests")
                             ;; TxOutCompression + hash_serialized_3
                             (:file "compressor-tests")
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
                             ;; Process RNG seeding (*random-state* must not
                             ;; replay SBCL's build-time stream on every start)
                             (:file "entropy-tests")
                             ;; Wave 10: RPC boolean/error-code parity, HTTP
                             ;; layer, BIP64 getutxos, config wires, arg
                             ;; handling, banlist persistence
                             (:file "wave10-tests")
                             ;; GA8 W1-A: intra-block coin overlay (chained-spend
                             ;; script validation + same-block double spends)
                             (:file "intrablock-coins-tests"))))
  :perform (test-op (op c)
                    (symbol-call :fiveam :run! :bitcoin-lisp-tests)))

(defpackage #:bitcoin-lisp.tests
  (:use #:cl #:fiveam)
  (:export #:run-tests
           #:run-unit-tests
           #:run-integration-tests))

(in-package #:bitcoin-lisp.tests)

;; Cluster mempool P3 shadow mode: run the WHOLE suite with full
;; mempool/txgraph equivalence assertions after every mempool mutation
;; (default NIL in production; see src/mempool/mempool.lisp).
(setf bitcoin-lisp.mempool:*txgraph-shadow-checks* t)

(def-suite :bitcoin-lisp-tests
  :description "Test suite for bitcoin-lisp")

(def-suite :crypto-tests
  :description "Tests for cryptographic functions"
  :in :bitcoin-lisp-tests)

(def-suite :serialization-tests
  :description "Tests for serialization functions"
  :in :bitcoin-lisp-tests)

(def-suite :storage-tests
  :description "Tests for storage operations"
  :in :bitcoin-lisp-tests)

(def-suite :validation-tests
  :description "Tests for validation operations"
  :in :bitcoin-lisp-tests)

(def-suite :mempool-tests
  :description "Tests for mempool operations"
  :in :bitcoin-lisp-tests)

(def-suite :package-tests
  :description "Tests for package relay (submitpackage)"
  :in :bitcoin-lisp-tests)

(def-suite :mining-tests
  :description "Tests for regtest support and mining RPCs"
  :in :bitcoin-lisp-tests)

(def-suite :robustness-tests
  :description "Malformed/adversarial-input robustness of the deserializers"
  :in :bitcoin-lisp-tests)

(def-suite :roundtrip-tests
  :description "serialize <-> deserialize round-trip property tests"
  :in :bitcoin-lisp-tests)

(def-suite :script-flag-tests
  :description "Per-flag SCRIPT_VERIFY gating matrix (flag toggles its rule)"
  :in :bitcoin-lisp-tests)

(def-suite :inbound-listening-tests
  :description "Inbound peer listening + inbound version handshake"
  :in :bitcoin-lisp-tests)

(def-suite :serve-requests-tests
  :description "Serving getheaders/getblocks/getaddr requests to peers"
  :in :bitcoin-lisp-tests)

(def-suite :persistence-tests
  :description "Tests for persistence, peer health, reorg operations"
  :in :bitcoin-lisp-tests)

(def-suite :pruning-tests
  :description "Tests for block pruning"
  :in :bitcoin-lisp-tests)

(def-suite :peerdb-tests
  :description "Tests for persistent peer database"
  :in :bitcoin-lisp-tests)

(def-suite :addrman-tests
  :description "Tests for the new/tried bucket address manager (addrman)"
  :in :bitcoin-lisp-tests)

(def-suite :compact-block-tests
  :description "Tests for Compact Block Relay (BIP 152)"
  :in :bitcoin-lisp-tests)

(def-suite :addrv2-tests
  :description "Tests for ADDRv2 (BIP 155) support"
  :in :bitcoin-lisp-tests)

(def-suite :netaddress-tests
  :description "Tests for network-typed addresses: onion/i2p codecs, netgroups, reachability"
  :in :bitcoin-lisp-tests)

(def-suite :dos-protection-tests
  :description "Tests for DoS protection (rate limiting, handshake timeout, rejects filter)"
  :in :bitcoin-lisp-tests)

(def-suite :difficulty-tests
  :description "Tests for difficulty adjustment validation"
  :in :bitcoin-lisp-tests)

(def-suite :weight-tests
  :description "Tests for block weight validation (BIP 141)"
  :in :bitcoin-lisp-tests)

(def-suite :sigops-tests
  :description "Tests for signature operations cost validation (BIP 141)"
  :in :bitcoin-lisp-tests)

(def-suite :integration-tests
  :description "Integration tests with testnet"
  :in :bitcoin-lisp-tests)

(defun run-tests ()
  "Run all bitcoin-lisp tests."
  (run! :bitcoin-lisp-tests))

(defun run-unit-tests ()
  "Run unit tests only (excludes integration tests)."
  (run! :crypto-tests)
  (run! :serialization-tests)
  (run! :storage-tests)
  (run! :validation-tests)
  ;; Coalton tests are run as part of coalton-tests suite
  ;; which is a child of bitcoin-lisp-tests
  )

(defun run-integration-tests ()
  "Run integration tests only (requires network)."
  (run! :integration-tests))

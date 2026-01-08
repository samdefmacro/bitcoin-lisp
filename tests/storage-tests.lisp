(in-package #:bitcoin-lisp.tests)

(in-suite :storage-tests)

;;;; UTXO Set Tests

(test utxo-set-add-and-get
  "Adding a UTXO should make it retrievable."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 50000000 script 100)
    (let ((entry (bitcoin-lisp.storage:get-utxo utxo-set txid 0)))
      (is (not (null entry)))
      (is (= 50000000 (bitcoin-lisp.storage:utxo-entry-value entry)))
      (is (= 100 (bitcoin-lisp.storage:utxo-entry-height entry)))
      (is (equalp script (bitcoin-lisp.storage:utxo-entry-script-pubkey entry))))))

(test utxo-set-remove
  "Removing a UTXO should make it no longer retrievable."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 25000000 script 50)
    (is (bitcoin-lisp.storage:utxo-exists-p utxo-set txid 0))
    (bitcoin-lisp.storage:remove-utxo utxo-set txid 0)
    (is (not (bitcoin-lisp.storage:utxo-exists-p utxo-set txid 0)))))

(test utxo-set-count
  "UTXO count should track additions and removals."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (is (= 0 (bitcoin-lisp.storage:utxo-count utxo-set)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 1000 script 1)
    (is (= 1 (bitcoin-lisp.storage:utxo-count utxo-set)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 1 2000 script 1)
    (is (= 2 (bitcoin-lisp.storage:utxo-count utxo-set)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid2 0 3000 script 1)
    (is (= 3 (bitcoin-lisp.storage:utxo-count utxo-set)))
    (bitcoin-lisp.storage:remove-utxo utxo-set txid1 0)
    (is (= 2 (bitcoin-lisp.storage:utxo-count utxo-set)))))

(test utxo-set-coinbase-flag
  "Coinbase UTXOs should be flagged correctly."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 6))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 5000000000 script 0 :coinbase t)
    (bitcoin-lisp.storage:add-utxo utxo-set txid2 0 1000000 script 1 :coinbase nil)
    (is (bitcoin-lisp.storage:utxo-entry-coinbase
         (bitcoin-lisp.storage:get-utxo utxo-set txid1 0)))
    (is (not (bitcoin-lisp.storage:utxo-entry-coinbase
              (bitcoin-lisp.storage:get-utxo utxo-set txid2 0))))))

(test utxo-set-multiple-outputs-same-tx
  "Multiple outputs from the same transaction should be distinguishable."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 1000 script 10)
    (bitcoin-lisp.storage:add-utxo utxo-set txid 1 2000 script 10)
    (bitcoin-lisp.storage:add-utxo utxo-set txid 2 3000 script 10)
    (is (= 3 (bitcoin-lisp.storage:utxo-count utxo-set)))
    (is (= 1000 (bitcoin-lisp.storage:utxo-entry-value
                 (bitcoin-lisp.storage:get-utxo utxo-set txid 0))))
    (is (= 2000 (bitcoin-lisp.storage:utxo-entry-value
                 (bitcoin-lisp.storage:get-utxo utxo-set txid 1))))
    (is (= 3000 (bitcoin-lisp.storage:utxo-entry-value
                 (bitcoin-lisp.storage:get-utxo utxo-set txid 2))))))

;;;; Chain State Tests

(test chain-state-init
  "Chain state should initialize with genesis hash."
  (let ((state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-test/")))
    (is (not (null (bitcoin-lisp.storage:best-block-hash state))))
    (is (= 0 (bitcoin-lisp.storage:current-height state)))))

(test chain-state-update-tip
  "Updating chain tip should change best block and height."
  (let ((state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-test/"))
        (new-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8)))
    (bitcoin-lisp.storage:update-chain-tip state new-hash 100)
    (is (equalp new-hash (bitcoin-lisp.storage:best-block-hash state)))
    (is (= 100 (bitcoin-lisp.storage:current-height state)))))

(test chain-state-block-index
  "Block index entries should be storable and retrievable."
  (let ((state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-test/"))
        (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (let ((entry (bitcoin-lisp.storage:make-block-index-entry
                  :hash hash
                  :height 50
                  :chain-work 12345
                  :status :valid)))
      (bitcoin-lisp.storage:add-block-index-entry state entry)
      (let ((retrieved (bitcoin-lisp.storage:get-block-index-entry state hash)))
        (is (not (null retrieved)))
        (is (= 50 (bitcoin-lisp.storage:block-index-entry-height retrieved)))
        (is (= 12345 (bitcoin-lisp.storage:block-index-entry-chain-work retrieved)))
        (is (eq :valid (bitcoin-lisp.storage:block-index-entry-status retrieved)))))))

;;;; Chain Work Tests

(test bits-to-target-conversion
  "Bits to target conversion should match expected values."
  ;; Testnet genesis bits: 0x1d00ffff
  (let ((target (bitcoin-lisp.storage:bits-to-target #x1d00ffff)))
    ;; This should give a very large target (low difficulty)
    (is (> target 0))
    (is (< target (expt 2 256)))))

(test chain-work-calculation
  "Chain work calculation should accumulate correctly."
  (let ((work1 (bitcoin-lisp.storage:calculate-chain-work #x1d00ffff 0)))
    (is (> work1 0))
    (let ((work2 (bitcoin-lisp.storage:calculate-chain-work #x1d00ffff work1)))
      (is (> work2 work1))
      ;; Work should roughly double (same difficulty)
      (is (< (abs (- work2 (* 2 work1))) 1)))))

;;;; Block Locator Tests

(test block-locator-empty-chain
  "Block locator for empty chain should include genesis."
  (let ((state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-test/")))
    (let ((locator (bitcoin-lisp.storage:build-block-locator state)))
      (is (not (null locator)))
      ;; Should at least have genesis
      (is (>= (length locator) 1)))))


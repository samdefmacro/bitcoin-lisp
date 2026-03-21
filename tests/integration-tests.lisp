(in-package #:bitcoin-lisp.tests)

(in-suite :integration-tests)

;;;; Network Integration Tests
;;;; Note: These tests require network access and may be slow.
;;;; They test real connectivity to testnet peers.

(test dns-seed-resolution
  "DNS seeds should resolve to IP addresses."
  (let ((seeds '("testnet-seed.bitcoin.jonasschnelli.ch"
                 "seed.tbtc.petertodd.org"
                 "testnet-seed.bluematt.me")))
    ;; At least one seed should resolve
    (let ((resolved nil))
      (dolist (seed seeds)
        (handler-case
            (let ((addresses (usocket:get-hosts-by-name seed)))
              (when addresses
                (setf resolved t)
                (is (> (length addresses) 0))))
          (error (c)
            (declare (ignore c))
            nil)))
      (is-true resolved "At least one DNS seed should resolve"))))

(test version-message-creation
  "Version message should be properly formatted."
  (let ((version-bytes (bitcoin-lisp.serialization:make-version-message-bytes
                        :start-height 100
                        :timestamp 1234567890)))
    ;; Version payload should be non-empty (header fields + net-addrs + user-agent + ...)
    ;; Minimum: 4(version) + 8(services) + 8(timestamp) + 26(addr-recv) + 26(addr-from)
    ;;          + 8(nonce) + 1+(user-agent varint+string) + 4(start-height) + 1(relay)
    (is (> (length version-bytes) 80))
    ;; Parse it back to verify round-trip
    (let ((parsed (flexi-streams:with-input-from-sequence (stream version-bytes)
                    (bitcoin-lisp.serialization:read-version-message stream))))
      (is (= 70016 (bitcoin-lisp.serialization:version-message-version parsed)))
      (is (= 100 (bitcoin-lisp.serialization:version-message-start-height parsed)))
      (is (stringp (bitcoin-lisp.serialization:version-message-user-agent parsed))))))

(test verack-message-creation
  "Verack message should be properly formatted."
  (let ((verack-bytes (bitcoin-lisp.serialization:make-verack-message)))
    ;; Verack is just a header with empty payload
    ;; Header is 24 bytes: 4 magic + 12 command + 4 length + 4 checksum
    (is (= 24 (length verack-bytes)))))

(test ping-pong-message-creation
  "Ping and pong messages should be properly formatted."
  (let ((ping-bytes (bitcoin-lisp.serialization:make-ping-message 12345)))
    ;; Ping is header (24 bytes) + 8 byte nonce
    (is (= 32 (length ping-bytes)))))

(test getblocks-message-creation
  "Getblocks message should be properly formatted."
  (let* ((genesis-hash (bitcoin-lisp.crypto:hex-to-bytes
                        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"))
         (locator (list genesis-hash))
         (getblocks-bytes (bitcoin-lisp.serialization:make-getblocks-message locator)))
    (is (> (length getblocks-bytes) 24))))

(test getheaders-message-creation
  "Getheaders message should be properly formatted."
  (let* ((genesis-hash (bitcoin-lisp.crypto:hex-to-bytes
                        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"))
         (locator (list genesis-hash))
         (getheaders-bytes (bitcoin-lisp.serialization:make-getheaders-message locator)))
    (is (> (length getheaders-bytes) 24))))

(test inv-message-creation
  "Inv message should be properly formatted."
  (let* ((block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (inv-vector (bitcoin-lisp.serialization:make-inv-vector
                      :type bitcoin-lisp.serialization:+inv-type-block+
                      :hash block-hash))
         (inv-bytes (bitcoin-lisp.serialization:make-inv-message (list inv-vector))))
    ;; Inv is header (24 bytes) + compact size + inv vector (36 bytes each)
    (is (> (length inv-bytes) 24))))

(test getdata-message-creation
  "Getdata message should be properly formatted."
  (let* ((tx-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
         (inv-vector (bitcoin-lisp.serialization:make-inv-vector
                      :type bitcoin-lisp.serialization:+inv-type-tx+
                      :hash tx-hash))
         (getdata-bytes (bitcoin-lisp.serialization:make-getdata-message (list inv-vector))))
    (is (> (length getdata-bytes) 24))))

;;;; End-to-end workflow tests (unit-level, no network needed)

(test block-storage-and-retrieval
  "Blocks should be storable and retrievable."
  (let* ((temp-dir (format nil "/tmp/btc-test-~A/" (get-universal-time)))
         (store (bitcoin-lisp.storage:init-block-store temp-dir))
         ;; Create a minimal test block
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 1296688602
                  :bits #x1d00ffff
                  :nonce 414098458))
         (coinbase-input (bitcoin-lisp.serialization:make-tx-in
                          :previous-output (bitcoin-lisp.serialization:make-outpoint
                                            :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                              :initial-element 0)
                                            :index #xFFFFFFFF)
                          :script-sig (make-array 7 :element-type '(unsigned-byte 8)
                                                    :initial-contents '(#x04 #xFF #xFF #x00 #x1D #x01 #x04))
                          :sequence #xFFFFFFFF))
         (coinbase-output (bitcoin-lisp.serialization:make-tx-out
                           :value 5000000000
                           :script-pubkey (make-array 2 :element-type '(unsigned-byte 8)
                                                        :initial-contents '(#x41 #x04))))
         (coinbase-tx (bitcoin-lisp.serialization:make-transaction
                       :version 1
                       :inputs (list coinbase-input)
                       :outputs (list coinbase-output)
                       :lock-time 0))
         (block (bitcoin-lisp.serialization:make-bitcoin-block
                 :header header
                 :transactions (list coinbase-tx))))
    ;; Store the block
    (let ((hash (bitcoin-lisp.storage:store-block store block)))
      ;; Verify it exists
      (is (bitcoin-lisp.storage:block-exists-p store hash))
      ;; Retrieve it
      (let ((retrieved (bitcoin-lisp.storage:get-block store hash)))
        (is (not (null retrieved)))
        ;; Verify header matches
        (let ((retrieved-header (bitcoin-lisp.serialization:bitcoin-block-header retrieved)))
          (is (= 1 (bitcoin-lisp.serialization:block-header-version retrieved-header)))
          (is (= 1296688602 (bitcoin-lisp.serialization:block-header-timestamp retrieved-header))))))))

(test utxo-set-block-application
  "Applying a block should update UTXO set correctly."
  (let* ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
         ;; Create a block with coinbase transaction
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 1296688602
                  :bits #x1d00ffff
                  :nonce 414098458))
         (coinbase-input (bitcoin-lisp.serialization:make-tx-in
                          :previous-output (bitcoin-lisp.serialization:make-outpoint
                                            :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                              :initial-element 0)
                                            :index #xFFFFFFFF)
                          :script-sig (make-array 2 :element-type '(unsigned-byte 8)
                                                    :initial-contents '(#x01 #x01))
                          :sequence #xFFFFFFFF))
         (coinbase-output (bitcoin-lisp.serialization:make-tx-out
                           :value 5000000000
                           :script-pubkey (make-array 3 :element-type '(unsigned-byte 8)
                                                        :initial-contents '(#x76 #xa9 #x14))))
         (coinbase-tx (bitcoin-lisp.serialization:make-transaction
                       :version 1
                       :inputs (list coinbase-input)
                       :outputs (list coinbase-output)
                       :lock-time 0))
         (block (bitcoin-lisp.serialization:make-bitcoin-block
                 :header header
                 :transactions (list coinbase-tx))))
    ;; Initial count should be 0
    (is (= 0 (bitcoin-lisp.storage:utxo-count utxo-set)))
    ;; Apply block
    (bitcoin-lisp.storage:apply-block-to-utxo-set utxo-set block 1)
    ;; Should now have 1 UTXO (the coinbase output)
    (is (= 1 (bitcoin-lisp.storage:utxo-count utxo-set)))
    ;; Verify the UTXO is coinbase-flagged
    (let* ((txid (bitcoin-lisp.serialization:transaction-hash coinbase-tx))
           (entry (bitcoin-lisp.storage:get-utxo utxo-set txid 0)))
      (is (not (null entry)))
      (is (= 5000000000 (bitcoin-lisp.storage:utxo-entry-value entry)))
      (is (bitcoin-lisp.storage:utxo-entry-coinbase entry)))))

(test chain-state-persistence
  "Chain state should persist and reload correctly."
  (let* ((temp-dir (format nil "/tmp/btc-chain-test-~A/" (get-universal-time)))
         (state (bitcoin-lisp.storage:init-chain-state temp-dir))
         (test-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAB)))
    ;; Update to a new tip
    (bitcoin-lisp.storage:update-chain-tip state test-hash 12345)
    ;; Save state
    (bitcoin-lisp.storage:save-state state)
    ;; Create new state and load
    (let ((state2 (bitcoin-lisp.storage:init-chain-state temp-dir)))
      (bitcoin-lisp.storage:load-state state2)
      ;; Verify loaded values
      (is (equalp test-hash (bitcoin-lisp.storage:best-block-hash state2)))
      (is (= 12345 (bitcoin-lisp.storage:current-height state2))))))


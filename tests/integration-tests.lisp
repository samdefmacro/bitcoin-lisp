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
  (let ((version-bytes (bl.ser:make-version-message-bytes
                        :start-height 100
                        :timestamp 1234567890)))
    ;; Version payload should be non-empty (header fields + net-addrs + user-agent + ...)
    ;; Minimum: 4(version) + 8(services) + 8(timestamp) + 26(addr-recv) + 26(addr-from)
    ;;          + 8(nonce) + 1+(user-agent varint+string) + 4(start-height) + 1(relay)
    (is (> (length version-bytes) 80))
    ;; Parse it back to verify round-trip
    (let ((parsed (bl.bytes:with-byte-reader (stream version-bytes)
                    (bl.ser:read-version-message stream))))
      (is (= 70016 (bl.ser:version-message-version parsed)))
      (is (= 100 (bl.ser:version-message-start-height parsed)))
      (is (stringp (bl.ser:version-message-user-agent parsed))))))

(test verack-message-creation
  "Verack message should be properly formatted."
  (let ((verack-bytes (bl.ser:make-verack-message)))
    ;; Verack is just a header with empty payload
    ;; Header is 24 bytes: 4 magic + 12 command + 4 length + 4 checksum
    (is (= 24 (length verack-bytes)))))

(test ping-pong-message-creation
  "Ping and pong messages should be properly formatted."
  (let ((ping-bytes (bl.ser:make-ping-message 12345)))
    ;; Ping is header (24 bytes) + 8 byte nonce
    (is (= 32 (length ping-bytes)))))

(test getblocks-message-creation
  "Getblocks message should be properly formatted."
  (let* ((genesis-hash (bl.crypto:hex-to-bytes
                        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"))
         (locator (list genesis-hash))
         (getblocks-bytes (bl.ser:make-getblocks-message locator)))
    (is (> (length getblocks-bytes) 24))))

(test getheaders-message-creation
  "Getheaders message should be properly formatted."
  (let* ((genesis-hash (bl.crypto:hex-to-bytes
                        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"))
         (locator (list genesis-hash))
         (getheaders-bytes (bl.ser:make-getheaders-message locator)))
    (is (> (length getheaders-bytes) 24))))

(test inv-message-creation
  "Inv message should be properly formatted."
  (let* ((block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (inv-vector (bl.ser:make-inv-vector
                      :type bl.ser:+inv-type-block+
                      :hash block-hash))
         (inv-bytes (bl.ser:make-inv-message (list inv-vector))))
    ;; Inv is header (24 bytes) + compact size + inv vector (36 bytes each)
    (is (> (length inv-bytes) 24))))

(test getdata-message-creation
  "Getdata message should be properly formatted."
  (let* ((tx-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
         (inv-vector (bl.ser:make-inv-vector
                      :type bl.ser:+inv-type-tx+
                      :hash tx-hash))
         (getdata-bytes (bl.ser:make-getdata-message (list inv-vector))))
    (is (> (length getdata-bytes) 24))))

;;;; End-to-end workflow tests (unit-level, no network needed)

(test block-storage-and-retrieval
  "Blocks should be storable and retrievable."
  (let* ((temp-dir (format nil "/tmp/btc-test-~A/" (get-universal-time)))
         (store (bl.store:init-block-store temp-dir))
         ;; Create a minimal test block
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 1296688602
                  :bits #x1d00ffff
                  :nonce 414098458))
         (coinbase-input (bl.ser:make-tx-in
                          :previous-output (bl.ser:make-outpoint
                                            :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                              :initial-element 0)
                                            :index #xFFFFFFFF)
                          :script-sig (make-array 7 :element-type '(unsigned-byte 8)
                                                    :initial-contents '(#x04 #xFF #xFF #x00 #x1D #x01 #x04))
                          :sequence #xFFFFFFFF))
         (coinbase-output (bl.ser:make-tx-out
                           :value 5000000000
                           :script-pubkey (make-array 2 :element-type '(unsigned-byte 8)
                                                        :initial-contents '(#x41 #x04))))
         (coinbase-tx (bl.ser:make-transaction
                       :version 1
                       :inputs (vector coinbase-input)
                       :outputs (vector coinbase-output)
                       :lock-time 0))
         (block (bl.ser:make-bitcoin-block
                 :header header
                 :transactions (list coinbase-tx))))
    ;; Store the block
    (let ((hash (bl.store:store-block store block)))
      ;; Verify it exists
      (is (bl.store:block-exists-p store hash))
      ;; Retrieve it
      (let ((retrieved (bl.store:get-block store hash)))
        (is (not (null retrieved)))
        ;; Verify header matches
        (let ((retrieved-header (bl.ser:bitcoin-block-header retrieved)))
          (is (= 1 (bl.ser:block-header-version retrieved-header)))
          (is (= 1296688602 (bl.ser:block-header-timestamp retrieved-header))))))))

(test utxo-set-block-application
  "Applying a block should update UTXO set correctly."
  (let* ((utxo-set (bl.store:make-utxo-set))
         ;; Create a block with coinbase transaction
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 1296688602
                  :bits #x1d00ffff
                  :nonce 414098458))
         (coinbase-input (bl.ser:make-tx-in
                          :previous-output (bl.ser:make-outpoint
                                            :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                              :initial-element 0)
                                            :index #xFFFFFFFF)
                          :script-sig (make-array 2 :element-type '(unsigned-byte 8)
                                                    :initial-contents '(#x01 #x01))
                          :sequence #xFFFFFFFF))
         (coinbase-output (bl.ser:make-tx-out
                           :value 5000000000
                           :script-pubkey (make-array 3 :element-type '(unsigned-byte 8)
                                                        :initial-contents '(#x76 #xa9 #x14))))
         (coinbase-tx (bl.ser:make-transaction
                       :version 1
                       :inputs (vector coinbase-input)
                       :outputs (vector coinbase-output)
                       :lock-time 0))
         (block (bl.ser:make-bitcoin-block
                 :header header
                 :transactions (list coinbase-tx))))
    ;; Initial count should be 0
    (is (= 0 (bl.store:utxo-count utxo-set)))
    ;; Apply block
    (bl.store:apply-block-to-utxo-set utxo-set block 1)
    ;; Should now have 1 UTXO (the coinbase output)
    (is (= 1 (bl.store:utxo-count utxo-set)))
    ;; Verify the UTXO is coinbase-flagged
    (let* ((txid (bl.ser:transaction-hash coinbase-tx))
           (entry (bl.store:get-utxo utxo-set txid 0)))
      (is (not (null entry)))
      (is (= 5000000000 (bl.store:utxo-entry-value entry)))
      (is (bl.store:utxo-entry-coinbase entry)))))

(test chain-state-persistence
  "Chain state should persist and reload correctly."
  (let* ((temp-dir (format nil "/tmp/btc-chain-test-~A/" (get-universal-time)))
         (state (bl.store:init-chain-state temp-dir))
         (test-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAB)))
    ;; Update to a new tip
    (bl.store:update-chain-tip state test-hash 12345)
    ;; Save state
    (bl.store:save-state state)
    ;; Create new state and load
    (let ((state2 (bl.store:init-chain-state temp-dir)))
      (bl.store:load-state state2)
      ;; Verify loaded values
      (is (equalp test-hash (bl.store:best-block-hash state2)))
      (is (= 12345 (bl.store:current-height state2))))))


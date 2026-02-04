(in-package #:bitcoin-lisp.tests)

(in-suite :serialization-tests)

;;;; Witness transaction serialization tests

;; A minimal synthetic P2WPKH witness transaction for testing:
;; - version: 2
;; - 1 input spending a previous output (all-0x11 txid, index 0)
;;   - empty scriptSig (native witness)
;;   - sequence 0xFFFFFFFE
;; - 1 output: 49999 satoshis to a 25-byte script
;; - witness: 1 input with 2 items (72-byte sig placeholder, 33-byte pubkey placeholder)
;; - locktime: 500000
;;
;; Wire format (BIP 144):
;;   version(4) + marker(1) + flag(1) + inputs + outputs + witness + locktime(4)

(defun make-witness-test-tx-bytes ()
  "Build raw bytes for a synthetic BIP 144 witness transaction."
  (coerce
   (flexi-streams:with-output-to-sequence (s)
     ;; Version = 2
     (bitcoin-lisp.serialization:write-int32-le s 2)
     ;; Marker + flag
     (bitcoin-lisp.serialization:write-uint8 s #x00)
     (bitcoin-lisp.serialization:write-uint8 s #x01)
     ;; 1 input
     (bitcoin-lisp.serialization:write-compact-size s 1)
     ;; prev outpoint: txid (32 bytes of 0x11), index 0
     (write-sequence (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11) s)
     (bitcoin-lisp.serialization:write-uint32-le s 0)
     ;; empty scriptSig
     (bitcoin-lisp.serialization:write-compact-size s 0)
     ;; sequence
     (bitcoin-lisp.serialization:write-uint32-le s #xFFFFFFFE)
     ;; 1 output
     (bitcoin-lisp.serialization:write-compact-size s 1)
     ;; value: 49999 satoshis
     (bitcoin-lisp.serialization:write-int64-le s 49999)
     ;; 25-byte scriptPubKey (P2PKH placeholder)
     (bitcoin-lisp.serialization:write-compact-size s 25)
     (write-sequence (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76) s)
     ;; Witness for input 0: 2 items
     (bitcoin-lisp.serialization:write-compact-size s 2)
     ;; Item 1: 72-byte signature placeholder
     (bitcoin-lisp.serialization:write-compact-size s 72)
     (write-sequence (make-array 72 :element-type '(unsigned-byte 8) :initial-element #xAA) s)
     ;; Item 2: 33-byte pubkey placeholder
     (bitcoin-lisp.serialization:write-compact-size s 33)
     (write-sequence (make-array 33 :element-type '(unsigned-byte 8) :initial-element #xBB) s)
     ;; Locktime: 500000
     (bitcoin-lisp.serialization:write-uint32-le s 500000))
   '(simple-array (unsigned-byte 8) (*))))

(test witness-transaction-deserialize
  "A BIP 144 witness transaction should deserialize correctly."
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (flexi-streams:with-input-from-sequence (s raw)
               (bitcoin-lisp.serialization:read-transaction s))))
    ;; Basic fields
    (is (= 2 (bitcoin-lisp.serialization:transaction-version tx)))
    (is (= 1 (length (bitcoin-lisp.serialization:transaction-inputs tx))))
    (is (= 1 (length (bitcoin-lisp.serialization:transaction-outputs tx))))
    (is (= 500000 (bitcoin-lisp.serialization:transaction-lock-time tx)))
    ;; Input details
    (let ((input (first (bitcoin-lisp.serialization:transaction-inputs tx))))
      (is (every (lambda (b) (= b #x11))
                 (bitcoin-lisp.serialization:outpoint-hash
                  (bitcoin-lisp.serialization:tx-in-previous-output input))))
      (is (= 0 (length (bitcoin-lisp.serialization:tx-in-script-sig input))))
      (is (= #xFFFFFFFE (bitcoin-lisp.serialization:tx-in-sequence input))))
    ;; Output
    (let ((output (first (bitcoin-lisp.serialization:transaction-outputs tx))))
      (is (= 49999 (bitcoin-lisp.serialization:tx-out-value output))))
    ;; Witness data
    (is (bitcoin-lisp.serialization:transaction-has-witness-p tx))
    (let ((witness (bitcoin-lisp.serialization:transaction-witness tx)))
      (is (= 1 (length witness)))       ; 1 input's witness
      (is (= 2 (length (first witness)))) ; 2 stack items
      (is (= 72 (length (first (first witness)))))  ; sig
      (is (= 33 (length (second (first witness))))))))  ; pubkey

(test witness-transaction-round-trip
  "Serializing a witness transaction back should produce identical bytes."
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (flexi-streams:with-input-from-sequence (s raw)
               (bitcoin-lisp.serialization:read-transaction s)))
         (re-serialized (bitcoin-lisp.serialization:serialize-witness-transaction tx)))
    (is (equalp raw re-serialized))))

(test witness-txid-excludes-witness
  "The txid should be computed from legacy serialization (no witness)."
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (flexi-streams:with-input-from-sequence (s raw)
               (bitcoin-lisp.serialization:read-transaction s)))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         ;; Manually compute legacy serialization hash
         (legacy-bytes (bitcoin-lisp.serialization:serialize-transaction tx))
         (expected-txid (bitcoin-lisp.crypto:hash256 legacy-bytes)))
    ;; txid should match legacy hash
    (is (equalp txid expected-txid))
    ;; legacy bytes should NOT equal witness bytes
    (is (not (equalp legacy-bytes (make-witness-test-tx-bytes))))))

(test witness-wtxid-includes-witness
  "The wtxid should be computed from witness serialization."
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (flexi-streams:with-input-from-sequence (s raw)
               (bitcoin-lisp.serialization:read-transaction s)))
         (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx))
         (expected-wtxid (bitcoin-lisp.crypto:hash256 raw)))
    ;; wtxid should match hash of full witness serialization
    (is (equalp wtxid expected-wtxid))
    ;; wtxid should differ from txid
    (is (not (equalp wtxid (bitcoin-lisp.serialization:transaction-hash tx))))))

(test legacy-transaction-still-works
  "Legacy transactions (no witness) should still deserialize correctly."
  (let* ((legacy-bytes
           (coerce
            (flexi-streams:with-output-to-sequence (s)
              (bitcoin-lisp.serialization:write-int32-le s 1)  ; version
              (bitcoin-lisp.serialization:write-compact-size s 1) ; 1 input
              ;; prev outpoint
              (write-sequence (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element #x22) s)
              (bitcoin-lisp.serialization:write-uint32-le s 0)
              ;; scriptSig (10 bytes)
              (bitcoin-lisp.serialization:write-compact-size s 10)
              (write-sequence (make-array 10 :element-type '(unsigned-byte 8)
                                             :initial-element #x48) s)
              (bitcoin-lisp.serialization:write-uint32-le s #xFFFFFFFF) ; sequence
              (bitcoin-lisp.serialization:write-compact-size s 1) ; 1 output
              (bitcoin-lisp.serialization:write-int64-le s 100000)
              (bitcoin-lisp.serialization:write-compact-size s 25)
              (write-sequence (make-array 25 :element-type '(unsigned-byte 8)
                                             :initial-element #x76) s)
              (bitcoin-lisp.serialization:write-uint32-le s 0)) ; locktime
            '(simple-array (unsigned-byte 8) (*))))
         (tx (flexi-streams:with-input-from-sequence (s legacy-bytes)
               (bitcoin-lisp.serialization:read-transaction s))))
    (is (= 1 (bitcoin-lisp.serialization:transaction-version tx)))
    (is (= 1 (length (bitcoin-lisp.serialization:transaction-inputs tx))))
    (is (= 10 (length (bitcoin-lisp.serialization:tx-in-script-sig
                        (first (bitcoin-lisp.serialization:transaction-inputs tx))))))
    (is (not (bitcoin-lisp.serialization:transaction-has-witness-p tx)))
    ;; Legacy round-trip
    (let ((re-serialized (bitcoin-lisp.serialization:serialize-transaction tx)))
      (is (equalp legacy-bytes re-serialized)))))

(test coinbase-wtxid-is-zero
  "Coinbase transaction wtxid should be 32 zero bytes."
  (let ((coinbase-tx (bitcoin-lisp.serialization:make-transaction
                      :version 1
                      :inputs (list (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element 0)
                                                       :index #xFFFFFFFF)
                                     :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                               :initial-element 1)))
                      :outputs (list (bitcoin-lisp.serialization:make-tx-out
                                      :value 5000000000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0)))
    (let ((wtxid (bitcoin-lisp.serialization:transaction-wtxid coinbase-tx)))
      (is (= 32 (length wtxid)))
      (is (every #'zerop wtxid)))))

(test witness-stack-content-correct
  "Witness stack items should have correct byte content."
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (flexi-streams:with-input-from-sequence (s raw)
               (bitcoin-lisp.serialization:read-transaction s)))
         (stack (first (bitcoin-lisp.serialization:transaction-witness tx))))
    ;; First item: 72 bytes of 0xAA
    (is (every (lambda (b) (= b #xAA)) (first stack)))
    ;; Second item: 33 bytes of 0xBB
    (is (every (lambda (b) (= b #xBB)) (second stack)))))

(test read-uint32-le
  "Read uint32 little-endian should decode correctly."
  (let ((bytes #(#x01 #x02 #x03 #x04)))
    (flexi-streams:with-input-from-sequence (stream bytes)
      (is (= (bitcoin-lisp.serialization:read-uint32-le stream)
             #x04030201)))))

(test write-uint32-le
  "Write uint32 little-endian should encode correctly."
  (let ((result (flexi-streams:with-output-to-sequence (stream)
                  (bitcoin-lisp.serialization:write-uint32-le stream #x04030201))))
    (is (equalp result #(#x01 #x02 #x03 #x04)))))

(test compact-size-small
  "CompactSize encoding for small values (< 253)."
  (let ((result (flexi-streams:with-output-to-sequence (stream)
                  (bitcoin-lisp.serialization:write-compact-size stream 100))))
    (is (equalp result #(#x64)))))

(test compact-size-medium
  "CompactSize encoding for medium values (253-65535)."
  (let ((result (flexi-streams:with-output-to-sequence (stream)
                  (bitcoin-lisp.serialization:write-compact-size stream 1000))))
    (is (equalp result #(#xFD #xE8 #x03)))))

(test compact-size-roundtrip
  "CompactSize encode then decode should return original value."
  (dolist (value '(0 1 100 252 253 1000 65535 65536 1000000))
    (let* ((encoded (flexi-streams:with-output-to-sequence (stream)
                      (bitcoin-lisp.serialization:write-compact-size stream value)))
           (decoded (flexi-streams:with-input-from-sequence (stream encoded)
                      (bitcoin-lisp.serialization:read-compact-size stream))))
      (is (= decoded value)))))

;;;; Compact Block (BIP 152) message serialization tests

(defun make-compact-block-test-header ()
  "Create a test block header for compact block tests."
  (bitcoin-lisp.serialization:make-block-header
   :version 536870912
   :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11)
   :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22)
   :timestamp 1609459200
   :bits #x1d00ffff
   :nonce 12345))

(defun make-compact-block-test-transaction ()
  "Create a simple test transaction for compact block tests."
  (bitcoin-lisp.serialization:make-transaction
   :version 2
   :inputs (list (bitcoin-lisp.serialization:make-tx-in
                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                      :initial-element #x33)
                                    :index 0)
                  :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                  :sequence #xffffffff))
   :outputs (list (bitcoin-lisp.serialization:make-tx-out
                   :value 50000
                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                              :initial-element #x76)))
   :lock-time 0))

(test sendcmpct-message-roundtrip
  "sendcmpct message should serialize and parse correctly."
  ;; Test low-bandwidth mode, version 1
  (let* ((msg (bitcoin-lisp.serialization:make-sendcmpct-message nil 1))
         ;; Extract payload (skip 24-byte header)
         (payload (subseq msg 24)))
    (multiple-value-bind (high-bw version)
        (bitcoin-lisp.serialization:parse-sendcmpct-payload payload)
      (is (null high-bw))
      (is (= version 1))))
  ;; Test high-bandwidth mode, version 2
  (let* ((msg (bitcoin-lisp.serialization:make-sendcmpct-message t 2))
         (payload (subseq msg 24)))
    (multiple-value-bind (high-bw version)
        (bitcoin-lisp.serialization:parse-sendcmpct-payload payload)
      (is (eq high-bw t))
      (is (= version 2)))))

(test compact-block-roundtrip
  "Compact block should serialize and deserialize correctly."
  (let* ((header (make-compact-block-test-header))
         (nonce #x123456789abcdef0)
         (short-ids (list #x112233445566 #xaabbccddeeff))
         (prefilled-tx (bitcoin-lisp.serialization:make-prefilled-tx
                        :index 0
                        :transaction (make-compact-block-test-transaction)))
         (cb (bitcoin-lisp.serialization:make-compact-block
              :header header
              :nonce nonce
              :short-ids short-ids
              :prefilled-txs (list prefilled-tx)))
         ;; Serialize
         (bytes (flexi-streams:with-output-to-sequence (s)
                  (bitcoin-lisp.serialization:write-compact-block s cb)))
         ;; Deserialize
         (cb2 (flexi-streams:with-input-from-sequence (s bytes)
                (bitcoin-lisp.serialization:read-compact-block s))))
    ;; Verify header
    (is (= (bitcoin-lisp.serialization:block-header-version
            (bitcoin-lisp.serialization:compact-block-header cb2))
           536870912))
    ;; Verify nonce
    (is (= (bitcoin-lisp.serialization:compact-block-nonce cb2) nonce))
    ;; Verify short IDs
    (is (= (length (bitcoin-lisp.serialization:compact-block-short-ids cb2)) 2))
    (is (= (first (bitcoin-lisp.serialization:compact-block-short-ids cb2)) #x112233445566))
    (is (= (second (bitcoin-lisp.serialization:compact-block-short-ids cb2)) #xaabbccddeeff))
    ;; Verify prefilled transactions
    (is (= (length (bitcoin-lisp.serialization:compact-block-prefilled-txs cb2)) 1))
    (let ((ptx (first (bitcoin-lisp.serialization:compact-block-prefilled-txs cb2))))
      (is (= (bitcoin-lisp.serialization:prefilled-tx-index ptx) 0)))))

(test compact-block-differential-index-encoding
  "Prefilled transaction indexes should use differential encoding."
  ;; Create compact block with prefilled txs at indexes 0, 2, 5
  ;; Differential: 0, (2-0-1)=1, (5-2-1)=2
  (let* ((header (make-compact-block-test-header))
         (tx (make-compact-block-test-transaction))
         (prefilled (list (bitcoin-lisp.serialization:make-prefilled-tx :index 0 :transaction tx)
                          (bitcoin-lisp.serialization:make-prefilled-tx :index 2 :transaction tx)
                          (bitcoin-lisp.serialization:make-prefilled-tx :index 5 :transaction tx)))
         (cb (bitcoin-lisp.serialization:make-compact-block
              :header header
              :nonce 0
              :short-ids '()
              :prefilled-txs prefilled))
         (bytes (flexi-streams:with-output-to-sequence (s)
                  (bitcoin-lisp.serialization:write-compact-block s cb)))
         (cb2 (flexi-streams:with-input-from-sequence (s bytes)
                (bitcoin-lisp.serialization:read-compact-block s))))
    ;; After parsing, indexes should be absolute again
    (let ((parsed-prefilled (bitcoin-lisp.serialization:compact-block-prefilled-txs cb2)))
      (is (= (bitcoin-lisp.serialization:prefilled-tx-index (first parsed-prefilled)) 0))
      (is (= (bitcoin-lisp.serialization:prefilled-tx-index (second parsed-prefilled)) 2))
      (is (= (bitcoin-lisp.serialization:prefilled-tx-index (third parsed-prefilled)) 5)))))

(test getblocktxn-message-roundtrip
  "getblocktxn message should serialize correctly."
  (let* ((block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab))
         (indexes '(1 3 5 7))
         (msg (bitcoin-lisp.serialization:make-getblocktxn-message block-hash indexes))
         ;; Extract payload (skip 24-byte header)
         (payload (subseq msg 24))
         (request (bitcoin-lisp.serialization:parse-getblocktxn-payload payload)))
    (is (equalp (bitcoin-lisp.serialization:block-txn-request-block-hash request) block-hash))
    (is (equal (bitcoin-lisp.serialization:block-txn-request-indexes request) indexes))))

(test short-txid-in-compact-block
  "Short txids in compact blocks should round-trip correctly."
  ;; Test via compact block serialization which uses short txids internally
  (let* ((header (make-compact-block-test-header))
         (short-ids (list #xaabbccddeeff #x112233445566))
         (cb (bitcoin-lisp.serialization:make-compact-block
              :header header
              :nonce 0
              :short-ids short-ids
              :prefilled-txs '()))
         (bytes (flexi-streams:with-output-to-sequence (s)
                  (bitcoin-lisp.serialization:write-compact-block s cb)))
         (cb2 (flexi-streams:with-input-from-sequence (s bytes)
                (bitcoin-lisp.serialization:read-compact-block s))))
    ;; Short IDs should round-trip correctly
    (is (= (first (bitcoin-lisp.serialization:compact-block-short-ids cb2))
           #xaabbccddeeff))
    (is (= (second (bitcoin-lisp.serialization:compact-block-short-ids cb2))
           #x112233445566))))

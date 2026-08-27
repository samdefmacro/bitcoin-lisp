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
   (bl.bytes:with-byte-buf (s)
     ;; Version = 2
     (bl.bytes:bb-write-i32-le s 2)
     ;; Marker + flag
     (bl.bytes:bb-write-u8 s #x00)
     (bl.bytes:bb-write-u8 s #x01)
     ;; 1 input
     (bl.bytes:bb-write-varint s 1)
     ;; prev outpoint: txid (32 bytes of 0x11), index 0
     (bl.bytes:bb-write-bytes s (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11))
     (bl.bytes:bb-write-u32-le s 0)
     ;; empty scriptSig
     (bl.bytes:bb-write-varint s 0)
     ;; sequence
     (bl.bytes:bb-write-u32-le s #xFFFFFFFE)
     ;; 1 output
     (bl.bytes:bb-write-varint s 1)
     ;; value: 49999 satoshis
     (bl.bytes:bb-write-i64-le s 49999)
     ;; 25-byte scriptPubKey (P2PKH placeholder)
     (bl.bytes:bb-write-varint s 25)
     (bl.bytes:bb-write-bytes s (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
     ;; Witness for input 0: 2 items
     (bl.bytes:bb-write-varint s 2)
     ;; Item 1: 72-byte signature placeholder
     (bl.bytes:bb-write-varint s 72)
     (bl.bytes:bb-write-bytes s (make-array 72 :element-type '(unsigned-byte 8) :initial-element #xAA))
     ;; Item 2: 33-byte pubkey placeholder
     (bl.bytes:bb-write-varint s 33)
     (bl.bytes:bb-write-bytes s (make-array 33 :element-type '(unsigned-byte 8) :initial-element #xBB))
     ;; Locktime: 500000
     (bl.bytes:bb-write-u32-le s 500000))
   '(simple-array (unsigned-byte 8) (*))))

(test witness-transaction-deserialize
  "A BIP 144 witness transaction should deserialize correctly."
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (bl.bytes:with-byte-reader (s raw)
               (bl.ser:br-read-transaction s))))
    ;; Basic fields
    (is (= 2 (bl.ser:transaction-version tx)))
    (is (= 1 (length (bl.ser:transaction-inputs tx))))
    (is (= 1 (length (bl.ser:transaction-outputs tx))))
    (is (= 500000 (bl.ser:transaction-lock-time tx)))
    ;; Input details
    (let ((input (elt (bl.ser:transaction-inputs tx) 0)))
      (is (every (lambda (b) (= b #x11))
                 (bl.ser:outpoint-hash
                  (bl.ser:tx-in-previous-output input))))
      (is (= 0 (length (bl.ser:tx-in-script-sig input))))
      (is (= #xFFFFFFFE (bl.ser:tx-in-sequence input))))
    ;; Output
    (let ((output (elt (bl.ser:transaction-outputs tx) 0)))
      (is (= 49999 (bl.ser:tx-out-value output))))
    ;; Witness data
    (is (bl.ser:transaction-has-witness-p tx))
    (let ((witness (bl.ser:transaction-witness tx)))
      (is (= 1 (length witness)))       ; 1 input's witness
      (is (= 2 (length (elt witness 0)))) ; 2 stack items
      (is (= 72 (length (first (elt witness 0)))))  ; sig
      (is (= 33 (length (second (elt witness 0))))))))  ; pubkey

(test witness-transaction-round-trip
  "Serializing a witness transaction back should produce identical bytes."
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (bl.bytes:with-byte-reader (s raw)
               (bl.ser:br-read-transaction s)))
         (re-serialized (bl.ser:serialize-witness-transaction tx)))
    (is (equalp raw re-serialized))))

(test transaction-wire-bytes-matches-core-tx-with-witness
  "transaction-wire-bytes mirrors Core's TX_WITH_WITNESS SerializeTransaction
(primitives/transaction.h:241): a segwit tx serializes with marker/flag and
round-trips byte-exact; a witnessless tx serializes in legacy form, with NO
marker/flag (byte 4, the input count, must be non-zero)."
  ;; Witness tx: wire form == BIP 144 form, byte-exact against the source bytes.
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (bl.bytes:with-byte-reader (s raw)
               (bl.ser:br-read-transaction s)))
         (wire (bl.ser:transaction-wire-bytes tx)))
    (is (equalp raw wire))
    (is (= #x00 (aref wire 4)))         ; marker
    (is (= #x01 (aref wire 5)))         ; flag
    ;; Round-trip: witness survives re-deserialization of the wire bytes.
    (let ((tx2 (bl.bytes:with-byte-reader (s wire)
                 (bl.ser:br-read-transaction s))))
      (is (bl.ser:transaction-has-witness-p tx2))
      (is (equalp (bl.ser:transaction-wtxid tx)
                  (bl.ser:transaction-wtxid tx2)))))
  ;; Witnessless tx: wire form == legacy form, no marker/flag.
  (let* ((tx (make-mempool-test-tx))
         (wire (bl.ser:transaction-wire-bytes tx)))
    (is (equalp (bl.ser:serialize-transaction tx) wire))
    (is (/= #x00 (aref wire 4))))
  ;; A tx whose witness vector holds only empty stacks counts as witnessless
  ;; (Core HasWitness: some scriptWitness must be non-null).
  (let ((tx (make-mempool-test-tx)))
    (setf (bl.ser:transaction-witness tx) (vector '()))
    (is (equalp (bl.ser:serialize-transaction tx)
                (bl.ser:transaction-wire-bytes tx)))))

(test witness-txid-excludes-witness
  "The txid should be computed from legacy serialization (no witness)."
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (bl.bytes:with-byte-reader (s raw)
               (bl.ser:br-read-transaction s)))
         (txid (bl.ser:transaction-hash tx))
         ;; Manually compute legacy serialization hash
         (legacy-bytes (bl.ser:serialize-transaction tx))
         (expected-txid (bl.crypto:hash256 legacy-bytes)))
    ;; txid should match legacy hash
    (is (equalp txid expected-txid))
    ;; legacy bytes should NOT equal witness bytes
    (is (not (equalp legacy-bytes (make-witness-test-tx-bytes))))))

(test witness-wtxid-includes-witness
  "The wtxid should be computed from witness serialization."
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (bl.bytes:with-byte-reader (s raw)
               (bl.ser:br-read-transaction s)))
         (wtxid (bl.ser:transaction-wtxid tx))
         (expected-wtxid (bl.crypto:hash256 raw)))
    ;; wtxid should match hash of full witness serialization
    (is (equalp wtxid expected-wtxid))
    ;; wtxid should differ from txid
    (is (not (equalp wtxid (bl.ser:transaction-hash tx))))))

(test legacy-transaction-still-works
  "Legacy transactions (no witness) should still deserialize correctly."
  (let* ((legacy-bytes
           (coerce
            (bl.bytes:with-byte-buf (s)
              (bl.bytes:bb-write-i32-le s 1)  ; version
              (bl.bytes:bb-write-varint s 1) ; 1 input
              ;; prev outpoint
              (bl.bytes:bb-write-bytes s (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element #x22))
              (bl.bytes:bb-write-u32-le s 0)
              ;; scriptSig (10 bytes)
              (bl.bytes:bb-write-varint s 10)
              (bl.bytes:bb-write-bytes s (make-array 10 :element-type '(unsigned-byte 8)
                                             :initial-element #x48))
              (bl.bytes:bb-write-u32-le s #xFFFFFFFF) ; sequence
              (bl.bytes:bb-write-varint s 1) ; 1 output
              (bl.bytes:bb-write-i64-le s 100000)
              (bl.bytes:bb-write-varint s 25)
              (bl.bytes:bb-write-bytes s (make-array 25 :element-type '(unsigned-byte 8)
                                             :initial-element #x76))
              (bl.bytes:bb-write-u32-le s 0)) ; locktime
            '(simple-array (unsigned-byte 8) (*))))
         (tx (bl.bytes:with-byte-reader (s legacy-bytes)
               (bl.ser:br-read-transaction s))))
    (is (= 1 (bl.ser:transaction-version tx)))
    (is (= 1 (length (bl.ser:transaction-inputs tx))))
    (is (= 10 (length (bl.ser:tx-in-script-sig
                        (elt (bl.ser:transaction-inputs tx) 0)))))
    (is (not (bl.ser:transaction-has-witness-p tx)))
    ;; Legacy round-trip
    (let ((re-serialized (bl.ser:serialize-transaction tx)))
      (is (equalp legacy-bytes re-serialized)))))

(test coinbase-wtxid-is-zero
  "Coinbase transaction wtxid should be 32 zero bytes."
  (let ((coinbase-tx (bl.ser:make-transaction
                      :version 1
                      :inputs (vector (bl.ser:make-tx-in
                                     :previous-output (bl.ser:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element 0)
                                                       :index #xFFFFFFFF)
                                     :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                               :initial-element 1)))
                      :outputs (vector (bl.ser:make-tx-out
                                      :value 5000000000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0)))
    (let ((wtxid (bl.ser:transaction-wtxid coinbase-tx)))
      (is (= 32 (length wtxid)))
      (is (every #'zerop wtxid)))))

(test witness-stack-content-correct
  "Witness stack items should have correct byte content."
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (bl.bytes:with-byte-reader (s raw)
               (bl.ser:br-read-transaction s)))
         (stack (elt (bl.ser:transaction-witness tx) 0)))
    ;; First item: 72 bytes of 0xAA
    (is (every (lambda (b) (= b #xAA)) (first stack)))
    ;; Second item: 33 bytes of 0xBB
    (is (every (lambda (b) (= b #xBB)) (second stack)))))

(test read-uint32-le
  "Read uint32 little-endian should decode correctly."
  (let ((bytes #(#x01 #x02 #x03 #x04)))
    (bl.bytes:with-byte-reader (stream bytes)
      (is (= (bl.bytes:br-read-u32-le stream)
             #x04030201)))))

(test write-uint32-le
  "Write uint32 little-endian should encode correctly."
  (let ((result (bl.bytes:with-byte-buf (stream)
                  (bl.bytes:bb-write-u32-le stream #x04030201))))
    (is (equalp result #(#x01 #x02 #x03 #x04)))))

(test compact-size-small
  "CompactSize encoding for small values (< 253)."
  (let ((result (bl.bytes:with-byte-buf (stream)
                  (bl.bytes:bb-write-varint stream 100))))
    (is (equalp result #(#x64)))))

(test compact-size-medium
  "CompactSize encoding for medium values (253-65535)."
  (let ((result (bl.bytes:with-byte-buf (stream)
                  (bl.bytes:bb-write-varint stream 1000))))
    (is (equalp result #(#xFD #xE8 #x03)))))

(test compact-size-roundtrip
  "CompactSize encode then decode should return original value."
  (dolist (value '(0 1 100 252 253 1000 65535 65536 1000000))
    (let* ((encoded (bl.bytes:with-byte-buf (stream)
                      (bl.bytes:bb-write-varint stream value)))
           (decoded (bl.bytes:with-byte-reader (stream encoded)
                      (bl.bytes:br-read-compact-size stream))))
      (is (= decoded value)))))

;;;; Compact Block (BIP 152) message serialization tests

(defun make-compact-block-test-header ()
  "Create a test block header for compact block tests."
  (bl.ser:make-block-header
   :version 536870912
   :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11)
   :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22)
   :timestamp 1609459200
   :bits #x1d00ffff
   :nonce 12345))

(defun make-compact-block-test-transaction ()
  "Create a simple test transaction for compact block tests."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                  :previous-output (bl.ser:make-outpoint
                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                      :initial-element #x33)
                                    :index 0)
                  :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                  :sequence #xffffffff))
   :outputs (vector (bl.ser:make-tx-out
                   :value 50000
                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                              :initial-element #x76)))
   :lock-time 0))

(test sendcmpct-message-roundtrip
  "sendcmpct message should serialize and parse correctly."
  ;; Test low-bandwidth mode, version 1
  (let* ((msg (bl.ser:make-sendcmpct-message nil 1))
         ;; Extract payload (skip 24-byte header)
         (payload (subseq msg 24)))
    (multiple-value-bind (high-bw version)
        (bl.ser:parse-sendcmpct-payload payload)
      (is (null high-bw))
      (is (= version 1))))
  ;; Test high-bandwidth mode, version 2
  (let* ((msg (bl.ser:make-sendcmpct-message t 2))
         (payload (subseq msg 24)))
    (multiple-value-bind (high-bw version)
        (bl.ser:parse-sendcmpct-payload payload)
      (is (eq high-bw t))
      (is (= version 2)))))

(test compact-block-roundtrip
  "Compact block should serialize and deserialize correctly."
  (let* ((header (make-compact-block-test-header))
         (nonce #x123456789abcdef0)
         (short-ids (list #x112233445566 #xaabbccddeeff))
         (prefilled-tx (bl.ser:make-prefilled-tx
                        :index 0
                        :transaction (make-compact-block-test-transaction)))
         (cb (bl.ser:make-compact-block
              :header header
              :nonce nonce
              :short-ids short-ids
              :prefilled-txs (list prefilled-tx)))
         ;; Serialize
         (bytes (bl.bytes:with-byte-buf (s)
                  (bl.ser:write-compact-block s cb)))
         ;; Deserialize
         (cb2 (bl.bytes:with-byte-reader (s bytes)
                (bl.ser:read-compact-block s))))
    ;; Verify header
    (is (= (bl.ser:block-header-version
            (bl.ser:compact-block-header cb2))
           536870912))
    ;; Verify nonce
    (is (= (bl.ser:compact-block-nonce cb2) nonce))
    ;; Verify short IDs
    (is (= (length (bl.ser:compact-block-short-ids cb2)) 2))
    (is (= (first (bl.ser:compact-block-short-ids cb2)) #x112233445566))
    (is (= (second (bl.ser:compact-block-short-ids cb2)) #xaabbccddeeff))
    ;; Verify prefilled transactions
    (is (= (length (bl.ser:compact-block-prefilled-txs cb2)) 1))
    (let ((ptx (first (bl.ser:compact-block-prefilled-txs cb2))))
      (is (= (bl.ser:prefilled-tx-index ptx) 0)))))

(test compact-block-differential-index-encoding
  "Prefilled transaction indexes should use differential encoding."
  ;; Create compact block with prefilled txs at indexes 0, 2, 5
  ;; Differential: 0, (2-0-1)=1, (5-2-1)=2
  (let* ((header (make-compact-block-test-header))
         (tx (make-compact-block-test-transaction))
         (prefilled (list (bl.ser:make-prefilled-tx :index 0 :transaction tx)
                          (bl.ser:make-prefilled-tx :index 2 :transaction tx)
                          (bl.ser:make-prefilled-tx :index 5 :transaction tx)))
         (cb (bl.ser:make-compact-block
              :header header
              :nonce 0
              :short-ids '()
              :prefilled-txs prefilled))
         (bytes (bl.bytes:with-byte-buf (s)
                  (bl.ser:write-compact-block s cb)))
         (cb2 (bl.bytes:with-byte-reader (s bytes)
                (bl.ser:read-compact-block s))))
    ;; After parsing, indexes should be absolute again
    (let ((parsed-prefilled (bl.ser:compact-block-prefilled-txs cb2)))
      (is (= (bl.ser:prefilled-tx-index (first parsed-prefilled)) 0))
      (is (= (bl.ser:prefilled-tx-index (second parsed-prefilled)) 2))
      (is (= (bl.ser:prefilled-tx-index (third parsed-prefilled)) 5)))))

(test getblocktxn-message-roundtrip
  "getblocktxn message should serialize correctly."
  (let* ((block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab))
         (indexes '(1 3 5 7))
         (msg (bl.ser:make-getblocktxn-message block-hash indexes))
         ;; Extract payload (skip 24-byte header)
         (payload (subseq msg 24))
         (request (bl.ser:parse-getblocktxn-payload payload)))
    (is (equalp (bl.ser:block-txn-request-block-hash request) block-hash))
    (is (equal (bl.ser:block-txn-request-indexes request) indexes))))

(test short-txid-in-compact-block
  "Short txids in compact blocks should round-trip correctly."
  ;; Test via compact block serialization which uses short txids internally
  (let* ((header (make-compact-block-test-header))
         (short-ids (list #xaabbccddeeff #x112233445566))
         (cb (bl.ser:make-compact-block
              :header header
              :nonce 0
              :short-ids short-ids
              :prefilled-txs '()))
         (bytes (bl.bytes:with-byte-buf (s)
                  (bl.ser:write-compact-block s cb)))
         (cb2 (bl.bytes:with-byte-reader (s bytes)
                (bl.ser:read-compact-block s))))
    ;; Short IDs should round-trip correctly
    (is (= (first (bl.ser:compact-block-short-ids cb2))
           #xaabbccddeeff))
    (is (= (second (bl.ser:compact-block-short-ids cb2))
           #x112233445566))))


(test script-push-data-minimal-encoding
  "Core CScript::operator<< picks the smallest push opcode for the length:
direct to 75, OP_PUSHDATA1 to 255, OP_PUSHDATA2 to 65535, OP_PUSHDATA4 above.
The 76-byte case is the testnet4 genesis timestamp message."
  (flet ((push-of (n)
           (bl.ser:script-push-data
            (make-array n :element-type '(unsigned-byte 8) :initial-element 7)))
         (prefix (v k) (coerce (subseq v 0 k) 'list)))
    (is (equal '(0) (coerce (push-of 0) 'list)))
    (is (equal '(75) (prefix (push-of 75) 1)))
    (is (equal '(#x4c 76) (prefix (push-of 76) 2)))
    (is (equal '(#x4c 255) (prefix (push-of 255) 2)))
    (is (equal '(#x4d #x00 #x01) (prefix (push-of 256) 3)))
    (is (equal '(#x4d #xff #xff) (prefix (push-of 65535) 3)))
    (is (equal '(#x4e #x00 #x00 #x01 #x00) (prefix (push-of 65536) 5)))
    (is (= (+ 3 300) (length (push-of 300))))
    (is (typep (push-of 10) '(simple-array (unsigned-byte 8) (*))))))

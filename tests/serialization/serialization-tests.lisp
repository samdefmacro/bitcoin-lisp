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

(test coinbase-wtxid-is-its-real-witness-hash
  "A coinbase's wtxid is its own GetWitnessHash, never the merkle tree's zero.

transaction-wtxid special-cased the coinbase and returned 32 zero bytes, so
getblock verbosity 2/3 and getrawtransaction reported hash=000...0 for the
coinbase of every block (Core core_io.cpp:435 emits GetWitnessHash there).
The zero belongs to BlockWitnessMerkleRoot alone."
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
    ;; Core's ComputeWitnessHash has no coinbase case: a witnessless coinbase
    ;; reports its TXID (primitives/transaction.cpp:88-95). The all-zero value
    ;; is the witness MERKLE leaf (consensus/merkle.cpp:80), not this.
    (let ((wtxid (bl.ser:transaction-wtxid coinbase-tx)))
      (is (= 32 (length wtxid)))
      (is (notevery #'zerop wtxid)
          "the coinbase's own wtxid is never the merkle tree's zero leaf")
      (is (equalp (bl.ser:transaction-hash coinbase-tx) wtxid)))
    ;; With a witness it is the hash of the witness serialization, which the
    ;; wallet, getblock and getrawtransaction all report as "hash"/"wtxid".
    (let* ((witnessed (bl.ser:make-transaction
                       :version (bl.ser:transaction-version coinbase-tx)
                       :inputs (bl.ser:transaction-inputs coinbase-tx)
                       :outputs (bl.ser:transaction-outputs coinbase-tx)
                       :witness (vector (list (make-array 32 :element-type '(unsigned-byte 8)
                                                             :initial-element 0)))
                       :lock-time 0))
           (wtxid (bl.ser:transaction-wtxid witnessed)))
      (is (equalp (bl.crypto:hash256 (bl.ser:serialize-witness-transaction witnessed))
                  wtxid))
      (is (not (equalp (bl.ser:transaction-hash witnessed) wtxid))))))

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

(test compact-block-prefilled-tx-is-core-tx-with-witness
  "A prefilled transaction is written with Core's TX_WITH_WITNESS, which emits
the 0x0001 marker only for a transaction that HAS witness data
(primitives/transaction.h:236-262). This wrote SERIALIZE-WITNESS-TRANSACTION
unconditionally, so a witnessless prefilled transaction went out as a
`Superfluous witness record\' -- bytes Core's own deserializer refuses."
  (let* ((tx (make-compact-block-test-transaction))
         (cb (bl.ser:make-compact-block
              :header (make-compact-block-test-header)
              :nonce 0
              :short-ids '()
              :prefilled-txs (list (bl.ser:make-prefilled-tx :index 0 :transaction tx))))
         (bytes (bl.bytes:with-byte-buf (s) (bl.ser:write-compact-block s cb)))
         (wire (bl.crypto:bytes-to-hex (bl.ser:transaction-wire-bytes tx))))
    (is-false (bl.ser:transaction-has-witness-p tx)
              "the fixture transaction must carry no witness")
    (is-true (search wire (bl.crypto:bytes-to-hex bytes))
             "the prefilled transaction is not TX_WITH_WITNESS bytes")
    ;; The marker would sit right after the 4-byte version of the embedded tx.
    (is-false (search (concatenate 'string (subseq wire 0 8) "0001")
                      (bl.crypto:bytes-to-hex bytes))
              "a superfluous 0x0001 witness marker was written")))

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

(defun %version-with-user-agent-string (string)
  "A VERSION payload whose user agent is STRING, read back; the user agent's
length in CHARACTERS, or the error the read signalled."
  (let ((payload (bl.ser:make-version-message-bytes
                  :user-agent string :nonce 7)))
    (handler-case
        (bl.bytes:with-byte-reader (s payload)
          (length (bl.ser:version-message-user-agent
                   (bl.ser:read-version-message s))))
      (bl.err:serialization-error (e) e))))

(defun %version-with-user-agent (n)
  "A VERSION payload whose user agent is N 'A's, read back; the user agent's
length, or the error the read signalled."
  (%version-with-user-agent-string (make-string n :initial-element #\A)))

(test version-user-agent-is-limited-to-cores-256-bytes
  "GA11 1052063f. Core reads the subversion through
LIMITED_STRING(strSubVer, MAX_SUBVERSION_LENGTH) (net_processing.cpp:3640),
which THROWS above 256 bytes -- the VERSION fails to deserialize and the peer
is dropped on the bad message, rather than the string being truncated and kept.

Ours read it as a plain CompactSize-prefixed string bounded only by
+max-message-payload+, so one peer could hand us ~4 MB of arbitrary bytes per
connection, retained on the peer object and re-serialized into every
getpeerinfo response (125 inbound slots = ~500 MB).

The check is on the LENGTH PREFIX, before the bytes are read, so an oversized
claim costs no allocation."
  (is (= 255 (%version-with-user-agent 255)))
  ;; The boundary itself parses -- without this the cap could be rejecting
  ;; everything and the assertions below would still pass.
  (is (= 256 (%version-with-user-agent 256))
      "positive control: a 256-byte user agent is exactly Core's limit and must parse")
  (dolist (n '(257 1000 200000))
    (let ((result (%version-with-user-agent n)))
      (is-true (typep result 'bl.err:serialization-error)
               "a ~D-byte user agent parsed to ~S instead of failing the message" n result)
      (is-true (search "exceeds maximum 256" (princ-to-string result))
               "unexpected error text: ~A" result))))

(defun %version-relay-for-byte (byte &key (version bl.ser:+protocol-version+))
  "The relay flag a VERSION message whose fRelay byte is BYTE reads back as."
  (let ((payload (copy-seq (bl.ser:make-version-message-bytes
                            :version version :relay t :nonce 7))))
    (setf (aref payload (1- (length payload))) byte)
    (bl.bytes:with-byte-reader (s payload)
      (bl.ser:version-message-relay (bl.ser:read-version-message s)))))

(defun %sendcmpct-announce-for-byte (byte)
  "The high-bandwidth flag a sendcmpct payload whose announce byte is BYTE
reads back as. The eight bytes after it are the little-endian version 2."
  (let ((payload (make-array 9 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref payload 0) byte
          (aref payload 1) 2)
    (bl.ser:parse-sendcmpct-payload payload)))

(test wire-boolean-is-true-for-every-nonzero-byte
  "GA11 d9ca7c2f. Core's bool unserializer assigns the raw byte to the bool --
`uint8_t f = ser_readdata8(s); a = f;' (serialize.h:277) -- so 2 and 255 read
as TRUE. Three places here tested the byte for equality with 1 instead: the
generated :bool codec row, the version message's relay :read form and
PARSE-SENDCMPCT-PAYLOAD, so a peer sending fRelay = 2 was recorded as not
wanting transactions and a sendcmpct with announce = 2 did not put us in that
peer's high-bandwidth set. Core writes only 0 and 1, which is what keeps this
to another implementation's or a fuzzer's bytes.

Byte 1 is the control: it must stay true through the change, and byte 0 must
stay false, or `every byte is true' would pass here just as well."
  (is-false (%version-relay-for-byte 0))
  (is-true (%version-relay-for-byte 1))
  (is-true (%version-relay-for-byte 2))
  (is-true (%version-relay-for-byte 255))
  (is-false (%sendcmpct-announce-for-byte 0))
  (is-true (%sendcmpct-announce-for-byte 1))
  (is-true (%sendcmpct-announce-for-byte 2))
  (is-true (%sendcmpct-announce-for-byte 255))
  ;; sendcmpct's second value is untouched by the flag's rule.
  (is (= 2 (nth-value 1 (%sendcmpct-announce-for-byte 2))))
  ;; The relay field's :READ form still owns the two things the codec row
  ;; cannot know: BIP 37's absent-means-relay default, and that a peer older
  ;; than 70002 never sends the byte at all.
  (is-true (let ((full (bl.ser:make-version-message-bytes :relay nil :nonce 7)))
             (bl.bytes:with-byte-reader (s (subseq full 0 (1- (length full))))
               (bl.ser:version-message-relay (bl.ser:read-version-message s))))
           "an absent fRelay means relay (BIP 37)")
  (is-true (%version-relay-for-byte 0 :version 70001)
           "a pre-70002 peer's trailing byte is not an fRelay flag"))

(defun %version-user-agent-field-bytes (string)
  "The bytes the VERSION message writes for STRING in its :var-string
user-agent field, CompactSize length prefix included. The field ends five
bytes before the payload does -- start_height (4) and the fRelay flag (1) --
and an empty user agent occupies exactly one byte, which locates its start."
  (let* ((empty (bl.ser:make-version-message-bytes :user-agent "" :nonce 5))
         (start (- (length empty) 6))
         (payload (bl.ser:make-version-message-bytes :user-agent string :nonce 5)))
    (subseq payload start (- (length payload) 5))))

(defun %version-user-agent-from-bytes (bytes)
  "The character codes of the user agent a VERSION whose user-agent field
holds the raw BYTES reads back as. The placeholder is the same length, so its
CompactSize prefix is the one BYTES needs."
  (let* ((payload (bl.ser:make-version-message-bytes
                   :user-agent (make-string (length bytes) :initial-element #\A)
                   :nonce 5)))
    (replace payload bytes :start1 (- (length payload) 5 (length bytes)))
    (bl.bytes:with-byte-reader (s payload)
      (map 'list #'char-code
           (bl.ser:version-message-user-agent (bl.ser:read-version-message s))))))

(test var-string-fields-are-utf-8-bytes-not-one-byte-per-code-point
  "GA11 2cae91f5. Core's std::basic_string serializer is a CompactSize length
and the raw bytes, with no character conversion at either end
(serialize.h:780-793) -- a std::string IS its bytes. The one codec row behind
DEFINE-MESSAGE and the wallet's DEFINE-WDB-KEY / DEFINE-WDB-VALUE wrote
(map '(vector (unsigned-byte 8)) #'char-code value) and read (map 'string
#'code-char ...), i.e. Latin-1: a character above U+00FF made the WRITE a raw
TYPE-ERROR, and everything from U+0080 up went to disk as one byte where Core
writes two or more.

The four classes below are the ones a wallet label spans. The empty string and
the ASCII case are the controls: they are byte-identical under either encoding,
so a change that broke them would not pass here.

The READ direction is asserted first on purpose: on the pre-fix code the write
of a character above U+00FF is a TYPE-ERROR, which ends the test where it
stands, so anything after it would prove nothing."
  ;; The read direction, per class. ASCII is the control.
  (is (equal '(105) (%version-user-agent-from-bytes #(105))))
  (is (equal (list #xE9) (%version-user-agent-from-bytes #(195 169))))
  (is (equal (list #x4E2D) (%version-user-agent-from-bytes #(228 184 173))))
  (is (equal (list #x1F600) (%version-user-agent-from-bytes #(240 159 152 128))))
  ;; Peer bytes are untrusted and Core never decodes them, so an invalid
  ;; sequence is REPLACED (U+FFFD) and the message still parses -- signalling
  ;; would refuse a VERSION Core reads.
  (is (equal (list #xFFFD #xFFFD 65) (%version-user-agent-from-bytes #(255 254 65)))
      "invalid UTF-8 must be replaced, not signalled")
  ;; Core's LIMITED_STRING counts BYTES, so the cap is on the encoding: 128
  ;; two-byte characters are exactly 256 bytes and parse, 129 do not.
  (let ((e-acute (code-char #xE9)))
    (is (= 128 (%version-with-user-agent-string
                (make-string 128 :initial-element e-acute))))
    (is-true (typep (%version-with-user-agent-string
                     (make-string 129 :initial-element e-acute))
                    'bl.err:serialization-error)
             "the 256-byte cap must count bytes, not characters"))
  ;; The write direction, same classes and same bytes.
  (is (equalp #(0) (%version-user-agent-field-bytes "")))
  (is (equalp #(2 104 105) (%version-user-agent-field-bytes "hi")))
  ;; U+00E9, the case that used to write the single byte E9.
  (is (equalp #(2 195 169)
              (%version-user-agent-field-bytes (string (code-char #xE9)))))
  ;; U+4E2D, the case that used to signal.
  (is (equalp #(3 228 184 173)
              (%version-user-agent-field-bytes (string (code-char #x4E2D)))))
  ;; U+1F600, above the BMP: four bytes, one CL character.
  (is (equalp #(4 240 159 152 128)
              (%version-user-agent-field-bytes (string (code-char #x1F600))))))

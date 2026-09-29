(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/deserialize.cpp at the pin: one FUZZ_TARGET per
;;;; serializable type. Every target deserializes the buffer, treating only
;;;; std::ios_base::failure as a legitimate refusal (DeserializeFromFuzzingInput,
;;;; :88-98) -- anything else a decoder throws is a crash -- and asserts that
;;;; a non-empty buffer that decoded re-serializes to something non-empty. The
;;;; types Core also round-trips (AssertEqualAfterSerializeDeserialize,
;;;; :100-109) get that assertion here too, as deser(ser(obj)) re-encoding to
;;;; ser(obj), plus the stronger byte form the canonical encodings allow: the
;;;; bytes the decoder consumed are exactly ser(obj).
;;;;
;;;; Types with no counterpart in this tree are named in the coverage document,
;;;; not faked here: BlockFilter (we build and serve filters, never decode
;;;; one), CPubKey and KeyOriginInfo (no stream codec of their own), FlatFilePos
;;;; alone (only inside CDiskTxPos), uint160/uint256 (raw octet vectors),
;;;; SnapshotMetadata, AddrInfo (see the addrman targets).

(def-suite :fuzz-deserialize-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/deserialize.cpp targets")

(in-suite :fuzz-deserialize-tests)

;;; --- helpers ---------------------------------------------------------------

(defun %ser (writer object)
  "OBJECT written by the byte-buf WRITER (bb object) into a fresh vector."
  (let ((bb (bl.ser:make-byte-buf)))
    (funcall writer bb object)
    (bl.ser:bb-finish bb)))

(defun deserialize-from-fuzzing-input (buffer reader)
  "Core DeserializeFromFuzzingInput: (values OBJECT CONSUMED) from READER (a
function of a byte-reader) over BUFFER; a SERIALIZATION-ERROR rejects the buffer."
  (let* ((br (bl.ser:make-byte-reader-from buffer))
         (object (fuzz-deserialize (funcall reader br))))
    (values object (subseq buffer 0 (bl.ser:br-pos br)))))

(defun assert-nonempty-reserialization (buffer bytes)
  "deserialize.cpp:97: assert(buffer.empty() || !Serialize(obj).empty())."
  (fuzz-assert (or (zerop (length buffer)) (fuzz-sabotage (plusp (length bytes))))
               "a non-empty buffer decoded to an object that serializes to nothing"))

(defun assert-equal-after-serialize-deserialize (object reader writer &optional consumed)
  "deserialize.cpp:100-109, deser(ser(obj)) == obj, compared as encodings;
with CONSUMED, also ser(obj) == the bytes the decoder read."
  (let* ((bytes (%ser writer object))
         (again (%ser writer (funcall reader (bl.ser:make-byte-reader-from bytes)))))
    (fuzz-assert (equalp bytes (fuzz-sabotage again))
                 "ser(deser(ser(obj))) ~A /= ser(obj) ~A"
                 (bl.crypto:bytes-to-hex again) (bl.crypto:bytes-to-hex bytes))
    (when consumed
      (fuzz-assert (equalp consumed (fuzz-sabotage bytes))
                   "decoded ~A but re-encodes as ~A"
                   (bl.crypto:bytes-to-hex consumed) (bl.crypto:bytes-to-hex bytes)))))

(defun consume-block-header (fdp)
  (bl.ser:make-block-header :version (consume-integral fdp :i32)
                            :prev-block (consume-uint256 fdp)
                            :merkle-root (consume-uint256 fdp)
                            :timestamp (consume-integral fdp :u32)
                            :bits (consume-integral fdp :u32)
                            :nonce (consume-integral fdp :u32)))

(defun consume-block (fdp)
  "A header and up to four ConsumeTransaction transactions."
  (bl.ser:make-bitcoin-block
   :header (consume-block-header fdp)
   :transactions (loop repeat (consume-integral-in-range fdp 0 4)
                       collect (consume-transaction fdp :max-num-in 3 :max-num-out 3))))

(defun consume-outpoint (fdp)
  (bl.ser:make-outpoint :hash (consume-uint256 fdp) :index (consume-integral fdp :u32)))

;;; --- targets ---------------------------------------------------------------

(define-fuzz-target out-point-deserialize
    (buffer :core "deserialize.cpp:151-155" :iterations 30000 :max-len 48
            :corpus (lambda (fdp) (%ser #'bl.ser:bb-write-outpoint (consume-outpoint fdp))))
  "COutPoint: a decoded outpoint re-encodes to the 36 bytes it was read from."
  (multiple-value-bind (op consumed) (deserialize-from-fuzzing-input buffer #'bl.ser:br-read-outpoint)
    (assert-nonempty-reserialization buffer (%ser #'bl.ser:bb-write-outpoint op))
    (assert-equal-after-serialize-deserialize op #'bl.ser:br-read-outpoint
                                              #'bl.ser:bb-write-outpoint consumed)))

(define-fuzz-target script-deserialize
    (buffer :core "deserialize.cpp:161-164" :iterations 30000 :max-len 300
            :corpus (lambda (fdp) (%ser #'bl.bytes:bb-write-var-bytes (consume-script fdp))))
  "CScript: a CompactSize-prefixed byte string."
  (multiple-value-bind (script consumed) (deserialize-from-fuzzing-input buffer #'bl.ser:br-read-var-bytes)
    (assert-nonempty-reserialization buffer (%ser #'bl.bytes:bb-write-var-bytes script))
    (assert-equal-after-serialize-deserialize script #'bl.ser:br-read-var-bytes
                                              #'bl.bytes:bb-write-var-bytes consumed)))

(define-fuzz-target tx-in-deserialize
    (buffer :core "deserialize.cpp:165-169" :iterations 30000 :max-len 200
            :corpus (lambda (fdp)
                      (%ser #'bl.ser:bb-write-tx-in
                            (bl.ser:make-tx-in :previous-output (consume-outpoint fdp)
                                               :script-sig (consume-script fdp)
                                               :sequence (consume-sequence fdp)))))
  "CTxIn: a decoded input round-trips, byte for byte."
  (multiple-value-bind (in consumed) (deserialize-from-fuzzing-input buffer #'bl.ser:br-read-tx-in)
    (assert-nonempty-reserialization buffer (%ser #'bl.ser:bb-write-tx-in in))
    (assert-equal-after-serialize-deserialize in #'bl.ser:br-read-tx-in
                                              #'bl.ser:bb-write-tx-in consumed)))

(define-fuzz-target blockheader-deserialize
    (buffer :core "deserialize.cpp:227-230" :iterations 30000 :max-len 100
            :corpus (lambda (fdp) (bl.ser:serialize-block-header (consume-block-header fdp))))
  "CBlockHeader: 80 bytes, and the decoded header writes them back."
  (multiple-value-bind (header consumed)
      (deserialize-from-fuzzing-input buffer #'bl.ser:br-read-block-header)
    (let ((bytes (bl.ser:serialize-block-header header)))
      (assert-nonempty-reserialization buffer bytes)
      (fuzz-assert (equalp consumed (fuzz-sabotage bytes)) "header re-encodes differently"))))

(define-fuzz-target block-deserialize
    (buffer :core "deserialize.cpp:211-214" :iterations 15000 :max-len 400
            :corpus (lambda (fdp) (bl.ser:serialize-witness-block (consume-block fdp))))
  "CBlock with TX_WITH_WITNESS. Core asserts only that it decodes or throws
ios_base::failure and that a decoded block serializes; a block is not a
canonical encoding in general (a witnessless transaction written with the
marker is refused, so it IS here) and the assertion below is the byte form."
  (multiple-value-bind (block consumed)
      (deserialize-from-fuzzing-input buffer #'bl.ser:br-read-bitcoin-block)
    (let ((bytes (bl.ser:serialize-witness-block block)))
      (assert-nonempty-reserialization buffer bytes)
      (fuzz-assert (equalp consumed (fuzz-sabotage bytes))
                   "block re-encodes to ~D bytes, decoded from ~D"
                   (length bytes) (length consumed)))))

(define-fuzz-target blockmerkleroot
    (buffer :core "deserialize.cpp:219-225" :iterations 15000 :max-len 400
            :corpus (lambda (fdp) (bl.ser:serialize-witness-block (consume-block fdp))))
  "BlockMerkleRoot over any decoded block, the mutation flag included: it must
answer, never signal, and the root of a block with one transaction is that
transaction's txid."
  (let* ((block (deserialize-from-fuzzing-input buffer #'bl.ser:br-read-bitcoin-block))
         (hashes (mapcar #'bl.ser:transaction-hash (bl.ser:bitcoin-block-transactions block))))
    (multiple-value-bind (root mutated) (bl.val:compute-merkle-root hashes)
      (declare (ignore mutated))
      (fuzz-assert (= 32 (length root)) "merkle root is not 32 bytes")
      (when (= 1 (length hashes))
        (fuzz-assert (equalp (fuzz-sabotage root) (first hashes))
                     "one-transaction root is not the txid")))))

(defun %compressed-coin-bytes (height coinbase value script)
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-compressed-coin bb height coinbase value script)
    (bl.ser:bb-finish bb)))

(defun %compressed-tx-out-bytes (value script)
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-compressed-tx-out bb value script)
    (bl.ser:bb-finish bb)))

(define-fuzz-target coins-deserialize
    (buffer :core "deserialize.cpp:239-242" :iterations 30000 :max-len 120
            :corpus (lambda (fdp)
                      (%compressed-coin-bytes (consume-integral-in-range fdp 0 #x7fffffff 32)
                                              (consume-bool fdp) (consume-money fdp)
                                              (consume-script fdp))))
  "Coin: VARINT(height*2+coinbase), a uint32, then TxOutCompression. Beyond
Core's decode-and-serialize, the coin a consensus-valid amount decodes to
survives deser(ser(coin)) unchanged. The BYTES need not: a raw script that
has a special form, and an oversized one read back as OP_RETURN, re-encode
shorter, and an amount code whose uint64 arithmetic wrapped is not
CompressAmount's image."
  (destructuring-bind (height coinbase value script)
      (deserialize-from-fuzzing-input buffer (lambda (br) (multiple-value-list
                                                           (bl.ser:br-read-compressed-coin br))))
    (let ((bytes (%compressed-coin-bytes height coinbase value script)))
      (assert-nonempty-reserialization buffer bytes)
      (when (bl.val:money-range-p value)
        (fuzz-assert (equalp (fuzz-sabotage (list height coinbase value script))
                             (multiple-value-list
                              (bl.ser:br-read-compressed-coin (bl.ser:make-byte-reader-from bytes))))
                     "coin ~S does not survive deser(ser(coin))" (list height coinbase value))))))

(define-fuzz-target txoutcompressor-deserialize
    (buffer :core "deserialize.cpp:340-344" :iterations 30000 :max-len 120
            :corpus (lambda (fdp) (%compressed-tx-out-bytes (consume-money fdp) (consume-script fdp))))
  "CTxOut through TxOutCompression: CompressAmount, then the script in one of
the six special forms or its length plus six. A consensus-valid output
survives deser(ser(out)); see coins-deserialize for why the bytes need not."
  (destructuring-bind (value script)
      (deserialize-from-fuzzing-input buffer (lambda (br) (multiple-value-list
                                                           (bl.ser:br-read-compressed-tx-out br))))
    (let ((bytes (%compressed-tx-out-bytes value script)))
      (assert-nonempty-reserialization buffer bytes)
      (when (bl.val:money-range-p value)
        (fuzz-assert (equalp (fuzz-sabotage (list value script))
                             (multiple-value-list
                              (bl.ser:br-read-compressed-tx-out (bl.ser:make-byte-reader-from bytes))))
                     "txout of ~D sat does not survive deser(ser(out))" value)))))

(define-fuzz-target inv-deserialize
    (buffer :core "deserialize.cpp:326-329" :iterations 20000 :max-len 48
            :corpus (lambda (fdp)
                      (%ser #'bl.ser:write-inv-vector
                            (bl.ser:make-inv-vector :type (consume-integral fdp :u32)
                                                    :hash (consume-uint256 fdp)))))
  "CInv: a type and a hash."
  (multiple-value-bind (inv consumed) (deserialize-from-fuzzing-input buffer #'bl.ser:read-inv-vector)
    (assert-nonempty-reserialization buffer (%ser #'bl.ser:write-inv-vector inv))
    (assert-equal-after-serialize-deserialize inv #'bl.ser:read-inv-vector
                                              #'bl.ser:write-inv-vector consumed)))

(define-fuzz-target messageheader-deserialize
    (buffer :core "deserialize.cpp:283-287" :iterations 30000 :max-len 40
            :corpus (lambda (fdp)
                      (subseq (bl.ser:serialize-message
                               (map 'string #'code-char (consume-random-length-byte-vector fdp 12))
                               (consume-random-length-byte-vector fdp 8))
                              0 24)))
  "CMessageHeader, then IsMessageTypeValid (protocol.cpp:26-43) on the type it
carries. The header keeps its type up to the first NUL, so it writes back the
24 bytes it was read from exactly when the rest of the type field is NUL
padding -- the half of IsMessageTypeValid about the field's shape."
  (multiple-value-bind (header consumed)
      (deserialize-from-fuzzing-input buffer #'bl.ser:read-message-header)
    (let* ((bytes (%ser #'bl.ser:write-message-header header))
           (field (subseq consumed 4 16))
           (padded (every #'zerop (subseq field (or (position 0 field) 12)))))
      (assert-nonempty-reserialization buffer bytes)
      (fuzz-assert (eq padded (equalp consumed (fuzz-sabotage bytes)))
                   "type field ~A: NUL-padded ~A, but re-encodes ~:[differently~;identically~]"
                   (bl.crypto:bytes-to-hex field) padded (equalp consumed bytes)))))

(define-fuzz-target bloomfilter-deserialize
    (buffer :core "deserialize.cpp:330-333" :iterations 20000 :max-len 120
            :corpus (lambda (fdp)
                      (bl.net:serialize-bloom-filter
                       (bl.net:make-bloom-filter (consume-integral-in-range fdp 1 40 32)
                                                 (max 1d-6 (min 0.999d0 (consume-probability fdp)))
                                                 (consume-integral fdp :u32)
                                                 (consume-integral-in-range fdp 0 3 8)))))
  "CBloomFilter (the filterload payload): decodes whole or is refused, and a
decoded filter serializes back to the bytes it was read from."
  (multiple-value-bind (filter consumed)
      (deserialize-from-fuzzing-input
       buffer (lambda (br)
                ;; PARSE-BLOOM-FILTER reads a whole payload; hand it the rest.
                (let ((f (bl.net:parse-bloom-filter
                          (subseq buffer (bl.ser:br-pos br)))))
                  (bl.ser:br-read-bytes br (length (bl.net:serialize-bloom-filter f)))
                  f)))
    (let ((bytes (bl.net:serialize-bloom-filter filter)))
      (assert-nonempty-reserialization buffer bytes)
      (fuzz-assert (equalp consumed (fuzz-sabotage bytes)) "filter re-encodes differently"))))

(define-fuzz-target merkle-block-deserialize
    (buffer :core "deserialize.cpp:146-150" :iterations 20000 :max-len 300
            :corpus (lambda (fdp)
                      (bl.net:serialize-merkle-block
                       (bl.ser:serialize-block-header (consume-block-header fdp))
                       (consume-integral-in-range fdp 0 64 32)
                       (loop repeat (consume-integral-in-range fdp 0 4) collect (consume-uint256 fdp))
                       (loop repeat (consume-integral-in-range fdp 0 24) collect (consume-bool fdp)))))
  "CMerkleBlock: a header, the transaction count and the partial merkle tree's
hashes and flag bits."
  (multiple-value-bind (fields consumed)
      (deserialize-from-fuzzing-input
       buffer (lambda (br)
                (let ((fields (multiple-value-list
                               (bl.net:parse-merkle-block (subseq buffer (bl.ser:br-pos br))))))
                  (bl.ser:br-read-bytes br (length (apply #'bl.net:serialize-merkle-block fields)))
                  fields)))
    (let ((bytes (apply #'bl.net:serialize-merkle-block fields)))
      (assert-nonempty-reserialization buffer bytes)
      ;; vBits is padded to whole bytes, so the byte form holds only up to the
      ;; padding: re-decoding what we wrote must give the same encoding.
      (fuzz-assert (equalp (fuzz-sabotage bytes)
                           (apply #'bl.net:serialize-merkle-block
                                  (multiple-value-list (bl.net:parse-merkle-block bytes))))
                   "merkle block does not survive a second round trip")
      (fuzz-assert (<= (length bytes) (length consumed))
                   "re-encoding grew from ~D to ~D bytes" (length consumed) (length bytes)))))

(define-fuzz-target block-header-and-short-txids-deserialize
    (buffer :core "deserialize.cpp:127-130" :iterations 15000 :max-len 400
            :corpus (lambda (fdp)
                      (%ser #'bl.ser:write-compact-block
                            (bl.ser:make-compact-block
                             :header (consume-block-header fdp)
                             :nonce (consume-integral fdp :u64)
                             :short-ids (loop repeat (consume-integral-in-range fdp 0 6)
                                              collect (consume-integral-in-range fdp 0 (1- (ash 1 48))))
                             :prefilled-txs
                             (let ((i -1))
                               (loop repeat (consume-integral-in-range fdp 0 2)
                                     collect (bl.ser:make-prefilled-tx
                                              :index (incf i (1+ (consume-integral-in-range fdp 0 3)))
                                              :transaction (consume-transaction fdp :max-num-in 2 :max-num-out 2))))))))
  "CBlockHeaderAndShortTxIDs (cmpctblock), prefilled transactions with their
differentially encoded indexes included."
  (multiple-value-bind (cb consumed) (deserialize-from-fuzzing-input buffer #'bl.ser:read-compact-block)
    (let ((bytes (%ser #'bl.ser:write-compact-block cb)))
      (assert-nonempty-reserialization buffer bytes)
      (fuzz-assert (equalp consumed (fuzz-sabotage bytes)) "compact block re-encodes differently"))))

(define-fuzz-target blocktransactionsrequest-deserialize
    (buffer :core "deserialize.cpp:349-352" :iterations 20000 :max-len 120
            :corpus (lambda (fdp)
                      (subseq (bl.ser:make-getblocktxn-message
                               (consume-uint256 fdp)
                               (let ((i -1))
                                 (loop repeat (consume-integral-in-range fdp 0 8)
                                       collect (incf i (1+ (consume-integral-in-range fdp 0 300))))))
                              24)))
  "BlockTransactionsRequest (getblocktxn): the indexes are DifferenceFormatter
encoded into std::vector<uint16_t>, so Core refuses -- `differential value
out of range' (blockencodings.h:25-33) -- any absolute index above 65535."
  (multiple-value-bind (request consumed)
      (deserialize-from-fuzzing-input
       buffer (lambda (br)
                (let ((r (bl.ser:parse-getblocktxn-payload (subseq buffer (bl.ser:br-pos br)))))
                  (bl.ser:br-read-bytes br (- (length (bl.ser:make-getblocktxn-message
                                                       (bl.ser:block-txn-request-block-hash r)
                                                       (bl.ser:block-txn-request-indexes r)))
                                              24))
                  r)))
    (let ((bytes (subseq (bl.ser:make-getblocktxn-message
                          (bl.ser:block-txn-request-block-hash request)
                          (bl.ser:block-txn-request-indexes request))
                         24)))
      (assert-nonempty-reserialization buffer bytes)
      (fuzz-assert (every (lambda (i) (<= 0 i #xffff))
                          (fuzz-sabotage (bl.ser:block-txn-request-indexes request)))
                   "an index outside uint16 was accepted: ~S"
                   (bl.ser:block-txn-request-indexes request))
      (fuzz-assert (equalp consumed bytes) "getblocktxn re-encodes differently"))))

(define-fuzz-target blocktransactions-deserialize
    (buffer :core "deserialize.cpp:345-348" :iterations 15000 :max-len 300
            :corpus (lambda (fdp)
                      (subseq (bl.ser:make-blocktxn-message
                               (consume-uint256 fdp)
                               (loop repeat (consume-integral-in-range fdp 0 3)
                                     collect (consume-transaction fdp :max-num-in 2 :max-num-out 2))
                               :witness t)
                              24)))
  "BlockTransactions (blocktxn): a block hash and transactions WITH witness."
  (multiple-value-bind (response consumed)
      (deserialize-from-fuzzing-input
       buffer (lambda (br)
                (let* ((r (bl.ser:parse-blocktxn-payload (subseq buffer (bl.ser:br-pos br))))
                       (n (- (length (bl.ser:make-blocktxn-message
                                      (bl.ser:block-txn-response-block-hash r)
                                      (bl.ser:block-txn-response-transactions r) :witness t))
                             24)))
                  (bl.ser:br-read-bytes br n)
                  r)))
    (let ((bytes (subseq (bl.ser:make-blocktxn-message
                          (bl.ser:block-txn-response-block-hash response)
                          (bl.ser:block-txn-response-transactions response) :witness t)
                         24)))
      (assert-nonempty-reserialization buffer bytes)
      (fuzz-assert (equalp consumed (fuzz-sabotage bytes)) "blocktxn re-encodes differently"))))

(define-fuzz-target partially-signed-transaction-deserialize
    (buffer :core "deserialize.cpp:185-188" :iterations 15000 :max-len 400
            :corpus (lambda (fdp)
                      (let ((psbt (bl.ser:make-empty-psbt
                                   (consume-transaction fdp :max-num-in 3 :max-num-out 3))))
                        (bl.ser:serialize-psbt psbt))))
  "PartiallySignedTransaction (with psbt_input_deserialize and
psbt_output_deserialize, :193-200, which are its maps): decodes or is refused,
and a decoded PSBT serializes."
  (let ((psbt (fuzz-deserialize (bl.ser:parse-psbt buffer))))
    (assert-nonempty-reserialization buffer (bl.ser:serialize-psbt psbt))))

(defun %v2-drops-embedded-ipv6-p (ip)
  "True for the IPv6 forms BIP155 refuses to carry embedded -- TORv2
(fd87:d87e:eb43::/48) and NET_INTERNAL (fd6b:88c0:8724::/48) -- which Core
unserializes as not-valid/internal (netaddress.h:446-462) and our V2 reader
drops."
  (let ((torv2 '(#xfd #x87 #xd8 #x7e #xeb #x43))
        (internal '(#xfd #x6b #x88 #xc0 #x87 #x24)))
    (flet ((prefix-p (p) (every #'= p ip)))
      (or (prefix-p torv2) (prefix-p internal)))))

(defun %addr-bytes-v1 (addr time)
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:write-net-addr bb addr :with-timestamp t :timestamp time)
    (bl.ser:bb-finish bb)))

(defun %addr-bytes-v2 (addr network-id time)
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:write-net-addr-v2 bb addr network-id time)
    (bl.ser:bb-finish bb)))

(define-fuzz-target address-deserialize
    (buffer :core "deserialize.cpp:289-315" :iterations 30000 :max-len 80
            :corpus (lambda (fdp)
                      (let* ((v1 (consume-bool fdp))
                             (time (consume-integral fdp :u32))
                             (addr (bl.ser:make-net-addr :services (consume-integral fdp :u64)
                                                         :ip (consume-uint128 fdp)
                                                         :port (consume-integral fdp :u16))))
                        (concatenate '(vector (unsigned-byte 8))
                                     (vector (if v1 1 0))
                                     (if v1
                                         (%addr-bytes-v1 addr time)
                                         (%addr-bytes-v2 addr (bl.ser:network-bip155-id
                                                               (bl.ser:net-addr-network addr))
                                                         time))))))
  "CAddress in V1_NETWORK (addr) or V2_NETWORK (addrv2, BIP155) form, the
first byte choosing the encoding (Core ConsumeDeserializationParams). A
decoded address round-trips in V2, and in V1 when V1 can carry it; one read
from V1 is always V1-compatible."
  (let* ((v1 (and (plusp (length buffer)) (oddp (aref buffer 0))))
         (br (bl.ser:make-byte-reader-from (if (plusp (length buffer)) (subseq buffer 1) buffer))))
    (multiple-value-bind (addr time network-id)
        (fuzz-deserialize (if v1
                              (bl.ser:read-net-addr br :with-timestamp t)
                              (bl.ser:read-net-addr-v2 br)))
      (when addr
        (let ((network-id (or network-id (bl.ser:network-bip155-id (bl.ser:net-addr-network addr)))))
          (when v1
            (fuzz-assert (bl.ser:v1-compatible-network-p (bl.ser:net-addr-network addr))
                         "an address read from V1 is not V1-compatible"))
          (when (bl.ser:v1-compatible-network-p (bl.ser:net-addr-network addr))
            (let ((bytes (%addr-bytes-v1 addr time)))
              (fuzz-assert (equalp (fuzz-sabotage bytes)
                                   (%addr-bytes-v1 (bl.ser:read-net-addr
                                                    (bl.ser:make-byte-reader-from bytes)
                                                    :with-timestamp t)
                                                   time))
                           "V1 address does not round-trip")))
          (let ((bytes (%addr-bytes-v2 addr network-id time)))
            (multiple-value-bind (again t2 n2)
                (bl.ser:read-net-addr-v2 (bl.ser:make-byte-reader-from bytes))
              (if again
                  (fuzz-assert (equalp (fuzz-sabotage bytes) (%addr-bytes-v2 again n2 t2))
                               "V2 address does not round-trip")
                  (fuzz-assert (and v1 (%v2-drops-embedded-ipv6-p (bl.ser:net-addr-ip addr)))
                               "V2 re-read dropped ~A" (bl.crypto:bytes-to-hex bytes))))))))))

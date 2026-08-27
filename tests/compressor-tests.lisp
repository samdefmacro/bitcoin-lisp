(in-package #:bitcoin-lisp.tests)

;;;; TxOutCompression + hash_serialized_3 tests
;;;;
;;;; P0: ports Bitcoin Core's src/test/compress_tests.cpp (amount pair
;;;; table + round-trip multiples, the script special forms including
;;;; the not-on-curve negative case) plus the Core VARINT example table
;;;; from serialize.h:363-384 and the per-output Coin record
;;;; (coins.h:63-79).
;;;;
;;;; P1: hash_serialized_3 vectors where the expected preimage is
;;;; assembled BY HAND (independent byte layout, kernel/coinstats.cpp
;;;; TxOutSer) and double-SHA256'd, then compared against
;;;; compute-utxo-set-hash — including the vout>=256 ordering trap and
;;;; the (height<<1|coinbase) packed-code-word trap.

(def-suite :compressor-tests
  :description "TxOutCompression codec (Core compressor.{h,cpp}) + hash_serialized_3"
  :in :bitcoin-lisp-tests)

(in-suite :compressor-tests)

;;;; Helpers

(defun %cmp-byte-vec (list)
  (make-array (length list) :element-type '(unsigned-byte 8)
                            :initial-contents list))

(defun %cmp-bytes (&rest contents)
  "Byte-vector literal helper."
  (%cmp-byte-vec contents))

(defun %cmp-core-varint-bytes (n)
  "Encode N as a Core VARINT, returning the raw bytes."
  (let ((buf (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-core-varint buf n)
    (bl.ser:bb-finish buf)))

(defun %cmp-read-core-varint (bytes)
  "Decode a Core VARINT. Returns (values value bytes-consumed)."
  (let ((br (bl.ser:make-byte-reader-from bytes)))
    (values (bl.ser:br-read-core-varint br)
            (bl.ser:br-pos br))))

(defun %cmp-fixed-privkey ()
  "Deterministic valid secp256k1 secret key (bytes 1..32)."
  (%cmp-byte-vec (loop for i from 1 to 32 collect i)))

(defun %cmp-p2pk-script (pubkey)
  "P2PK script: PUSH(len) || pubkey || OP_CHECKSIG. (P2PKH/P2SH scripts
below reuse make-p2pkh-script / make-p2sh-script from sigops-tests.)"
  (concatenate '(simple-array (unsigned-byte 8) (*))
               (%cmp-bytes (length pubkey)) pubkey (%cmp-bytes #xac)))

(defun %cmp-script-roundtrip (script)
  "Serialize SCRIPT through the compressed-script stream codec and read
it back. Returns (values decoded-script encoded-bytes)."
  (let ((buf (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-compressed-script buf script)
    (let* ((encoded (bl.ser:bb-finish buf))
           (br (bl.ser:make-byte-reader-from encoded)))
      (values (bl.ser:br-read-compressed-script br)
              encoded))))

(defun %cmp-x-not-on-curve ()
  "A deterministic 32-byte x coordinate that is NOT on the secp256k1
curve (0x02||x fails point parsing). Mirrors compress_tests.cpp
compress_p2pk_scripts_not_on_curve's rejection-sampling loop."
  (loop for i from 0 below 256
        for x = (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element i)
        for candidate = (concatenate '(simple-array (unsigned-byte 8) (*))
                                     (%cmp-bytes #x02) x)
        unless (bl.crypto:public-key-valid-p candidate)
          return x
        finally (error "no off-curve x found (impossible)")))

;;;; Core VARINT (serialize.h:363-384)

(test core-varint-canonical-examples
  "The canonical VARINT example table from serialize.h:378-383."
  (let ((cases `((0          . ,(%cmp-bytes #x00))
                 (1          . ,(%cmp-bytes #x01))
                 (127        . ,(%cmp-bytes #x7F))
                 (128        . ,(%cmp-bytes #x80 #x00))
                 (255        . ,(%cmp-bytes #x80 #x7F))
                 (256        . ,(%cmp-bytes #x81 #x00))
                 (16383      . ,(%cmp-bytes #xFE #x7F))
                 (16384      . ,(%cmp-bytes #xFF #x00))
                 (16511      . ,(%cmp-bytes #xFF #x7F))
                 (65535      . ,(%cmp-bytes #x82 #xFE #x7F))
                 (,(expt 2 32) . ,(%cmp-bytes #x8E #xFE #xFE #xFF #x00)))))
    (dolist (case cases)
      (destructuring-bind (value . bytes) case
        (is (equalp bytes (%cmp-core-varint-bytes value))
            "encode ~D" value)
        (multiple-value-bind (decoded consumed) (%cmp-read-core-varint bytes)
          (is (= value decoded) "decode ~D" value)
          (is (= (length bytes) consumed)))))))

(test core-varint-round-trip
  "Round-trip across the byte-length boundaries up to 2^64-1."
  (dolist (v (list 0 1 2 126 127 128 129 254 255 256 16382 16383 16384
                   16511 16512 65535 65536 2113663 2113664 270549119
                   270549120 4294967295 (expt 2 32) (1- (expt 2 64))))
    (multiple-value-bind (decoded consumed)
        (%cmp-read-core-varint (%cmp-core-varint-bytes v))
      (is (= v decoded))
      (is (= consumed (length (%cmp-core-varint-bytes v)))))))

(test core-varint-overflow-rejected
  "A VARINT exceeding 64 bits must error (Core: \"ReadVarInt(): size too
large\", serialize.h:442-462)."
  (signals error
    (%cmp-read-core-varint
     (make-array 11 :element-type '(unsigned-byte 8) :initial-element #xFF))))

;;;; Amount compression (compress_tests.cpp:41-64)

(test compress-amounts-pair-table
  "compress_tests.cpp:43-48 TestPair cases (CENT=1e6, COIN=1e8)."
  (let ((cent 1000000)
        (coin 100000000))
    (dolist (case `((0 . #x0)
                    (1 . #x1)
                    (,cent . #x7)
                    (,coin . #x9)
                    (,(* 50 coin) . #x32)
                    (,(* 21000000 coin) . #x1406f40)))
      (destructuring-bind (dec . enc) case
        (is (= enc (bl.ser:compress-amount dec)))
        (is (= dec (bl.ser:decompress-amount enc)))))))

(test compress-amounts-round-trip-multiples
  "compress_tests.cpp:50-63: encode round-trips for the unit/CENT/COIN/
50-COIN multiple ranges + decode round-trips for all i < 100000.
Failures are counted, not is'd per-iteration (540k+ iterations)."
  (let ((cent 1000000)
        (coin 100000000)
        (bad 0))
    (flet ((enc-ok (v)
             (unless (= v (bl.ser:decompress-amount
                           (bl.ser:compress-amount v)))
               (incf bad)))
           (dec-ok (v)
             (unless (= v (bl.ser:compress-amount
                           (bl.ser:decompress-amount v)))
               (incf bad))))
      (loop for i from 1 to 100000 do (enc-ok i))              ; NUM_MULTIPLES_UNIT
      (loop for i from 1 to 10000 do (enc-ok (* i cent)))      ; NUM_MULTIPLES_CENT
      (loop for i from 1 to 10000 do (enc-ok (* i coin)))      ; NUM_MULTIPLES_1BTC
      (loop for i from 1 to 420000 do (enc-ok (* i 50 coin)))  ; NUM_MULTIPLES_50BTC
      (loop for i from 0 below 100000 do (dec-ok i)))
    (is (= 0 bad))))

;;;; Script compression (compress_tests.cpp:66-165)

(test compress-script-p2pkh
  "P2PKH compresses to 0x00 + 20-byte key hash and round-trips."
  (let* ((pubkey (bl.crypto:derive-public-key (%cmp-fixed-privkey)))
         (hash (bl.crypto:hash160 pubkey))
         (script (make-p2pkh-script hash))
         (out (bl.ser:compress-script script)))
    (is (= 25 (length script)))
    (is (= 21 (length out)))
    (is (= #x00 (aref out 0)))
    (is (equalp hash (subseq out 1)))
    ;; direct decompress + stream round-trip
    (is (equalp script (bl.ser:decompress-script
                        #x00 (subseq out 1))))
    (multiple-value-bind (decoded encoded) (%cmp-script-roundtrip script)
      (is (equalp out encoded))
      (is (equalp script decoded)))))

(test compress-script-p2sh
  "P2SH compresses to 0x01 + 20-byte script hash and round-trips."
  (let* ((redeem (%cmp-bytes #x51))    ; OP_1
         (hash (bl.crypto:hash160 redeem))
         (script (make-p2sh-script hash))
         (out (bl.ser:compress-script script)))
    (is (= 23 (length script)))
    (is (= 21 (length out)))
    (is (= #x01 (aref out 0)))
    (is (equalp hash (subseq out 1)))
    (is (equalp script (bl.ser:decompress-script
                        #x01 (subseq out 1))))
    (multiple-value-bind (decoded encoded) (%cmp-script-roundtrip script)
      (is (equalp out encoded))
      (is (equalp script decoded)))))

(test compress-script-p2pk-compressed-key
  "P2PK with a compressed key: id byte = the key's own 0x02/0x03 prefix,
payload = the 32-byte x coordinate (compress_tests.cpp:102-117)."
  (let* ((pubkey (bl.crypto:derive-public-key (%cmp-fixed-privkey)))
         (script (%cmp-p2pk-script pubkey))
         (out (bl.ser:compress-script script)))
    (is (= 35 (length script)))
    (is (= 33 (length out)))
    (is (= (aref pubkey 0) (aref out 0)))
    (is (equalp (subseq pubkey 1 33) (subseq out 1)))
    (is (equalp script (bl.ser:decompress-script
                        (aref out 0) (subseq out 1))))
    (multiple-value-bind (decoded encoded) (%cmp-script-roundtrip script)
      (is (equalp out encoded))
      (is (equalp script decoded)))))

(test compress-script-p2pk-uncompressed-key
  "P2PK with an uncompressed key: id = 0x04 | y-parity, payload = x;
decompression must recover the FULL 65-byte key via secp256k1
(compress_tests.cpp:119-133; compressor.cpp:122-135)."
  (let* ((pubkey (bl.crypto:derive-public-key
                  (%cmp-fixed-privkey) :compressed nil))
         (script (%cmp-p2pk-script pubkey))
         (out (bl.ser:compress-script script)))
    (is (= 67 (length script)))
    (is (= 33 (length out)))
    (is (= (logior #x04 (logand (aref pubkey 64) #x01)) (aref out 0)))
    (is (equalp (subseq pubkey 1 33) (subseq out 1)))
    ;; Point recovery: the decompressed script must be byte-identical,
    ;; i.e. the y coordinate was correctly recomputed.
    (is (equalp script (bl.ser:decompress-script
                        (aref out 0) (subseq out 1))))
    (multiple-value-bind (decoded encoded) (%cmp-script-roundtrip script)
      (is (equalp out encoded))
      (is (equalp script decoded)))))

(test compress-script-p2pk-not-on-curve
  "An uncompressed P2PK whose x is not on the curve can be neither
compressed nor decompressed (compress_tests.cpp:135-165)."
  (let* ((x (%cmp-x-not-on-curve))
         (pubkey-raw (concatenate '(simple-array (unsigned-byte 8) (*))
                                  (%cmp-bytes #x04) x
                                  (make-array 32 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)))
         (script (%cmp-p2pk-script pubkey-raw)))
    (is (= 67 (length script)))
    (is (null (bl.ser:compress-script script)))
    (dolist (id '(#x04 #x05))
      (is (null (bl.ser:decompress-script id x))))))

(test compress-script-raw-fallback
  "A non-special script serializes as VARINT(size + 6) + raw bytes."
  (let ((script (%cmp-bytes #x6a #x04 #xde #xad #xbe #xef))) ; OP_RETURN push
    (is (null (bl.ser:compress-script script)))
    (multiple-value-bind (decoded encoded) (%cmp-script-roundtrip script)
      ;; 6 + 6 = 12 -> single VARINT byte 0x0C, then the script.
      (is (= (+ 1 (length script)) (length encoded)))
      (is (= #x0C (aref encoded 0)))
      (is (equalp script (subseq encoded 1)))
      (is (equalp script decoded)))))

(test compress-script-oversize-becomes-op-return
  "A raw script above MAX_SCRIPT_SIZE decodes as a one-byte OP_RETURN
and the payload is skipped (compressor.h:87-90)."
  (let ((size 10001)
        (buf (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-core-varint buf (+ size 6))
    (bl.ser:bb-write-bytes
     buf (make-array size :element-type '(unsigned-byte 8) :initial-element #x55))
    (let* ((bytes (bl.ser:bb-finish buf))
           (br (bl.ser:make-byte-reader-from bytes))
           (script (bl.ser:br-read-compressed-script br)))
      (is (equalp (%cmp-bytes #x6a) script))
      (is (bl.ser:br-eof-p br)))))

;;;; Compressed TxOut + Coin record (compressor.h:112-116; coins.h:63-79)

(test compressed-coin-record-known-bytes
  "Hand-computed Coin record: height 100 coinbase -> code 201 ->
VARINT [80 49]; 50 COIN -> compressed 0x32 -> VARINT [32]; P2PKH(0xCC*20)
-> [00 CC*20]."
  (let* ((script (make-p2pkh-script
                  (make-array 20 :element-type '(unsigned-byte 8)
                                 :initial-element #xCC)))
         (expected (concatenate '(simple-array (unsigned-byte 8) (*))
                                (%cmp-bytes #x80 #x49 #x32 #x00)
                                (make-array 20 :element-type '(unsigned-byte 8)
                                               :initial-element #xCC)))
         (buf (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-compressed-coin
     buf 100 t 5000000000 script)
    (is (equalp expected (bl.ser:bb-finish buf)))))

(test compressed-coin-record-zero-fields
  "height 0, non-coinbase, value 0, raw script [51]: [00 00 07 51]."
  (let ((buf (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-compressed-coin
     buf 0 nil 0 (%cmp-bytes #x51))
    (is (equalp (%cmp-bytes #x00 #x00 #x07 #x51)
                (bl.ser:bb-finish buf)))))

(test compressed-coin-record-round-trip
  "serialize -> parse round-trips height/coinbase/value/script."
  (let ((pubkey (bl.crypto:derive-public-key (%cmp-fixed-privkey))))
    (dolist (case (list (list 0 nil 0 (%cmp-bytes #x51))
                        (list 1 t 5000000000
                              (make-p2pkh-script
                               (bl.crypto:hash160 pubkey)))
                        (list 100000 nil 546 (%cmp-p2pk-script pubkey))
                        (list 918212 nil 123456789
                              (%cmp-bytes #x6a #x02 #xab #xcd))
                        ;; height 2^30 exercises multi-byte VARINT codes
                        (list (expt 2 30) t 2100000000000000
                              (make-p2sh-script
                               (bl.crypto:hash160 (%cmp-bytes #x51))))))
      (destructuring-bind (height coinbase value script) case
        (let ((buf (bl.ser:make-byte-buf)))
          (bl.ser:bb-write-compressed-coin
           buf height coinbase value script)
          (let ((br (bl.ser:make-byte-reader-from
                     (bl.ser:bb-finish buf))))
            (multiple-value-bind (h cb v s)
                (bl.ser:br-read-compressed-coin br)
              (is (= height h))
              (is (eq (and coinbase t) (and cb t)))
              (is (= value v))
              (is (equalp script s))
              (is (bl.ser:br-eof-p br)))))))))

;;;; hash_serialized_3 (kernel/coinstats.cpp:47-52, 88-146)
;;;;
;;;; The expected preimages below are assembled by hand with explicit
;;;; byte loops — independent of coin-muhash-element and the production
;;;; serializers — then double-SHA256'd with the crypto layer.

(defun %h3-coin-preimage (txid vout height coinbase value script)
  "TxOutSer bytes for one coin: txid || vout LE32 ||
(height<<1|coinbase) LE32 || value LE64 || compactsize(len) || script.
Scripts here are all < 253 bytes, so compactsize is a single byte."
  (assert (< (length script) 253))
  (let ((out '()))
    (loop for b across txid do (push b out))
    (loop for k below 4 do (push (ldb (byte 8 (* 8 k)) vout) out))
    (let ((code (logior (ash height 1) (if coinbase 1 0))))
      (loop for k below 4 do (push (ldb (byte 8 (* 8 k)) code) out)))
    (loop for k below 8 do (push (ldb (byte 8 (* 8 k)) value) out))
    (push (length script) out)
    (loop for b across script do (push b out))
    (%cmp-byte-vec (nreverse out))))

(defun %h3-expected-hash (coins)
  "Double-SHA256 over hand-assembled preimages. COINS is a list of
(txid vout height coinbase value script), already in Core order
(txid-lex groups, numerically ascending vout within a group)."
  (bl.crypto:hash256
   (apply #'concatenate '(simple-array (unsigned-byte 8) (*))
          (mapcar (lambda (c) (apply #'%h3-coin-preimage c)) coins))))

(test hash-serialized-3-single-coin
  "Single-coin vector against a hand-assembled preimage."
  (let ((txid (%cmp-byte-vec (loop for i below 32 collect i)))
        (script (%cmp-bytes #x51 #x52))
        (set (bl.store:make-utxo-set)))
    (bl.store:add-utxo set txid 5 123456789 script 1000)
    (is (equalp (%h3-expected-hash
                 (list (list txid 5 1000 nil 123456789 script)))
                (bl.store:compute-utxo-set-hash set)))))

(test hash-serialized-3-vout-ordering-trap
  "vouts 1, 256, 300 on ONE txid must hash in NUMERIC order (Core's
std::map<uint32_t, Coin>, coinstats.cpp:118-141). Our LE-u32 key bytes
order them 256 < 1 < 300, so an unsorted implementation diverges."
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-element #xAB))
        (script (%cmp-bytes #x51))
        (set (bl.store:make-utxo-set)))
    ;; scrambled insertion order
    (bl.store:add-utxo set txid 300 333 script 7)
    (bl.store:add-utxo set txid 1 111 script 7)
    (bl.store:add-utxo set txid 256 222 script 7)
    (let ((numeric (%h3-expected-hash
                    (list (list txid 1 7 nil 111 script)
                          (list txid 256 7 nil 222 script)
                          (list txid 300 7 nil 333 script))))
          (le-lex (%h3-expected-hash
                   (list (list txid 256 7 nil 222 script)
                         (list txid 1 7 nil 111 script)
                         (list txid 300 7 nil 333 script)))))
      ;; the trap is real: the two orders produce different digests
      (is (not (equalp numeric le-lex)))
      (is (equalp numeric (bl.store:compute-utxo-set-hash set))))))

(test hash-serialized-3-coinbase-code-word
  "Coinbase + non-coinbase mix across two txids: the u32 code word must
pack (height<<1)|coinbase, and groups must follow txid-lex order."
  (let ((txid-a (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element #x01))
        (txid-b (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element #x02))
        (script-a (%cmp-bytes #x51))
        (script-b (%cmp-bytes #x52 #x53))
        (set (bl.store:make-utxo-set)))
    ;; insert b's coin first; group order must still be a then b
    (bl.store:add-utxo set txid-b 0 999 script-b 200)
    (bl.store:add-utxo set txid-a 0 5000000000 script-a 100
                                   :coinbase t)
    (is (equalp (%h3-expected-hash
                 (list (list txid-a 0 100 t 5000000000 script-a)
                       (list txid-b 0 200 nil 999 script-b)))
                (bl.store:compute-utxo-set-hash set)))))

(test hash-serialized-3-leveldb-cache-parity
  "The LevelDB-backed coins-view-cache path must produce the identical
digest for the vout-ordering-trap coins (its iterator emits LE-u32 key
order, so the per-txid sort must fix it there too)."
  (let ((path (namestring
               (merge-pathnames (format nil "btc-cmp-h3-test-~D-~D/"
                                        (get-universal-time) (random 100000))
                                (uiop:temporary-directory))))
        (txid (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-element #xAB))
        (script (%cmp-bytes #x51)))
    (unwind-protect
         (bl.store:with-coins-view-db (base path)
           (let ((cache (bl.store:make-coins-view-cache base))
                 (expected (%h3-expected-hash
                            (list (list txid 1 7 nil 111 script)
                                  (list txid 256 7 nil 222 script)
                                  (list txid 300 7 nil 333 script)))))
             (bl.store:add-utxo cache txid 300 333 script 7)
             (bl.store:add-utxo cache txid 1 111 script 7)
             (bl.store:add-utxo cache txid 256 222 script 7)
             (is (equalp expected
                         (bl.store:compute-utxo-set-hash cache)))))
      (ignore-errors (bl.store:leveldb-destroy-db path))
      (ignore-errors
        (uiop:delete-directory-tree (pathname path)
                                    :validate t :if-does-not-exist :ignore)))))

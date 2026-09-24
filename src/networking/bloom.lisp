(in-package #:bitcoin-lisp.networking)

;;;; BIP37 bloom filters (Bitcoin Core common/bloom.{h,cpp}, hash.cpp
;;;; MurmurHash3).
;;;
;;; A light client loads a filter with `filterload', grows it with `filteradd'
;;; and drops it with `filterclear'. While one is loaded, the transactions
;;; announced to that peer, the answer to its `mempool' request and the
;;; `merkleblock' it gets for a MSG_FILTERED_BLOCK getdata are the ones the
;;; filter matches (IsRelevantAndUpdate), and a match may insert the matched
;;; outpoint into the filter (the BLOOM_UPDATE_* flags) so the spend of that
;;; output matches too. Only a node started with -peerbloomfilters (or a peer
;;; holding the bloomfilter permission) offers NODE_BLOOM and answers these.
;;;
;;; The serialized filter and the murmur hash are a public byte contract:
;;; tests/networking/bloom-tests.lisp checks them against Core's
;;; test/bloom_tests.cpp vectors.

(defconstant +max-bloom-filter-size+ 36000
  "Core MAX_BLOOM_FILTER_SIZE, bytes (bloom.h:17).")
(defconstant +max-bloom-hash-funcs+ 50 "Core MAX_HASH_FUNCS (bloom.h:18).")

(defconstant +max-script-element-size+ 520
  "Core MAX_SCRIPT_ELEMENT_SIZE (script/script.h): the largest element a
filteradd may carry.")

(defconstant +bloom-update-none+ 0 "Core BLOOM_UPDATE_NONE.")
(defconstant +bloom-update-all+ 1 "Core BLOOM_UPDATE_ALL.")
(defconstant +bloom-update-p2pubkey-only+ 2 "Core BLOOM_UPDATE_P2PUBKEY_ONLY.")
(defconstant +bloom-update-mask+ 3 "Core BLOOM_UPDATE_MASK.")

(defstruct (bloom-filter (:constructor %make-bloom-filter))
  "Core CBloomFilter: the bit array, the number of hash functions, the tweak
that seeds them and the BLOOM_UPDATE_* flags."
  (data (make-array 0 :element-type '(unsigned-byte 8))
   :type (simple-array (unsigned-byte 8) (*)))
  (hash-funcs 0 :type (unsigned-byte 32))
  (tweak 0 :type (unsigned-byte 32))
  (flags 0 :type (unsigned-byte 8)))

(defun make-bloom-filter (elements fp-rate tweak flags)
  "Core's CBloomFilter(nElements, nFPRate, nTweak, nFlags) (bloom.cpp:25-40):
the size ideal for ELEMENTS at FP-RATE, capped at the protocol limits. The
arithmetic is Core's, double for double: the bit count is truncated before it
is capped and divided by 8, and the hash-function count divides the bit count
by ELEMENTS in INTEGER arithmetic before multiplying by ln 2."
  (let* ((ln2squared 0.4804530139182014246671025263266649717305529515945455d0)
         (ln2 0.6931471805599453094172321214581765680755001343602552d0)
         (bits (min (ldb (byte 32 0)
                         (truncate (* (* (/ -1d0 ln2squared) elements)
                                      (log (coerce fp-rate 'double-float)))))
                    (* +max-bloom-filter-size+ 8)))
         (size (floor bits 8))
         (funcs (min (truncate (* (floor (* size 8) elements) ln2))
                     +max-bloom-hash-funcs+)))
    (%make-bloom-filter
     :data (make-array size :element-type '(unsigned-byte 8) :initial-element 0)
     :hash-funcs funcs :tweak tweak :flags flags)))

(defun murmur-hash3 (seed data)
  "Core MurmurHash3 (hash.cpp:13-73), the x86_32 variant, over the octet
vector DATA with SEED."
  (declare (type (unsigned-byte 32) seed))
  (let* ((h1 seed)
         (c1 #xcc9e2d51)
         (c2 #x1b873593)
         (len (length data))
         (nblocks (floor len 4)))
    (declare (type (unsigned-byte 32) h1))
    (flet ((rotl (x r) (ldb (byte 32 0) (logior (ash x r) (ash x (- r 32)))))
           (mul (a b) (ldb (byte 32 0) (* a b))))
      (dotimes (i nblocks)
        (let* ((o (* i 4))
               (k1 (logior (aref data o) (ash (aref data (+ o 1)) 8)
                           (ash (aref data (+ o 2)) 16) (ash (aref data (+ o 3)) 24))))
          (setf k1 (mul (rotl (mul k1 c1) 15) c2)
                h1 (logxor h1 k1)
                h1 (ldb (byte 32 0) (+ (mul (rotl h1 13) 5) #xe6546b64)))))
      (let ((tail (* nblocks 4)) (k1 0))
        (case (logand len 3)
          (3 (setf k1 (logxor k1 (ash (aref data (+ tail 2)) 16)))
           (setf k1 (logxor k1 (ash (aref data (+ tail 1)) 8)))
           (setf k1 (logxor k1 (aref data tail))))
          (2 (setf k1 (logxor k1 (ash (aref data (+ tail 1)) 8)))
           (setf k1 (logxor k1 (aref data tail))))
          (1 (setf k1 (logxor k1 (aref data tail)))))
        (when (plusp (logand len 3))
          (setf k1 (mul (rotl (mul k1 c1) 15) c2)
                h1 (logxor h1 k1))))
      ;; Finalization: fmix32.
      (setf h1 (logxor h1 len)
            h1 (logxor h1 (ash h1 -16))
            h1 (mul h1 #x85ebca6b)
            h1 (logxor h1 (ash h1 -13))
            h1 (mul h1 #xc2b2ae35)
            h1 (logxor h1 (ash h1 -16)))
      h1)))

(defun %bloom-bit (filter n key)
  "Core CBloomFilter::Hash (bloom.cpp:42-46): the bit hash function N sets."
  (mod (murmur-hash3 (ldb (byte 32 0) (+ (* n #xFBA4C795) (bloom-filter-tweak filter)))
                     key)
       (* 8 (length (bloom-filter-data filter)))))

(defun bloom-insert (filter key)
  "Core CBloomFilter::insert (bloom.cpp:48-58). An empty filter stays empty:
a zero-size filter is the match-all filter, and hashing into it would divide
by zero (CVE-2013-5700)."
  (let ((data (bloom-filter-data filter)))
    (when (plusp (length data))
      (dotimes (i (bloom-filter-hash-funcs filter))
        (let ((bit (%bloom-bit filter i key)))
          (setf (aref data (ash bit -3))
                (logior (aref data (ash bit -3)) (ash 1 (logand bit 7))))))))
  filter)

(defun bloom-contains-p (filter key)
  "Core CBloomFilter::contains (bloom.cpp:67-79); an empty filter matches all."
  (let ((data (bloom-filter-data filter)))
    (or (zerop (length data))
        (loop for i below (bloom-filter-hash-funcs filter)
              for bit = (%bloom-bit filter i key)
              always (logbitp (logand bit 7) (aref data (ash bit -3)))))))

(defun outpoint-bytes (txid index)
  "A COutPoint as the filter hashes it: the 32-byte txid in internal order and
the output index as a little-endian uint32."
  (let ((out (make-array 36 :element-type '(unsigned-byte 8))))
    (replace out txid)
    (dotimes (i 4) (setf (aref out (+ 32 i)) (ldb (byte 8 (* 8 i)) index)))
    out))

(defun bloom-within-size-constraints-p (filter)
  "Core IsWithinSizeConstraints (bloom.cpp:88-91)."
  (and (<= (length (bloom-filter-data filter)) +max-bloom-filter-size+)
       (<= (bloom-filter-hash-funcs filter) +max-bloom-hash-funcs+)))

(defun %script-pushes-match-p (filter script)
  "T when a non-empty data push of SCRIPT is in FILTER; decoding stops at
the first malformed op, as Core's GetOp loop breaks."
  (loop with pos = 0
        while (< pos (length script))
        do (multiple-value-bind (op data next) (bl.val:next-script-op script pos)
             (unless op (return nil))
             (when (and data (plusp (length data)) (bloom-contains-p filter data))
               (return t))
             (setf pos next))))

(defun bloom-relevant-and-update-p (filter tx)
  "Core CBloomFilter::IsRelevantAndUpdate (bloom.cpp:93-159): TX matches when
the filter holds its txid, a data push of one of its output scripts, an
outpoint it spends, or a data push of one of its input scripts. A matched
OUTPUT inserts that outpoint under BLOOM_UPDATE_ALL, or under
BLOOM_UPDATE_P2PUBKEY_ONLY when the output is pay-to-pubkey or bare multisig,
so the transaction that later spends it matches too. An empty filter matches
everything."
  (when (zerop (length (bloom-filter-data filter)))
    (return-from bloom-relevant-and-update-p t))
  (let* ((txid (bl.ser:transaction-hash tx))
         (found (bloom-contains-p filter txid))
         (update (logand (bloom-filter-flags filter) +bloom-update-mask+)))
    (loop for out across (bl.ser:transaction-outputs tx)
          for i from 0
          do (when (%script-pushes-match-p filter (bl.ser:tx-out-script-pubkey out))
               (setf found t)
               (when (or (= update +bloom-update-all+)
                         (and (= update +bloom-update-p2pubkey-only+)
                              (member (bl.val:classify-script (bl.ser:tx-out-script-pubkey out))
                                      '(:pubkey :multisig))))
                 (bloom-insert filter (outpoint-bytes txid i)))))
    (or found
        (loop for in across (bl.ser:transaction-inputs tx)
              for prev = (bl.ser:tx-in-previous-output in)
                thereis (or (bloom-contains-p filter (outpoint-bytes (bl.ser:outpoint-hash prev)
                                                                     (bl.ser:outpoint-index prev)))
                            (%script-pushes-match-p filter (bl.ser:tx-in-script-sig in)))))))

(defun serialize-bloom-filter (filter)
  "The filterload payload / Core's CBloomFilter serialization: the bit array
with its CompactSize length, nHashFuncs and nTweak as little-endian uint32,
and nFlags."
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-varint bb (length (bloom-filter-data filter)))
    (bl.ser:bb-write-bytes bb (bloom-filter-data filter))
    (bl.ser:bb-write-u32-le bb (bloom-filter-hash-funcs filter))
    (bl.ser:bb-write-u32-le bb (bloom-filter-tweak filter))
    (bl.ser:bb-write-u8 bb (bloom-filter-flags filter))
    (bl.ser:bb-finish bb)))

(defun parse-bloom-filter (payload)
  "A filterload PAYLOAD as a BLOOM-FILTER (signals on truncation). The size
limits are NOT checked here: Core reads any size and then judges it with
IsWithinSizeConstraints (net_processing.cpp:5057-5064)."
  (bl.bytes:with-byte-reader (s payload)
    (let* ((n (bl.bytes:br-read-compact-size s))
           (data (coerce (bl.bytes:br-read-bytes s n) '(simple-array (unsigned-byte 8) (*)))))
      (%make-bloom-filter :data data
                          :hash-funcs (bl.bytes:br-read-u32-le s)
                          :tweak (bl.bytes:br-read-u32-le s)
                          :flags (bl.bytes:br-read-u8 s)))))

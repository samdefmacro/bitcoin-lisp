(in-package #:bitcoin-lisp.storage)

;;;; BIP158 compact block filters (basic filter, type 0x00)
;;;;
;;;; A Golomb-Rice Coded Set (GCS) probabilistically encodes the set of scripts
;;;; touched by a block so light clients can test a block for relevance without
;;;; downloading it. Consensus-adjacent: the encoding must match Bitcoin Core
;;;; byte-for-byte or filter headers diverge. Mirrors Core's src/blockfilter.cpp,
;;;; src/util/golombrice.h and the MSB-first BitStream* in src/streams.h.
;;;;
;;;; The pure GCS math here takes/returns plain byte vectors; block-level element
;;;; extraction and the filter-header chain sit on top. Persistence and the P2P
;;;; wiring live in blockfilterindex.lisp.

(defconstant +basic-filter-type+ 0
  "BIP158 basic filter type byte (BlockFilterType::BASIC).")

(defconstant +basic-filter-p+ 19
  "Golomb-Rice parameter P for the basic filter (blockfilter.h BASIC_FILTER_P).")

(defconstant +basic-filter-m+ 784931
  "GCS modulus parameter M for the basic filter (blockfilter.h BASIC_FILTER_M).")

;;; --------------------------------------------------------------------------
;;; MSB-first bit stream writer (mirrors BitStreamWriter in streams.h)
;;; --------------------------------------------------------------------------

(defstruct (gcs-writer (:constructor %make-gcs-writer))
  "Accumulates bits most-significant-first and packs them into whole bytes.
ACC holds up to 7 pending low-order bits between flushes (an integer, since a
single Write may transiently hold up to 64 bits before draining)."
  (bytes (make-array 64 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
  (acc 0)
  (acc-bits 0 :type fixnum))

(defun gcs-writer-push-bits (w value nbits)
  "Append the low NBITS bits of VALUE to writer W, most-significant bit first."
  (declare (type fixnum nbits))
  (let ((acc (logior (ash (gcs-writer-acc w) nbits)
                     (logand value (1- (ash 1 nbits)))))
        (bits (the fixnum (+ (gcs-writer-acc-bits w) nbits)))
        (out (gcs-writer-bytes w)))
    (loop while (>= bits 8)
          do (decf bits 8)
             (vector-push-extend (logand (ash acc (- bits)) #xff) out))
    (setf (gcs-writer-acc w) (logand acc (1- (ash 1 bits)))
          (gcs-writer-acc-bits w) bits)))

(defun gcs-writer-flush (w)
  "Flush any pending bits, zero-padding to the next byte boundary."
  (when (plusp (gcs-writer-acc-bits w))
    (vector-push-extend (logand (ash (gcs-writer-acc w) (- 8 (gcs-writer-acc-bits w))) #xff)
                        (gcs-writer-bytes w))
    (setf (gcs-writer-acc w) 0 (gcs-writer-acc-bits w) 0)))

;;; --------------------------------------------------------------------------
;;; MSB-first bit stream reader (mirrors BitStreamReader in streams.h)
;;; --------------------------------------------------------------------------

(defstruct (gcs-reader (:constructor %make-gcs-reader))
  (bytes nil :type (vector (unsigned-byte 8)))
  (byte-pos 0 :type fixnum)
  (bit-pos 0 :type fixnum))            ; 0 = most-significant bit of current byte

(defun gcs-reader-read-bit (r)
  "Read and return the next bit (0/1) from reader R, most-significant first."
  (let* ((b (aref (gcs-reader-bytes r) (gcs-reader-byte-pos r)))
         (bit (logand (ash b (- (- 7 (gcs-reader-bit-pos r)))) 1)))
    (incf (gcs-reader-bit-pos r))
    (when (= (gcs-reader-bit-pos r) 8)
      (setf (gcs-reader-bit-pos r) 0)
      (incf (gcs-reader-byte-pos r)))
    bit))

(defun gcs-reader-read-bits (r nbits)
  "Read NBITS bits as an unsigned integer, most-significant bit first."
  (declare (type fixnum nbits))
  (let ((v 0))
    (dotimes (i nbits v)
      (setf v (logior (ash v 1) (gcs-reader-read-bit r))))))

;;; --------------------------------------------------------------------------
;;; Golomb-Rice coding (golombrice.h)
;;; --------------------------------------------------------------------------

(defun gcs-golomb-encode (w p x)
  "Golomb-Rice encode X with parameter P onto writer W: quotient as unary
(q ones then a zero), then the low P bits as the remainder."
  (let ((q (ash x (- p))))
    (loop while (plusp q)
          do (let ((n (min q 64)))
               (gcs-writer-push-bits w (1- (ash 1 n)) n)
               (decf q n)))
    (gcs-writer-push-bits w 0 1)
    (gcs-writer-push-bits w x p)))

(defun gcs-golomb-decode (r p)
  "Golomb-Rice decode one value with parameter P from reader R."
  (let ((q 0))
    (loop while (= (gcs-reader-read-bit r) 1) do (incf q))
    (+ (ash q p) (gcs-reader-read-bits r p))))

(defun gcs-fast-range (x n)
  "FastRange64 (util/fastrange.h): the high 64 bits of the 128-bit product X*N,
mapping the 64-bit hash X uniformly into [0, N)."
  (ash (* x n) -64))

(defun block-filter-siphash-keys (block-hash)
  "Derive the GCS SipHash keys (values k0 k1) from a 32-byte BLOCK-HASH in
internal (little-endian) byte order, as Core does via uint256::GetUint64."
  (values (bl.crypto:bytes-to-uint64-le block-hash 0)
          (bl.crypto:bytes-to-uint64-le block-hash 8)))

(defun %gcs-hashed-set (elements k0 k1 f)
  "Hash each ELEMENT (a byte vector) into [0, F) with SipHash-2-4 keyed by
K0/K1, returning the values sorted ascending (Core BuildHashedSet)."
  (let* ((n (length elements))
         (hs (make-array n :element-type '(unsigned-byte 64))))
    (loop for e in elements
          for i from 0
          do (setf (aref hs i)
                   (gcs-fast-range (bl.crypto:siphash-2-4 k0 k1 e) f)))
    (sort hs #'<)))

(defun build-gcs-filter (elements k0 k1 &key (p +basic-filter-p+) (m +basic-filter-m+))
  "Build an encoded GCS filter from ELEMENTS (a list of DISTINCT byte vectors).
The result is CompactSize(N) followed by the Golomb-Rice coded delta stream of
the sorted hashed set. Callers must deduplicate ELEMENTS first (N counts them)."
  (let* ((n (length elements))
         (f (* n m))
         (out (bl.bytes:make-byte-buf)))
    (bl.bytes:bb-write-varint out n)
    (when (plusp n)
      (let ((w (%make-gcs-writer))
            (last 0))
        (loop for v across (%gcs-hashed-set elements k0 k1 f)
              do (gcs-golomb-encode w p (- v last))
                 (setf last v))
        (gcs-writer-flush w)
        (bl.bytes:bb-write-bytes out (gcs-writer-bytes w))))
    (bl.bytes:bb-finish out)))

(defun gcs-filter-match-any (encoded k0 k1 elements
                             &key (p +basic-filter-p+) (m +basic-filter-m+))
  "Test whether the encoded GCS filter ENCODED possibly contains any of ELEMENTS
(a list of byte vectors). Uses the two-pointer merge of Core GCSFilter::MatchAny.
May return true on a false positive (rate ~1/M); never a false negative."
  (when (null elements)
    (return-from gcs-filter-match-any nil))
  ;; N is read as Core's GCSFilter constructor reads it (blockfilter.cpp,
  ;; VectorReader + ReadCompactSize): a non-canonical or oversized encoding
  ;; is an error, not a filter with a strange N.
  (let* ((br (bl.bytes:make-byte-reader-from encoded))
         (n (bl.bytes:br-read-compact-size br))
         (start (bl.bytes:br-pos br)))
    (when (zerop n)
      (return-from gcs-filter-match-any nil))
    (let* ((f (* n m))
           (queries (%gcs-hashed-set elements k0 k1 f))
           (nq (length queries))
           (r (%make-gcs-reader :bytes encoded :byte-pos start))
           (value 0)
           (qi 0))
      (dotimes (i n nil)
        (incf value (gcs-golomb-decode r p))
        (loop
          (cond ((= qi nq) (return-from gcs-filter-match-any nil))
                ((= (aref queries qi) value) (return-from gcs-filter-match-any t))
                ((> (aref queries qi) value) (return))
                (t (incf qi))))))))

(defun gcs-filter-match (encoded k0 k1 element
                         &key (p +basic-filter-p+) (m +basic-filter-m+))
  "Test whether the encoded GCS filter possibly contains a single ELEMENT."
  (gcs-filter-match-any encoded k0 k1 (list element) :p p :m m))

;;; --------------------------------------------------------------------------
;;; Basic block filter: element set, construction, header chain
;;; --------------------------------------------------------------------------

(declaim (inline %script-op-return-p))
(defun %script-op-return-p (script)
  "T if SCRIPT begins with OP_RETURN (0x6a)."
  (and (plusp (length script)) (= (aref script 0) #x6a)))

(defun basic-filter-elements (block spent-scripts)
  "Return the deduplicated list of byte-vector elements for BLOCK's basic filter.
Includes every output scriptPubKey except empty ones and those starting with
OP_RETURN, plus every spent prevout scriptPubKey in SPENT-SCRIPTS except empty
ones (the coinbase spends nothing, so it is naturally excluded). SPENT-SCRIPTS
is a list of the scriptPubKeys (byte vectors) of the outputs the block spends."
  (let ((seen (make-hash-table :test 'equalp))
        (elements '()))
    (flet ((add (script)
             (when (and (plusp (length script))
                        (not (gethash script seen)))
               (setf (gethash script seen) t)
               (push (coerce script '(simple-array (unsigned-byte 8) (*))) elements))))
      (dolist (tx (bl.ser:bitcoin-block-transactions block))
        (loop for out across (bl.ser:transaction-outputs tx)
              for spk = (bl.ser:tx-out-script-pubkey out)
              do (unless (%script-op-return-p spk) (add spk))))
      (dolist (spk spent-scripts) (add spk)))
    (nreverse elements)))

(defun build-basic-block-filter (block block-hash spent-scripts)
  "Build and return the encoded BIP158 basic filter bytes for BLOCK.
BLOCK-HASH is the 32-byte block hash in internal byte order (keys the SipHash);
SPENT-SCRIPTS is the list of scriptPubKeys spent by the block (see
BASIC-FILTER-ELEMENTS)."
  (multiple-value-bind (k0 k1) (block-filter-siphash-keys block-hash)
    (build-gcs-filter (basic-filter-elements block spent-scripts) k0 k1)))

(defun block-filter-hash (encoded-filter)
  "BIP157 filter hash: the double-SHA256 of the encoded filter bytes."
  (bl.crypto:hash256 encoded-filter))

(alexandria:define-constant +zero-filter-header+ (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
  :test #'equalp :documentation "The all-zero previous filter header used before the genesis filter.")

(defun block-filter-header (filter-hash prev-header)
  "BIP157 filter header: double-SHA256(filter-hash || prev-filter-header)."
  (bl.crypto:hash256
   (concatenate '(simple-array (unsigned-byte 8) (*)) filter-hash prev-header)))

(defun compute-block-filter-header (encoded-filter prev-header)
  "Convenience: filter header from the ENCODED filter and the parent's header."
  (block-filter-header (block-filter-hash encoded-filter) prev-header))
